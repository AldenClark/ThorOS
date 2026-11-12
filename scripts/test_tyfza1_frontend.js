#!/usr/bin/env node
// Exercise production PON views and validation against the pinned upstream LuCI UCI model.
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const luci = process.env.TYFZA1_LUCI_FEED || path.join(root, 'sources/openwrt/feeds/luci');
const resources = path.join(root, 'port/packages/luci-app-tyfza1-pon/htdocs/luci-static/resources');
const baseclass = { extend: object => object };
const rpcCalls = [];
let rpcResults = {};
const rpc = { declare: spec => () => {
	const name = spec.object + '.' + spec.method;
	rpcCalls.push(name);
	const result = rpcResults[name];
	return result instanceof Error ? Promise.reject(result) : Promise.resolve(result ?? {});
} };
let canWrite = true;
const L = { url: (...p) => '/' + p.join('/'), resource: p => '/luci-static/resources/' + p,
	bind: (f, ctx) => f.bind(ctx), hasViewPermission: () => canWrite };
function E(tag, attrs, children) {
	if (Array.isArray(children)) children = children.map(child => Array.isArray(child) ? String(child) : child);
	return { tag, attrs: attrs || {}, children,
		replaceChildren(...nodes) { this.children = nodes; },
		getAttribute(name) { return this.attrs[name]; },
		querySelectorAll() {
			const found = [];
			walk(this, node => {
				if (node.tag === 'details' && node.attrs['data-tyf-fold']) found.push(node);
				return false;
			});
			return found;
		} };
}
function walk(node, predicate) {
	if (Array.isArray(node)) {
		for (const part of node) { const found = walk(part, predicate); if (found) return found; }
		return null;
	}
	if (!node || typeof node !== 'object') return null;
	if (predicate(node)) return node;
	return walk(node.children, predicate);
}
function text(node) {
	if (Array.isArray(node)) return node.map(text).join(' ');
	return node && typeof node === 'object' ? node.textContent ?? text(node.children) : node == null ? '' : String(node);
}
function load(file, context) {
	return new Function(...Object.keys(context), fs.readFileSync(file, 'utf8'))(...Object.values(context));
}

const uci = load(path.join(luci, 'modules/luci-base/htdocs/luci-static/resources/uci.js'), { baseclass, rpc, L });
const validation = load(path.join(luci, 'modules/luci-base/htdocs/luci-static/resources/validation.js'), {
	baseclass, _: value => ({ format: () => value })
});
const status = load(path.join(resources, 'tyfza1/status.js'), { baseclass, rpc, L, E });
let options, lastMap;
class Map {
	constructor(configName, title) { options = {}; lastMap = this; this.configName = configName; this.title = title; }
	section() {
		this.sectionObject = { tabs: [], tab(name) { this.tabs.push(name); },
			taboption(tab, type, key) {
				const option = { tab, type, values: {}, dependencies: [],
					value(k, v) { this.values[k] = v; },
					depends(k, v) { this.dependencies.push(typeof k === 'object' ? k : { [k]: v }); } };
				options[key] = option;
				return option;
			} };
		return this.sectionObject;
	}
	render() { return Promise.resolve(E('form')); }
}
const form = { Map, NamedSection: 'section', Value: 'value', Flag: 'flag', ListValue: 'list' };
let polling;
const ui = load(path.join(resources, 'tyfza1/ui.js'), {
	baseclass, poll: { add: f => { polling = f; } }, status, L, E
});
const settings = load(path.join(resources, 'view/network/tyfza1-pon.js'), {
	view: baseclass, form, uci, status, L, E
});
const overview = load(path.join(resources, 'view/tyfza1/overview.js'), {
	view: baseclass, status, ui, L, E, URL, Blob, setTimeout
});
function config() {
	uci.state = { values: { pon: { pon: { '.type': 'pon', mode: 'epon-d10g', enabled: '1', loid: 'lab-only' } } },
		creates: {}, changes: {}, deletes: {}, reorder: {} };
}

async function main() {
	const css = fs.readFileSync(path.join(resources, 'tyfza1/status.css'));
	const revision = crypto.createHash('sha256').update(css).digest('hex').slice(0, 12);
	assert.equal(status.style().attrs.href, '/luci-static/resources/tyfza1/status.css?v=' + revision);
	const menu = JSON.parse(fs.readFileSync(path.join(root, 'port/packages/luci-app-tyfza1-pon/root/usr/share/luci/menu.d/luci-app-tyfza1-pon.json')));
	assert.deepEqual(Object.keys(menu).sort(), ['admin/network/pon', 'admin/network/pon/config', 'admin/network/pon/status']);
	assert.equal(menu['admin/network/pon'].action.type, 'firstchild');
	for (const item of Object.values(menu)) {
		if (item.action.type === 'view') assert.ok(fs.existsSync(path.join(resources, 'view', item.action.path + '.js')));
	}
	for (const filename of ['hardware', 'internet', 'iptv', 'acceleration', 'diagnostics'])
		assert.equal(fs.existsSync(path.join(resources, 'view/tyfza1', filename + '.js')), false);

	const online = { serdes: { mode: 'epon-d10g', configured: '1', rx_los: '0', error: '0' },
		mac: { prepared: '1', error: '0' }, mpcp: { enabled: '1', registered: '00000001' },
		oam_ports: [{ live: true, registered: true, discovery_stable: true, auth_state: 'accepted' }],
		identity: { onu_mac: '02:00:00:00:00:01' }, bosa: { configured: '1', model: 'BOSA' } };
	assert.equal(status.ponState(online).tone, 'good');
	assert.equal(status.ponState({}).tone, 'muted');
	assert.equal(status.ponState({ ...online, service: { enabled: '0', error: '0' } }).text, '未启用');
	assert.equal(status.ponState({ ...online, service: { enabled: '1', error: '1' } }).tone, 'danger');
	assert.match(status.ponState({ service: { enabled: '1', error: '-5' } }).help, /service.*-5/);
	assert.equal(status.ponState({ serdes: { mode: 'epon-d10g' } }).text, '状态不可用');
	assert.equal(status.ponState({ ...online, optical: { tx_fault: '1' } }).text, '光模块发射故障');
	assert.match(JSON.stringify(status.ponCard({ ...online, optical: { rx_los: '1' } })), /接收失光/);
	assert.match(JSON.stringify(status.ponCard({ ...online, optical: { tx_disabled: '1' } })), /已关闭/);
	assert.equal(status.ponState({ ...online, serdes: { ...online.serdes, rx_los: '1' } }).tone, 'danger');
	assert.equal(status.ponState({ ...online, mac: { error: '-95' } }).tone, 'danger');
	assert.equal(status.ponState({ ...online, mpcp: { enabled: '1', registered: 'garbage' } }).text, '等待注册');
	assert.equal(status.ponState({ ...online, oam_ports: [{ live: false, auth_state: 'accepted' }] }).tone, 'warn');
	assert.equal(status.ponState({ ...online, oam_ports: [{ live: true, registered: true, auth_state: 'rejected' }] }).tone, 'danger');
	for (const mode of ['gpon', 'xgpon', 'xgspon']) {
		const active = { serdes: { mode, configured: '1' }, mac: { prepared: '1', activation: 'O5', onu_id: '17' },
			activation: { omcc_onu_id: '37' }, omci: { live: true, error: '0' }, mpcp: { enabled: '0' } };
		assert.equal(status.ponState(active).tone, 'warn');
		assert.equal(status.ponState({ ...active, data_path: { configured: '1' } }).tone, 'good');
		assert.equal(status.ponState({ ...active, data_path: { configured: '1', error: '-5' } }).text, '业务配置异常');
		assert.match(status.ponState({ ...active, omci: { live: true, error: '-22' } }).help, /omci.*-22/);
		assert.match(text(ui.authentication(active)), new RegExp('ONU-ID ' + (mode === 'gpon' ? '17' : '37')));
		const stale = { ...active, data_path: { configured: '1' }, omci: { live: false, auth: '1' } };
		assert.equal(status.ponState(stale).text, 'OMCI 状态不可用');
		assert.doesNotMatch(text(ui.authentication(stale)), /认证通过/);
		const current = { ...active, data_path: { configured: '1', session: '7' }, omci: { live: true, session: '7', auth: '1' } };
		assert.equal(status.omciLive(current), true);
		assert.match(text(ui.authentication(current)), /OLT LOID 认证 认证通过/);
		assert.equal(status.ponState({ ...current, omci: { ...current.omci, auth: '2' } }).text, '认证未通过');
		assert.equal(status.omciLive({ ...current, omci: { ...current.omci, session: '6' } }), false);
	}

	config();
	assert.equal((await settings.render()).tag, 'form');
	assert.deepEqual(lastMap.sectionObject.tabs, ['link', 'identity']);
	assert.equal(lastMap.configName, 'pon');
	assert.equal(Object.keys(options.mode.values).length, 6);
	for (const key of ['_wan_protocol', '_wan_device', '_network_settings', '_acceleration', 'flow_offloading_hw'])
		assert.equal(options[key], undefined);
	assert.equal(options._advanced.default, '0');
	assert.equal(options._advanced.cfgvalue(), '0');
	options._advanced.write('pon', '1'); options._advanced.remove('pon');
	assert.equal(uci.get('pon', 'pon', '_advanced'), undefined);
	for (const key of ['vendor_id', 'oam_model', 'equipment_id', 'hardware_version', 'software_version',
		'operator_id', 'omcc_version', 'disable_enhanced_security', 'llid_count']) {
		assert.ok(options[key].dependencies.length > 0, key + ' needs a supported-mode dependency');
		assert.ok(options[key].dependencies.every(dep => dep._advanced === '1' && dep.mode),
			key + ' must require both advanced expansion and the correct PON mode');
	}
	for (const key of ['loid', 'loid_password', 'serial_number', 'registration_id', 'ploam_password', 'omci_psk'])
		assert.ok(options[key].dependencies.every(dep => dep._advanced === undefined), key + ' is a primary auth field');
	assert.equal(options.onu_mac.validate('pon', ''), true);
	assert.notEqual(options.onu_mac.validate('pon', 'ff:ff:ff:ff:ff:ff'), true);
	assert.notEqual(options.onu_mac.validate('pon', '00:00:00:00:00:00'), true);
	assert.equal(options.onu_mac.validate('pon', '02:00:00:00:00:01'), true);
	assert.equal(options.serial_number.validate('pon', ''), true);
	assert.equal(options.serial_number.validate('pon', 'ABCD1234abcd'), true);
	assert.equal(options.serial_number.validate('pon', '414243441234abcd'), true);
	assert.notEqual(options.serial_number.validate('pon', 'ABCD1234567z'), true);
	assert.notEqual(options.serial_number.validate('pon', '中文12345678'), true);
	assert.equal(options.loid.validate('pon', '中'.repeat(8)), true);
	assert.notEqual(options.loid.validate('pon', '中'.repeat(9)), true);
	assert.notEqual(options.loid.validate('pon', 'a\0b'), true);
	assert.equal(options.llid_count.datatype, 'and(uinteger,range(1,32))');
	for (const [value, expected] of [['1', true], ['32', true], ['08', true], ['1.5', false], ['0', false], ['33', false]]) {
		const validator = { value, factory: validation, assert: condition => !!condition };
		assert.equal(validation.types.uinteger.call(validator) && validation.types.range.call(validator, 1, 32), expected);
	}
	for (const key of ['hardware_version', 'software_version']) {
		const itu = { section: { formvalue: () => 'xgpon' } }, epon = { section: { formvalue: () => 'epon-d10g' } };
		assert.equal(options[key].validate.call(itu, 'pon', 'a'.repeat(14)), true);
		assert.notEqual(options[key].validate.call(itu, 'pon', 'a'.repeat(15)), true);
		assert.equal(options[key].validate.call(epon, 'pon', 'a'.repeat(16)), true);
	}
	assert.equal(options.operator_id.validate('pon', 'CTC'), true);
	assert.notEqual(options.operator_id.validate('pon', '12345'), true);
	options.llid_count.write('pon', '08');
	assert.equal(uci.get('pon', 'pon', 'llid_count'), '8');
	assert.equal(uci.state.changes.network, undefined);
	assert.equal(uci.state.changes.firewall, undefined);
	canWrite = false; await settings.render(); assert.equal(lastMap.readonly, true); canWrite = true;

	const rawPath = 'configured=0 error=-5 paths=2\ngem=100 vlan=100\ngem=200 vlan=200\n';
	assert.equal(ui.paths({ data_path_raw: rawPath }).length, 2);
	assert.match(text(ui.services({ data_path_raw: rawPath })), /GEM 100/);
	assert.ok(ui.diagnostics({ omci: { live: false, error: '-22' }, data_path_raw: rawPath }).includes('[omci]\nlive: false\nerror: -22'));
	assert.ok(ui.diagnostics({ data_path_raw: rawPath }).includes('[data_path]\n' + rawPath));
	rpcResults['luci.tyfza1-pon.status'] = online;
	const page = await overview.render(online);
	assert.match(text(page), /PON 状态/);
	assert.match(text(page), /ONU 身份与光学校准/);
	assert.match(text(page), /生效的 ONU MAC 02:00:00:00:00:01/);
	assert.doesNotMatch(text(page), /硬件转发|业务网络|普通端口/);
	assert.equal(page.querySelectorAll().some(node => node.attrs['data-tyf-fold'] === 'paths'), false,
		'EPON must not render the OMCI-only GEM section');
	const identityFold = walk(page, node => node.attrs['data-tyf-fold'] === 'identity');
	identityFold.open = true;
	await polling();
	assert.equal(walk(page, node => node.attrs['data-tyf-fold'] === 'identity').open, true);
	rpcResults['luci.tyfza1-pon.status'] = new Error('unavailable');
	await polling();
	assert.match(text(page), /上次成功读取的数据/);
	rpcResults['luci.tyfza1-pon.status'] = online;
	const diagButton = walk(page, node => node.tag === 'button' && text(node) === '读取诊断快照');
	const download = walk(page, node => node.tag === 'button' && text(node) === '下载快照');
	assert.ok(diagButton && download);
	assert.equal(rpcCalls.includes('luci.tyfza1-pon.diagnostics'), false, 'diagnostics must not be polled');
	rpcResults['luci.tyfza1-pon.diagnostics'] = { ...online, data_path_raw: rawPath, state: { error: '-5' } };
	await diagButton.attrs.click();
	assert.equal(rpcCalls.filter(call => call === 'luci.tyfza1-pon.diagnostics').length, 1);
	assert.match(text(page), /\[state\]/);
	assert.equal(download.disabled, false);
	rpcResults['luci.tyfza1-pon.diagnostics'] = new Error('unavailable');
	await diagButton.attrs.click();
	assert.match(text(page), /诊断读取失败/);
	assert.equal(download.disabled, true, 'failed reads cannot export stale diagnostics');

	const ituPage = await overview.render({ serdes: { mode: 'gpon', configured: '1' }, identity: {}, bosa: {},
		mac: { activation: 'O5', prepared: '1' }, omci: { live: true }, data_path_raw: rawPath });
	assert.equal(ituPage.querySelectorAll().some(node => node.attrs['data-tyf-fold'] === 'paths'), true);
	assert.match(text(ituPage), /GEM 100/);

	const acl = JSON.parse(fs.readFileSync(path.join(root, 'port/packages/luci-app-tyfza1-pon/root/usr/share/rpcd/acl.d/luci-app-tyfza1-pon.json')));
	assert.deepEqual(acl['luci-app-tyfza1-pon'].write.uci, ['pon']);
	assert.deepEqual(acl['luci-app-tyfza1-pon'].read.uci, ['pon']);
	assert.deepEqual(acl['luci-app-tyfza1-pon'].read.ubus['luci.tyfza1-pon'], ['status', 'diagnostics']);
	assert.equal(acl['luci-app-tyfza1-pon'].write.ubus, undefined);
	const backend = fs.readFileSync(path.join(root, 'port/packages/luci-app-tyfza1-pon/root/usr/share/rpcd/ucode/luci.tyfza1-pon'), 'utf8');
	assert.match(backend, /diagnostics: \{ call: function\(\)/);
	assert.doesNotMatch(backend, /network_ports|wan_rx_packets|lan_rx_dropped/);
	// Run the installed RPC source with readfile fixtures. The source is ucode, but
	// the status/diagnostics logic uses a JS-compatible subset of its primitives.
	const base = '/sys/bus/platform/devices/4f5500000.pon/';
	const files = {
		'/proc/uptime': '100.00 100.00', '/var/run/pon-service': 'enabled=1 error=0',
		[base + 'serdes']: 'mode=gpon configured=1 error=0',
		[base + 'data_path']: 'configured=1 paths=1 error=0\ngem=100 vlan=100',
		[base + 'bosa']: 'configured=1 model=205 error=0',
		[base + 'state']: 'error=-5', [base + 'traffic']: 'rx=123 tx=456',
		[base + 'fe']: 'enabled=1 flows=2',
		'/sys/bus/platform/devices/4f4300000.ethernet/pon_deepq': 'configured=1'
	};
	const reads = [];
	const source = backend.split('\n').slice(1).join('\n').replace("import { readfile } from 'fs';", '')
		.replace('for (let token in split(trim(text), /\\s+/))', 'for (let token of split(trim(text), /\\s+/))');
	const methods = new Function('readfile', 'trim', 'split', 'substr', 'index', 'type', 'length', 'push', 'json', 'time', source)(
		file => { reads.push(file); return files[file] ?? null; },
		value => String(value).trim(), (value, separator) => String(value).split(separator),
		(value, start, length) => String(value).substr(start, length),
		(value, search) => String(value).indexOf(search),
		value => Number.isInteger(value) ? 'int' : typeof value,
		value => value.length, (list, item) => list.push(item), JSON.parse, () => 100
	)['luci.tyfza1-pon'];
	const lightweight = methods.status.call();
	assert.equal(lightweight.data_path.paths, '1');
	assert.equal(lightweight.bosa.model, '205');
	assert.equal(lightweight.oam_ports.length, 0);
	assert.ok(!reads.some(file => file.includes('/pon-oam/')), 'GPON must not probe EPON OAM sessions');
	assert.equal(lightweight.state, undefined);
	assert.equal(lightweight.traffic, undefined);
	assert.equal(lightweight.fe, undefined);
	assert.equal(lightweight.deepq, undefined);
	assert.equal(methods.diagnostics.call().traffic.rx, '123');
	assert.equal(methods.diagnostics.call().deepq.configured, '1');
	files[base + 'serdes'] = 'mode=epon-d10g configured=1 error=0';
	reads.length = 0;
	methods.status.call();
	assert.ok(reads.some(file => file.includes('/pon-oam/')), 'EPON must still inspect OAM sessions');
	console.log('PON LuCI: 2 views, native UCI isolation, conditional auth, lazy diagnostics, status semantics and read-only permissions passed');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
