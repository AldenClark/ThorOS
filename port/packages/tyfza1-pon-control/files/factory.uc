#!/usr/bin/ucode
// SPDX-License-Identifier: GPL-2.0-or-later
'use strict';
import { readfile, writefile, mkdir, chmod, rename, unlink } from 'fs';

const source = ARGV[0];
const output = ARGV[1];
const hs = readfile(source + '/config_hs.xml');
const cs = readfile(source + '/config.xml');

function field(text, key) {
	const entry = match(text, regexp('<Value\\s+Name="' + key + '"\\s+Value="([^"]*)"'));
	if (!entry) die('Missing factory field: ' + key);
	return replace(entry[1], /&(quot|apos|lt|gt|amp);/g,
		(m, entity) => ({ quot: '"', apos: "'", lt: '<', gt: '>', amp: '&' })[entity]);
}

function optional_field(text, key) {
	const entry = match(text, regexp('<Value\\s+Name="' + key + '"\\s+Value="([^"]*)"'));
	return entry ? field(text, key) : '';
}

function save(path, data) {
	const full = output + '/' + path;
	let directory = '';
	const parts = split(full, '/');
	pop(parts);
	for (let part in parts) {
		directory += part + '/';
		mkdir(directory);
	}
	if (writefile(full + '.new', data) != length(data) || !rename(full + '.new', full))
		die('Cannot write factory runtime: ' + path);
}

function mac(text) {
	if (!match(text, /^[0-9a-fA-F]{12}$/) || (int(substr(text, 0, 2), 16) & 1) || text == '000000000000')
		die('Invalid factory MAC');
	return join(':', map(match(text, /../g), entry => entry[0]));
}

function import_optical() {
	unlink(output + '/tmp/tyfza1-factory/rtl9617c/bosa-calibration.bin');
	const calibration = readfile(source + '/rtkbosa_k.bin');
	if (calibration == null) die('Cannot read factory BOSA calibration');
	if (length(calibration) < 1024) die('BOSA calibration needs at least 1024 bytes');
	save('tmp/tyfza1-factory/rtl9617c/bosa-calibration.bin', calibration);
}

let failed = false;

function import_identity() {
if (cs == null || cs == '') {
	warn('Factory PON configuration: Missing or empty config.xml\n');
	failed = true;
}
const identity = {
	loid: optional_field(cs, 'LOID'),
	loid_password: optional_field(cs, 'LOID_PASSWD'),
	ploam_password: optional_field(cs, 'GPON_PLOAM_PASSWD'),
	registration_id: optional_field(cs, 'GPON_PLOAM_PASSWD'),
	omci_psk: optional_field(cs, 'OMCI_PSK'),
	equipment_id: optional_field(hs, 'GPON_ONU_MODEL'),
	software_version: optional_field(cs, 'OMCI_SW_VER1')
};
try {
	// Original modutils.sh maps MIB family/speed to the six supported protocols.
	const family = field(hs, 'PON_MODE');
	const speed = field(hs, 'PON_SPEED');
	if (family == '1' && field(hs, 'PON_SUB_MODE') != '0')
		die('Unsupported factory ITU sub-mode');
	const modes = {
		'1:0': 'gpon', '1:1': 'xgpon', '1:2': 'xgspon',
		'2:0': 'epon', '2:1': 'epon-d10g', '2:2': 'epon-bi10g'
	};
	const mode = modes[family + ':' + speed];
	// Active Ethernet is valid OEM data, but has no supported PON protocol.
	if (family == '0')
		warn('Factory Active Ethernet is not supported; leaving PON mode unset\n');
	else {
		if (mode == null) die('Unsupported factory PON mode/speed: ' + family + '/' + speed);
		identity.mode = mode;
	}
} catch (e) {
	warn('Factory PON mode: ' + e.message + '\n');
	failed = true;
}
try {
	identity.serial_number = field(hs, 'GPON_SN');
} catch (e) {
	warn('Factory ITU identity: ' + e.message + '\n');
	failed = true;
}
try {
	const start = index(cs, '<chain chainName="EPON_LLID_TBL">');
	const remainder = start < 0 ? '' : substr(cs, start);
	const llid = start < 0 ? '' : substr(remainder, 0, index(remainder, '</chain>'));
	// ITU factory configurations can have an empty EPON LLID table.
	if (substr(identity.mode || '', 0, 4) == 'epon' || optional_field(llid, 'macAddr') != '') {
		const epon = {
			onu_mac: mac(field(llid, 'macAddr')),
			vendor_id: field(hs, 'PON_VENDOR_ID'),
			oam_model: field(hs, 'EPON_ONU_MODEL')
		};
		for (let key, value in epon) identity[key] = value;
	}
} catch (e) {
	warn('Factory EPON identity: ' + e.message + '\n');
	failed = true;
}
let config = "config pon 'pon'\n";
for (let key, value in identity)
	config += sprintf("\toption %s '%s'\n", key, replace(value, /'/g, "'\\''"));
save('var/run/tyfza1-factory/pon_factory', config);
chmod(output + '/var/run/tyfza1-factory', 0700);
chmod(output + '/var/run/tyfza1-factory/pon_factory', 0600);
}

// Each subsystem consumes its own original factory data.
try {
	save('tmp/tyfza1-factory/lan_mac', mac(field(hs, 'ELAN_MAC_ADDR')) + '\n');
} catch (e) {
	warn('Factory LAN identity: ' + e.message + '\n');
	failed = true;
}
try {
	import_optical();
	print('Loaded factory optical calibration\n');
} catch (e) {
	warn('Factory optical: ' + e.message + '\n');
	failed = true;
}
try {
	import_identity();
	print('Loaded factory PON identity\n');
} catch (e) {
	warn('Factory PON identity: ' + e.message + '\n');
	failed = true;
}
exit(failed ? 1 : 0);
