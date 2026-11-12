'use strict';
'require view';
'require tyfza1.status as status';
'require tyfza1.ui as ui';

function diagnosticsPanel() {
	var snapshot = null;
	var message = E('p', { class: 'tyf-note', role: 'status' }, '仅在需要排查问题时读取，不随状态页面自动刷新。');
	var output = E('pre', { class: 'tyf-raw', hidden: true });
	var download = E('button', { type: 'button', class: 'cbi-button', disabled: true, click: function() {
		if (!snapshot) return;
		var url = URL.createObjectURL(new Blob([snapshot], { type: 'text/plain;charset=utf-8' }));
		var anchor = E('a', { href: url, download: 'tyfza1-pon-status.txt' });
		anchor.click();
		setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
	} }, '下载快照');
	var refresh = E('button', { type: 'button', class: 'cbi-button', click: function() {
		refresh.disabled = true;
		return status.callDiagnostics().then(function(data) {
			if (!data || !data.serdes) throw new Error('PON 驱动状态暂不可用');
			snapshot = 'TYFZA1 PON diagnostic snapshot\nCaptured: ' +
				new Date((data.queried_at || Date.now() / 1000) * 1000).toISOString() + '\n\n' + ui.diagnostics(data);
			output.textContent = snapshot;
			output.hidden = false;
			download.disabled = false;
			message.textContent = '已取得当前诊断快照。需要最新数据时请重新读取。';
		}).catch(function() {
			snapshot = null;
			output.textContent = '';
			output.hidden = true;
			download.disabled = true;
			message.textContent = '诊断读取失败，请稍后重试。';
		}).finally(function() { refresh.disabled = false; });
	} }, '读取诊断快照');
	return ui.fold('高级诊断', 'diagnostics', [
		ui.note('仅导出驱动和协议运行状态，不读取 UCI 认证密码或原厂镜像；快照可能包含 ONU 身份、OLT 业务标识，请在分享前核对。'),
		E('div', { class: 'tyf-actions' }, [refresh, download]), message, output
	]);
}

return view.extend({
	load: function() { return status.callStatus().catch(function() { return null; }); },
	render: function(initial) {
		return ui.page('PON 状态', '查看光链路、注册认证与 OLT 下发的业务；O5 不代表互联网已经连通。',
			initial, status.callStatus, function(data) {
				var mode = (data.serdes || {}).mode, identity = data.identity || {}, bosa = data.bosa || {};
				return E('div', {}, [
					status.ponCard(data),
					status.card('注册与认证', null, ui.authentication(data)),
					['gpon', 'xgpon', 'xgspon'].indexOf(mode) !== -1
						? ui.fold('OLT 下发的 GEM 业务通道', 'paths', ui.services(data)) : null,
					ui.fold('ONU 身份与光学校准', 'identity', [
						status.rows([
							['生效的 ONU MAC', status.value(identity.onu_mac)],
							['生效的 ITU-T SN', mode && mode.indexOf('epon') === 0 ? 'EPON 不适用' : status.value(identity.serial_number)],
							['BOSA 校准', bosa.configured == null ? '未提供' : bosa.configured === '1' ? '已配置' : '未就绪'],
							['BOSA 型号', status.value(bosa.model)],
							['BOSA 错误码', status.value(bosa.error)]
						]),
						ui.note('身份项显示驱动当前生效值，留空的认证配置仍由原厂值接管；此处不写入原厂分区。')
					])
				]);
			}, diagnosticsPanel());
	},
	handleSaveApply: null, handleSave: null, handleReset: null
});
