
assert = (condition, message) ->
	if not condition then throw message or 'Assertion failed'


## Make sure we have all we need before going dynamic

assert JSON and $ and SockJS

data_node = $('script[src="js/main.js"]')
assert data_node.get(0)

conn_box = $('#sb-conn-box')
conn_status = conn_box.find('#sb-conn-status')
conn_action = conn_box.find('#sb-conn-action')
conn_config = conn_box.find('#sb-conn-config')
conn_mode = $('#sb-conn-mode')
conn_mode_lock = false

ap_list = $('#sb-ap-list')
ap_list_empty = ap_list.find('.sb-ap-list-empty')
ap_tpl = ap_list.find('.sb-ap.sb-ap-tpl')
assert ap_list_empty and ap_tpl and conn_box

# console.log(data_node.data('aps'))


$(document).ready ->

	## Websockets base

	sock_url = data_node.data('events-url')
	console.log('SockJS url:', sock_url)
	assert sock_url

	sock_evid = 0
	sock_evid_get = ->
		sock_evid += 1
	sock_evid_handlers = {}

	sock = sock_connect_timer = null

	sock_send = (q, data) ->
		assert q?
		data = {} if not data?
		data.q = q
		data.id = sock_evid_get()
		# console.log('traffic >>', data)
		sock.send(JSON.stringify(data))
		data.id

	sock_connect = ->
		sock = new SockJS(sock_url, null, transports: 'xhr-streaming')
		sock.onopen = sock_onopen
		sock.onclose = sock_onclose
		sock.onmessage = sock_onmessage

	sock_onopen = ->
		console.log('connected to:', sock_url)
		if sock_connect_timer
			clearInterval(sock_connect_timer)
			ap_list.find('.sb-ap').not(ap_tpl).remove()
			sock_send('sync')
			sock_connect_timer = null

	sock_onclose = ->
		console.log('disconnected from:', sock_url)
		if not sock_connect_timer
			sock_connect_timer = window.setInterval((-> sock_connect()), 2000)

	sock_onmessage = (e) ->
		data = $.parseJSON(e.data)
		# console.log('traffic <<', data)

		if data.q == 'new' or data.q == 'update'
			if data.q == 'new'
				ap = ap_tpl.clone(true).detach()
				ap.attr('id', "sb-ap-uid-#{data.ap.uid}")
				ap.find('.sb-ap-form-auto')
					.bootstrapSwitch() # doesn't work well with .clone(true)
					.on('switchChange', sb_switch_auto)
			else
				ap = ap_list.find("#sb-ap-uid-#{data.ap.uid}")

			ap.find('.ssid').text(data.ap.ssid)
			ap.find('button').attr('title', data.ap.title)
			ap.find('.sb-ap-bar-inner').css('width', "#{data.ap.strength}%")
			ap.find('.sb-ap-private').toggleClass('invisible', not data.ap.private)
			ap.find('.sb-ap-form-connect-open').toggleClass('hidden', data.ap.private)
			ap.find('.sb-ap-form-auto').bootstrapSwitch('state', data.ap.auto != false)

			ap_pass_box = ap.find('.sb-ap-form-passphrase')
			ap_pass_box
				.toggleClass('hidden', not data.ap.private)
				.removeClass('has-success has-error has-feedback')
			if data.ap.pass_state
				ap_pass_box
					.addClass('has-feedback')
					.addClass("has-#{data.ap.pass_state}")

			ap_pass = ap.find('.sb-ap-passphrase')
			ap_pass_ph = if data.ap.pass_state\
				then ap_pass.data("ph-state-#{data.ap.pass_state}")\
				else null
			if not ap_pass_ph
				ap_pass_ph = ap_pass.data('ph-state-other')
			ap_pass.attr('placeholder', ap_pass_ph)

			ap.find('.sb-ap-state span').addClass('hidden')
			if data.ap.pass_state
				ap.find(".sb-ap-state .sb-ap-state-#{data.ap.pass_state}").removeClass('hidden')
			if data.q == 'new'
				ap.removeClass('sb-ap-tpl hidden')
				ap.appendTo(ap_tpl.parent())
				ap_list_empty.addClass('hidden')
				ap.find('.sb-ap-uid').val(data.ap.uid)
				ap.find('.dropdown-menu').click (ev) -> ev.stopPropagation()

		else if data.q == 'remove'
			ap_list.find("#sb-ap-uid-#{data.ap.uid}").remove()
			if ap_list.find('.sb-ap').not(ap_tpl).length == 0
				ap_list_empty.removeClass('hidden')

		else if data.q == 'status'
			if data.ap_uid?
				ap = ap_list.find("#sb-ap-uid-#{data.ap_uid}")
				ap_others = ap_list.find('.sb-ap').not(ap_tpl).not(ap)
				ap_btn = ap.find('.sb-ap-btn-main')
			else
				ap = ap_btn = null

			ap_btn_default = true
			ap_btn_toggle = (ap, highlight=false, connected=false, others=false) ->
				[ap_btn_show, ap_btn_hide] = if highlight\
					then ['disconnect', 'connect'] else ['connect', 'disconnect']
				ap.find('.sb-ap-form-connect-btn[name="'+ap_btn_show+'"]').removeClass('hidden')
				ap.find('.sb-ap-form-connect-btn[name="'+ap_btn_hide+'"]').addClass('hidden')
				if highlight
					ap_btn.removeClass('btn-danger').addClass(
						if connected then 'btn-success' else 'btn-info' )
				if not others
					ap_btn_default = false
			ap_btn_reset_others = -> ap_btn_toggle(ap_others, false, false, true)

			conn_status.text(data.status)
			conn_action.text(data.action)
			conn_box
				.removeClass('alert-info')
				.removeClass('alert-success')
				.addClass(if data.code == 'done' then 'alert-success' else 'alert-info')
			ap_list.find('.sb-ap-btn-main').removeClass('btn-success btn-info')

			if data.code?
				if data.code.startsWith('live_')
					ap_btn_reset_others()
					ap_btn_toggle(ap, true)
				else if data.code.startsWith('fail_')
					ap_btn.addClass('btn-danger')
					ap_btn_reset_others()
			if data.code == 'done'
				conn_config.html(data.config)
				conn_config.removeClass('hidden')
				ap_btn_reset_others()
				ap_btn_toggle(ap, true, true)
			else
				conn_config.addClass('hidden')

			if ap_btn_default
				if not ap?
					ap = ap_list.find('.sb-ap')
				ap_btn_toggle(ap) # reset to default "Connect" state

		else if data.q == 'online'
			conn_mode_lock = true
			conn_mode.bootstrapSwitch('state', data.value)
			conn_mode_lock = false

		else if data.q == 'result'
			if sock_evid_handlers[data.id]?
				sock_evid_handlers[data.id](data)
				delete sock_evid_handlers[data.id]

		else
			console.log('unrecognized ev:', data)

	sock_connect()


	## Form overrides

	ap_list.find('.dropdown-menu').click (ev) -> ev.stopPropagation()

	ap_list.find('form').submit (ev) ->
		conn_mode.bootstrapSwitch('state', true)
		form = $(ev.target)
		form_data = form.serializeArray()
		action = $('.sb-ap-form-connect-btn:visible').attr('name')
		form_data.push(name: action, value: 't')
		if action == 'connect'
			sock_send('connect', form: form_data)
		else if action == 'disconnect'
			sock_send('disconnect')
		else
			console.log('Unrecognized form action:', form_data)
		false


	## Dynamic on/off switches

	sb_switch_auto = (ev, data) ->
		ap_uid = $(data.el).parents('form').find('.sb-ap-uid').val()
		if ap_uid != 'none'
			sock_send 'auto',
				ap_uid: ap_uid
				value: data.value
		false

	$('.sb-ap-form-auto')
		.not(ap_tpl.find('.sb-ap-form-auto')) # doesn't work well with .clone(true)
		.bootstrapSwitch()
		.on('switchChange', sb_switch_auto)
	$('.sb-ap-form-auto-box .sb-label').on 'click', (ev) ->
		$(ev.target).parents('.sb-ap-form-auto-box')
			.find('.sb-ap-form-auto').bootstrapSwitch('toggleState')

	conn_mode
		.bootstrapSwitch()
		.on 'switchChange', (ev, data) ->
			if not conn_mode_lock
				sock_send('online', value: data.value)
			false

	scan_ev_id = null
	$('#sb-scan').on 'click', (ev) ->
		if not scan_ev_id?
			scan_ev_id = sock_send('scan')
			$(ev.target).addClass('disabled')
			sock_evid_handlers[scan_ev_id] = ->
				scan_ev_id = null
				$(ev.target).removeClass('disabled')
		false
