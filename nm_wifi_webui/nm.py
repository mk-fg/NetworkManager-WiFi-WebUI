#-*- coding: utf-8 -*-

from __future__ import print_function

from nm_wifi_webui import utils, secrets

from txdbus import (
	error as txdbus_error, client as txdbus_client,
	objects as txdbus_objects, interface as txdbus_iface,
	marshal as txdbus_marshal )

from twisted.internet import reactor, defer, task
from twisted.application import service

import itertools as it, operator as op, functools as ft
from weakref import WeakKeyDictionary
from collections import namedtuple
import os, sys, types, logging, hashlib, copy, uuid
import socket, struct, time


def ntop( n, af, none_for_0=False,
		_afid={4: socket.AF_INET, 6: socket.AF_INET6} ):
	assert af in [4, 6], af
	if none_for_0 and n == 0: return None
	if af == 4: n = struct.pack('@I', n)
	elif af == 6: n = ''.join(map(chr, n))
	return socket.inet_ntop(_afid[af], n)


class NMAP(namedtuple( 'NMAP',
		'dbus_path ssid private mode sec strength hwaddr bitrate pass_state auto' )):

	_uid = _uuid = None
	uuid_generation_ns = uuid.UUID('cbc481a169650cf35627bf4cc654bdb8')

	@classmethod
	def get_uid(cls, dbus_path):
		return hashlib.sha512(dbus_path).hexdigest()[:10]

	@classmethod
	def get_uuid(cls, hwaddr):
		return bytes(uuid.uuid3(cls.uuid_generation_ns, utils.force_bytes(hwaddr)))

	@property
	def uid(self):
		'NMAP identifier that makes sense within one pid/NM run.'
		if not self._uid: self._uid = self.get_uid(self.dbus_path)
		return self._uid

	@property
	def uuid(self):
		'NMAP identifier that makes persists after pid/NM restarts.'
		if not self._uuid: self._uuid = self.get_uuid(self.hwaddr)
		return self._uuid

	@property
	def data(self):
		data = self._asdict()
		data['uid'] = self.uid
		return data



class NMError(Exception): pass

class NMConnectionError(NMError): pass

class NMActionError(NMError):

	dbus_err_name = None

	def __init__(self, msg_or_dbus_err=None):
		args = list()
		if msg_or_dbus_err is not None:
			if isinstance(msg_or_dbus_err, txdbus_error.RemoteError):
				args.append(msg_or_dbus_err.message)
				self.dbus_err_name = msg_or_dbus_err.errName
			else: args.append(msg_or_dbus_err)
		super(NMActionError, self).__init__(*args)


class NMInterface(service.MultiService):

	def __init__(self, secrets_file, webui):
		service.MultiService.__init__(self)
		self.log = logging.getLogger('nm.core')

		self.secrets = secrets.SecretStorage(secrets_file)
		self.dbus = DBusProxy(self.secrets)

		self.webui, webui.nm = webui, self

		self.wifi_init()

		self.dev_up, self.dev_signals = dict(), dict()


	def startService(self):
		reactor.callLater(0, self._startService)

	@defer.inlineCallbacks
	def _startService(self):
		yield self.dbus.nm.signal('DeviceAdded', self.iface_added, pass_ref=False)
		yield self.dbus.nm.signal('DeviceRemoved', self.iface_removed, pass_ref=False)
		yield self.dbus.nm.signal( 'PropertiesChanged', self.wifi_changed,
			iface='org.freedesktop.DBus.Properties', pass_ref=False )

		yield self.wifi_conn_enabled_set()
		yield self.iface_detect()
		if not self.wifi_iface:
			self.log.debug('Unable to detect valid wifi interface, waiting for one to become available')


	NMError = NMError
	NMConnectionError = NMConnectionError
	NMActionError = NMActionError

	wifi_iface = wifi_dev = None
	wifi_caps, wifi_aps = list(), dict()
	wifi_signals, wifi_signals_ap = list(), dict()

	wifi_sec = set(['none', 'wep', 'wpa-tkip', 'wpa-ccmp'])
	wifi_sec_dict = dict(
		none=0x0, cipher_wep40=0x1, cipher_wep104=0x2,
		cipher_tkip=0x4, cipher_ccmp=0x8, wpa=0x10, rsn=0x20 )
	wifi_ap_flags = dict(none=0 , privacy=0x1)
	wifi_ap_sec_dict = dict( none=0x0,
		pair_wep40=0x1, pair_wep104=0x2,
		pair_tkip=0x4, pair_ccmp=0x8,
		group_wep40=0x10, group_wep104=0x20,
		group_tkip=0x40, group_ccmp=0x80,
		key_mgmt_psk=0x100, key_mgmt_802_1x=0x200 )
	wifi_ap_modes = set(['unknown', 'adhoc', 'infrastructure'])

	wifi_pass_state = set([None, 'success', 'error'])

	wifi_conn_res = set([
		'idle_disconnected', 'idle_unavailable',
		'live_init', 'live_connect', 'live_config', # connect = prepare-auth, config = ip_* and later
		'done',
		'fail_auth', 'fail_addr', 'fail_link', 'fail' ])
	wifi_conn_res_dict = dict(
		prepare='connect', config='connect', need_auth='connect',
		ip_config='config', ip_check='config', secondaries='config' )
	wifi_conn_res_text = dict(
		idle_disconnected='Idle', idle_unavailable='Unavailable',
		live_init='Initiating connection',
		live_connect='Authenticating', live_config='Configuring network parameters',
		done='Idle',
		fail_auth='Authentication failed', fail_addr='Network configuration failed',
		fail_link='Network became unreachable', fail='Association failed' )

	wifi_conn_enabled = None
	wifi_conn_res_reqs = list()
	wifi_conn_res_code = None
	wifi_conn_res_ap = None
	wifi_conn_res_act = 'Idle'
	wifi_conn_res_last = 'Disconnected'
	_wifi_conn_res_fail_reason = None # used only for logging
	_wifi_conn_res_config = None

	wifi_iface_detect_lock = defer.DeferredLock()
	wifi_iface_detect_task = None
	wifi_iface_detect_delay = 2

	dev_up, dev_signals = dict(), dict()
	iface_set = set()


	@property
	def wifi_dev_path(self):
		if not self.wifi_dev: return None
		return self.wifi_dev.path

	@property
	def wifi_conn_res_config(self):
		if self.wifi_conn_res_code != 'done': return
		return self._wifi_conn_res_config


	def _iface_detect_lock(func):
		@ft.wraps(func)
		@defer.inlineCallbacks
		def _wrapper(self, *args, **kws):
			yield self.wifi_iface_detect_lock.acquire()
			try: yield func(self, *args, **kws)
			finally: self.wifi_iface_detect_lock.release()
		return _wrapper

	@defer.inlineCallbacks
	def iface_detect(self):
		dev_list = yield self.dbus.nm.GetDevices()
		assert not self.wifi_iface, self.wifi_iface
		for dev_path in set(dev_list).difference(self.iface_set):
			yield self.iface_added(dev_path)

	@_iface_detect_lock
	@defer.inlineCallbacks
	def iface_added(self, dev_path):
		self.iface_set.add(dev_path)

		dev = self.dbus.ref('Device', dev_path)
		iface = yield dev.get('Interface')
		iface_type = yield dev.get('DeviceType')
		iface_state = yield dev.get('State')

		self.log.debug('Detected %r interface: %s (%s)', iface_type, iface, iface_state)

		if dev_path not in self.dev_signals:
			self.dev_signals.setdefault(dev_path, set()).add(
				(yield dev.signal('StateChanged', self.iface_changed)) )

		if iface_state == 'activated': # for all interfaces, not just wifi
			# yield self.hook_iface_up(iface, dev)
			self.dev_up[dev_path] = iface

		if iface_type != 'wifi': defer.returnValue(None)

		def skip(reason, level='warn'):
			getattr(self.log, level)('Skipping wifi interface (reason: %s): %s', reason, iface)
			defer.returnValue(None)

		if self.wifi_iface: skip('extra')

		sec_id = yield dev.get('WirelessCapabilities', iface='Device.Wireless')
		yield self.wifi_added(iface, dev, sec_id)

	@_iface_detect_lock
	def iface_changed(self, dev, new_state, old_state, reason):
		return self.iface_changed_apply(dev, new_state, old_state, reason)

	@defer.inlineCallbacks
	def iface_changed_apply(self, dev, new_state, old_state=None, reason=None):
		new_state, old_state = map(
			ft.partial(dev.interpret_prop_value, 'State'),
			[new_state, old_state] )
		reason = dev.interpret_prop_value('Reason', reason)
		iface = yield dev.get('Interface')
		iface_type = yield dev.get('DeviceType')
		dev_is_wifi = dev.path == self.wifi_dev_path

		log_status = lambda msg, level='debug':\
			getattr(self.log, level)(
				'%s (dev: %s/%s): %s -> %s, %s',
				msg, iface_type, iface, old_state, new_state, reason )
		log_status('Interface state-change')

		if new_state == old_state:
			log_status('Skipping null state-change')
			defer.returnValue(None)

		# Hooks for active interfaces
		if new_state == 'activated':
			if dev.path not in self.dev_up:
				# yield self.hook_iface_up(iface, dev)
				self.dev_up[dev.path] = iface
		elif old_state == 'activated':
			if dev.path in self.dev_up:
				iface_old = self.dev_up.pop(dev.path)
				# yield self.hook_iface_down(iface_old)

		if dev_is_wifi:
			# React to external "on/off" switching
			if new_state == 'unmanaged': # reason=sleeping
				yield self.wifi_conn_enabled_set(False)
			elif old_state == 'unmanaged': # reason=now_managed
				yield self.wifi_conn_enabled_set(True)

			# Auth-fail scenario - WPA/RSN:
			#  02:26:35 :: disconnected -> prepare, unknown
			#  02:26:35 :: prepare -> config, unknown
			#  02:26:35 :: config -> need_auth, unknown
			#  dbus_GetSecrets
			#  02:26:35 :: need_auth -> prepare, unknown
			#  02:26:35 :: prepare -> config, unknown
			#  02:26:40 :: config -> need_auth, supplicant_disconnect
			#  dbus_GetSecrets not-saved
			#  02:26:40 :: need_auth -> failed, no_secrets
			#  02:26:40 :: failed -> disconnected, unknown

			# Auth-fail scenario - WEP:
			#  05:29:58 :: prepare -> config, unknown
			#  05:29:58 :: config -> need_auth, unknown
			#  dbus_GetSecrets
			#  05:29:58 :: need_auth -> prepare, unknown
			#  05:29:58 :: prepare -> config, unknown
			#  05:30:24 :: config -> failed, ssid_not_found
			#  05:30:24 :: failed -> disconnected, unknown

			# Auth-success:
			#  16:09:55 :: need_auth -> prepare, unknown
			#  16:09:55 :: prepare -> config, unknown
			#  16:09:56 :: config -> ip_config, unknown
			#  fail:
			#   16:10:26 :: ip_config -> failed, config_unavailable
			#   16:10:26 :: failed -> disconnected, unknown
			#  success:
			#   16:09:57 :: ip_config -> secondaries, unknown
			#   16:09:57 :: secondaries -> activated, unknown

			if new_state == 'failed':
				self.wifi_conn_res_fail_reason = reason
				if old_state == 'need_auth' and reason == 'no_secrets':
					self.wifi_update_ap(uid=self.wifi_conn_res_ap.uid, pass_state='error')
					# Redundant with DBusSecretAgent getting GetSecrets with not-saved flag
					self.secrets.update(self.wifi_conn_res_ap.uuid, state='error')

			elif new_state == 'disconnected':
				if self.wifi_conn_res_code == 'live_connect':
					self.wifi_status_update_fail('auth')
				elif self.wifi_conn_res_code == 'live_config':
					self.wifi_status_update_fail('addr')
				elif self.wifi_conn_res_code is None:
					self.wifi_status_update('idle_disconnected', 'Disconnected')
				elif self.wifi_conn_res_code == 'activated': pass # nm bug? sent after disconnect-connect
				elif reason == 'user_requested' or old_state == 'unavailable': pass
				elif self.wifi_conn_enabled:
					self.log.warn(
						'Unhandled disconnection reason transition: %s -> %s, %s (last fail reason: %s)',
						old_state, new_state, reason, self.wifi_conn_res_fail_reason )

			elif new_state in self.wifi_conn_res_dict: # "in-progress"
				if self.wifi_conn_res_dict[new_state] != self.wifi_conn_res_dict.get(old_state):
					if old_state == 'config' and new_state == 'ip_config':
						self.wifi_update_ap(uid=self.wifi_conn_res_ap.uid, pass_state='success')
						self.secrets.update(self.wifi_conn_res_ap.uuid, state='success')
					elif old_state == 'disconnected':
						if not (yield self.wifi_status_update_ap()):
							defer.returnValue(None)
					self.wifi_status_update_live(self.wifi_conn_res_dict[new_state])

			elif new_state == 'activated':
				config = yield self.wifi_dev_config()
				self.wifi_status_update_done(self.wifi_conn_res_ap, config)

			elif new_state == 'unmanaged'\
				or old_state == 'unmanaged'\
				or old_state == 'unknown': pass

			else:
				self.log.warn( 'Unhandled connection state'
					' transition: %s -> %s, %s', old_state, new_state, reason )

	@_iface_detect_lock
	@defer.inlineCallbacks
	def iface_removed(self, dev_path):
		self.iface_set.discard(dev_path)
		for sig_ref in self.dev_signals.get(dev_path, set()): yield sig_ref.release()
		if dev_path in self.dev_up:
			iface_old = self.dev_up.pop(dev.path)
			# yield self.hook_iface_down(iface_old)
		if dev_path == self.wifi_dev_path:
			self.wifi_removed('iface_removed')

	def wifi_init(self):
		self.log.debug('WiFi state init')

		for ap in self.wifi_aps: self.wifi_remove_ap(ap)
		for sig_ref in self.wifi_signals: reactor.callLater(0, sig_ref.release)
		for sig_ref_set in self.wifi_signals_ap.viewvalues():
			for sig_ref in sig_ref_set: reactor.callLater(0, sig_ref.release)
		self.wifi_signals, self.wifi_signals_ap = list(), dict()

		self.wifi_iface = self.wifi_dev = None # str/ref
		self.wifi_caps, self.wifi_aps = list(), dict()

		for req in self.wifi_conn_res_reqs: req.cancel()
		self.wifi_conn_res_reqs = list()

	@defer.inlineCallbacks
	def wifi_dev_config_get(self, dev):
		config = dict(nameservers=set())
		for n in 4, 6:
			conf_path = yield dev.get('Ip{}Config'.format(n))
			if conf_path != '/':
				conf_obj = self.dbus.ref( 'IP{}Config'.format(n), conf_path)
				addrs = yield conf_obj.get('Addresses')
				addrs = list(
					(ntop(addr, n), prefix, ntop(gw, n, none_for_0=True))
					for addr, prefix, gw in addrs )
				config['nameservers'].update(
					ntop(addr, n) for addr in (yield conf_obj.get('Nameservers')) )
			else: addrs = list()
			config['ipv{}_addrs'.format(n)] = addrs
		defer.returnValue(config)

	@defer.inlineCallbacks
	def wifi_dev_config(self):
		config = yield self.wifi_dev_config_get(self.wifi_dev)
		self._wifi_conn_res_config = config
		defer.returnValue(config)

	def wifi_sec_translate(self, sec_id):
		caps = set(['none'])
		cap = lambda cap: sec_id & self.wifi_sec_dict[cap]
		if cap('wpa') or cap('rsn'):
			if cap('cipher_tkip'): caps.add('wpa-tkip')
			if cap('cipher_ccmp'): caps.add('wpa-ccmp')
		if cap('cipher_wep40') or cap('cipher_wep104'): caps.add('wep')
		return caps

	def wifi_ap_sec_translate(self, sec_id):
		cap = lambda cap: sec_id & self.wifi_ap_sec_dict[cap]
		key = cipher = None
		if cap('key_mgmt_psk'): key, cipher = 'psk', 'pair'
		elif cap('key_mgmt_802_1x'): key, cipher = 'enterprise', 'group'
		if key:
			# WEP doesn't seem to be ever triggered here,
			#  APs with it just have privacy=True and sec_id=0
			if cap('{}_wep40'.format(cipher)) or cap('{}_wep104'.format(cipher)): cipher = 'wep'
			elif cap('{}_tkip'.format(cipher)): cipher = 'wpa-tkip'
			elif cap('{}_ccmp'.format(cipher)): cipher = 'wpa-ccmp'
			if key != 'psk': cipher = 'enterprise-{}'.format(cipher) # marks it as unsupported
		return cipher or 'none'

	@defer.inlineCallbacks
	def wifi_update_ap_auto(self, uid, value, action=False):
		ap = self.wifi_aps[uid]
		conn_obj = self.dbus.ref( 'Settings.Connection',
			(yield self.dbus.nm_settings.GetConnectionByUuid(ap.uuid)) )
		settings = yield conn_obj.GetSettings()
		settings['connection']['autoconnect'] = value
		yield conn_obj.Update(dbus_variant_sanitize(settings))
		self.wifi_update_ap(uid=uid, auto=value, action=action)

	def wifi_update_ap_lock(self, ap_path):
		self.wifi_aps[NMAP.get_uid(ap_path)] = defer.Deferred()

	def wifi_update_ap(self, uid=None, force_new=False, action=False, **ap_params):
		self.log.debug('Updating AP parameters (uid: %s): %s', uid, ap_params)
		d = None
		if uid is None:
			if 'pass_state' not in ap_params:
				uuid = NMAP.get_uuid(ap_params['hwaddr'])
				# Doesn't acknowledge passphrases that are stored but not validated
				ap_params['pass_state'] = self.secrets.get(uuid, 'state')
			else: uuid = None
			ap = NMAP(**ap_params)
			uid = ap.uid
			d = self.wifi_aps.get(uid)
			if isinstance(d, defer.Deferred): del self.wifi_aps[uid]
			else: d = None
			assert not uuid or ap.uuid == uuid, [ap.uuid, uuid]
			assert not force_new or uid not in self.wifi_aps, [uid, ap_params]
		else:
			assert not force_new, [uid, ap_params]
			assert 'dbus_path' not in ap_params, ap_params
			assert uid in self.wifi_aps, [uid, ap_params]
		if uid in self.wifi_aps:
			ev, ap = 'update', self.wifi_aps[uid].data
			ap.update(ap_params)
			del ap['uid']
			ap = NMAP(**ap)
			assert ap.uid == uid, [ap.uid, uid]
		else:
			ev = 'new'
		assert ap.sec in self.wifi_sec, [ap.sec, self.wifi_sec]
		assert ap.mode in self.wifi_ap_modes, ap.mode
		assert ap.pass_state in self.wifi_pass_state, ap.pass_state
		self.wifi_aps[ap.uid] = ap
		if not action: self.webui.handle_ap_update(ev, ap)
		if d: d.callback(ap)
		return ap.uid

	def wifi_remove_ap(self, uid_or_ap):
		if isinstance(uid_or_ap, NMAP): uid_or_ap = uid_or_ap.uid
		ap = self.wifi_aps.pop(uid_or_ap, None)
		if ap: self.webui.handle_ap_update('remove', ap)

	@defer.inlineCallbacks
	def wifi_aps_list(self): # XXX: maybe just don't put deferreds in there?
		aps = list()
		for k in self.wifi_aps.keys():
			aps.append((yield self.wifi_aps[k]))
		defer.returnValue(aps)


	@defer.inlineCallbacks
	def wifi_disconnect(self, action=False):
		if not (self.wifi_iface and self.wifi_dev): return
		if action:
			self.log.debug('Initiating disconnect from AP')
			# yield self.hook_iface_down(self.wifi_dev.path)
			try: yield self.wifi_dev.Disconnect()
			except txdbus_error.RemoteError as err:
				if err.errName != nm_iface_full('Device.UnknownConnection'): raise
				raise NMActionError(err)
		self.wifi_status_update_disconnect()

	@defer.inlineCallbacks
	def wifi_scan(self, reason='manual_request'):
		# XXX: crashes NetworkManager-0.9.8.8 with 6/ABRT, lol
		# Shouldn't be critical, as it does periodic scans on its own,
		#  and nm-applet doesn't even have the button
		# XXX: maybe remove the button?
		# if self.wifi_dev:
		# 	self.log.debug('Initiating AP scan (%s, reason: %s)', self.wifi_iface, reason)
		# 	yield self.wifi_dev.RequestScan(dict(), _nm_interface='Device.Wireless')
		yield None

	@defer.inlineCallbacks
	def wifi_changed(self, props):
		if 'NetworkingEnabled' in props:
			yield self.wifi_conn_enabled_set(props['NetworkingEnabled'])
		self.log.debug('NM props update: %s', props)

	@defer.inlineCallbacks
	def wifi_conn_enabled_set(self, val=None, action=False):
		if val is None: val = yield self.dbus.nm.get('NetworkingEnabled')
		else:
			assert isinstance(val, bool), val
			if action: self.log.debug('Switching to %s mode', 'online' if val else 'offline')
		self.wifi_conn_enabled = val
		if not val:
			try: yield self.wifi_disconnect(action=action)
			except NMActionError: pass
		try: yield self.dbus.nm.Enable(val)
		except txdbus_error.RemoteError as err:
			if err.errName != nm_iface_full('AlreadyEnabledOrDisabled'): raise
		else: yield self.webui.handle_online_update(val)


	@defer.inlineCallbacks
	def wifi_added(self, iface, dev, sec_id):
		'Use new WiFi interface.'
		self.wifi_iface, self.wifi_dev = iface, dev
		self.wifi_sec = self.wifi_sec_translate(sec_id)

		if self.wifi_iface_detect_task:
			self.wifi_iface_detect_task.stop()
			self.wifi_iface_detect_task = None
		reactor.callLater(0, self.wifi_scan, 'iface_added')

		assert not self.wifi_signals, self.wifi_signals
		self.wifi_signals.extend([
			(yield dev.signal( 'AccessPointAdded',
				self.wifi_update_ap_added, iface='Device.Wireless' )),
			(yield dev.signal( 'AccessPointRemoved',
				self.wifi_update_ap_removed, iface='Device.Wireless' )),
			(yield dev.signal( 'PropertiesChanged',
				self.wifi_changed, iface='org.freedesktop.DBus.Properties' )) ])

		aps = yield dev.GetAccessPoints(_nm_interface='Device.Wireless')
		for ap_path in aps: yield self.wifi_update_ap_added(dev, ap_path)

		self.log.debug( 'Using new wifi interface:'
			' %s (capabilities: %s)', self.wifi_iface, ', '.join(self.wifi_sec) )
		yield self.wifi_status_update_init()

	# @defer.inlineCallbacks
	def wifi_changed( self, dev, dbus_iface, props,
			props_missing=None, _should_not_change=['Autoconnect', 'PermHwAddress'] ):
		for k, v in props.viewitems():
			if k in _should_not_change:
				self.log.warn('Unexpected dev property change: %r = %r', k, v)
			elif k == 'WirelessCapabilities':
				self.wifi_sec = self.wifi_sec_translate(v) # XXX: UI update?
			# XXX: elif k == 'Bitrate': - not displayed currently
			# XXX: elif k == 'ActiveAccessPoint': - ap signals used instead

	@defer.inlineCallbacks
	def wifi_removed(self, reason='unspecified'):
		'Scrap currently-used WiFi interface.'
		self.log.debug( 'Resetting wifi interface (%s,'
			' reason: %s), scheduling detection task', self.wifi_iface, reason )
		yield self.wifi_conn_enabled_set(False)
		yield self.wifi_init()
		if not self.wifi_iface_detect_task:
			self.wifi_iface_detect_task = task.LoopingCall(self.iface_detect)
			self.wifi_iface_detect_task.start(self.wifi_iface_detect_delay, now=True)


	def wifi_status_update(self, code, status, action=None, ap=None, config=None):
		assert code in self.wifi_conn_res, code
		assert code != 'done' or (ap and config), [code, ap, config]
		# live_* and fail_* only make sense UI-wise with ap
		assert not code or not (( code.startswith('fail_')
			or code.startswith('live_') ) and not ap), [code, ap]
		if action is None: action = self.wifi_conn_res_text[code]
		self.log.debug( 'Status update: %s, %s'
			' (code: %s, ap: %s, config: %s)', status, action, code, ap, config )
		self.wifi_conn_res_code, self.wifi_conn_res_ap = code, ap
		self.wifi_conn_res_last, self.wifi_conn_res_act = status, action
		self.webui.handle_status_update(status, action, code, ap, config)
		return code

	def wifi_status_update_done(self, ap, config):
		self.wifi_conn_res_fail_reason = None
		status = 'Connected to "{}"'.format(ap.ssid)
		res = self.wifi_status_update('done', status, ap=ap, config=config)
		reqs, self.wifi_conn_res_reqs = self.wifi_conn_res_reqs, list()
		for d in reqs: d.callback(res)
		return res

	def wifi_status_update_disconnect(self):
		self.wifi_conn_res_fail_reason = None
		return self.wifi_status_update('idle_disconnected', 'Disconnected')

	def wifi_status_update_fail(self, code, status='Disconnected', action=None, ap=None):
		if ap is None: ap = self.wifi_conn_res_ap
		if not code.startswith('fail_'): code = 'fail_{}'.format(code)
		res = self.wifi_status_update(code, status, action, ap)
		reqs, self.wifi_conn_res_reqs = self.wifi_conn_res_reqs, list()
		for d in reqs: d.errback(NMConnectionError(res))
		return res

	def wifi_status_update_live(self, code, ap=None):
		if ap is None: ap = self.wifi_conn_res_ap
		assert ap
		if not code.startswith('live_'): code = 'live_{}'.format(code)
		status = 'Connecting to "{}"'.format(ap.ssid)
		return self.wifi_status_update(code, status, ap=ap)

	@defer.inlineCallbacks
	def wifi_status_update_ap(self):
		conn_path = yield self.wifi_dev.get('ActiveConnection')
		if conn_path != '/':
			self.log.debug('Found Active AP: %s', conn_path)
			ap_path = yield self.dbus.ref('Connection.Active', conn_path).get('SpecificObject')
			self.wifi_conn_res_ap = yield self.wifi_aps[NMAP.get_uid(ap_path)]
		else:
			self.log.debug('No Active AP detected')
		defer.returnValue(self.wifi_conn_res_ap)

	@_iface_detect_lock
	def wifi_status_update_auto(self):
		return self.wifi_status_update_init()

	@defer.inlineCallbacks
	def wifi_status_update_init(self):
		'Send full status update from current NM state.'
		self.wifi_conn_res_fail_reason = None
		state = yield self.wifi_dev.get('State')
		yield self.wifi_status_update_ap()
		yield self.iface_changed_apply(self.wifi_dev, state)


	@defer.inlineCallbacks
	def wifi_connect(self, ap_info):
		try: ap = self.wifi_aps[ap_info['uid']]
		except KeyError:
			defer.returnValue(self.wifi_status_update(
				'fail', 'Disconnected', 'Failed to find specified network' ))

		p_prev = self.secrets.get(ap.uuid, 'p')
		if isinstance(ap_info, NMAP):
			ap_info = dict(uid=ap_info.uid)
			ap_info['p'] = p_prev
		else:
			if not ap_info.get('p'): ap_info['p'] = p_prev
			elif ap_info['p'] != p_prev: ap_info['state'] = None
			if ap_info['p'] is None: self.secrets.unset(ap.uuid)
			else: self.secrets.set(ap.uuid, ap_info, 'p', 'state')

		if 'auto' in ap_info:
			self.wifi_update_ap(uid=ap.uid, auto=ap_info['auto'])

		self.log.debug('Initiating AP connection to %s', ap)

		def stop_if_ap_is_gone():
			if self.wifi_dev and ap.uid in self.wifi_aps: return
			defer.returnValue(self.wifi_status_update('fail_link', 'Disconnected', ap=ap))

		ap_obj = self.dbus.ref('AccessPoint', ap.dbus_path)
		try:
			conn_path = yield self.dbus.nm_settings.GetConnectionByUuid(ap.uuid)
			conn_obj = self.dbus.ref('Settings.Connection', conn_path)
			settings = yield conn_obj.GetSettings()
		except txdbus_error.RemoteError as err:
			if err.errName != nm_iface_full('Settings.InvalidConnection'): raise
			conn_obj, settings = None, dict()
		else:
			self.log.debug('Reusing existing connection Settings (path: %s): %s', conn_path, settings)

		# ref-settings.html from NM gtk-doc
		settings['connection'] = dict(
			id=ap.ssid, uuid=ap.uuid,
			type='802-11-wireless', autoconnect=ap_info['auto'] )
		settings['802-11-wireless'] = dict(
			ssid=list(txdbus_marshal.Byte(ord(c)) for c in ap.ssid), mode=ap.mode )
		if ap.sec != 'none':
			settings['802-11-wireless']['security'] = '802-11-wireless-security'
			if ap.sec.startswith('wpa-'):
				if len(ap_info['p']) < 8:
					defer.returnValue(self.wifi_status_update_fail( 'auth',
						action='WPA passphrase/key must be 8-32 characters long', ap=ap ))
				if ap.mode == 'adhoc': key_mgmt = 'wpa-none'
				elif ap.mode == 'infrastructure': key_mgmt = 'wpa-psk'
				else: raise NotImplementedError # XXX: error for e.g. wpa-enterprise
				settings['802-11-wireless-security'] = {'key-mgmt': key_mgmt}
			elif ap.sec == 'wep':
				try: int(ap_info['p'], 16)
				except ValueError: pw_hex = False
				else: pw_hex = True
				pw_len = len(ap_info['p'])
				pw_type = 1 if pw_len in [5, 13]\
					or (pw_hex and pw_len in [10, 26]) else 2
				settings['802-11-wireless-security'] = {
					'key-mgmt': 'none', 'auth-alg': 'shared',
					'wep-key-flags': 1, 'wep-key-type': pw_type }
		else:
			settings.pop('802-11-wireless-security', None)
		settings['ipv4'] = settings['ipv6'] = dict(method='auto')

		yield stop_if_ap_is_gone()
		self.log.debug( 'Activating connection with'
			' settings (update: %s): %s', bool(conn_obj), settings )
		if conn_obj:
			yield conn_obj.Update(settings)
			active_path = yield self.dbus.nm\
				.ActivateConnection(conn_path, self.wifi_dev_path, ap.dbus_path)
		else:
			conn_path, active_path = yield self.dbus.nm\
				.AddAndActivateConnection(settings, self.wifi_dev_path, ap.dbus_path)
			self.log.debug('Created new Settings object (path: %s)', conn_path)

		d = defer.Deferred()
		self.wifi_conn_res_reqs.append(d)
		self.wifi_status_update_live('init', ap)
		defer.returnValue((yield d))


	@defer.inlineCallbacks
	def wifi_update_ap_added(self, dev, ap_path):
		self.wifi_update_ap_lock(ap_path)
		ap = self.dbus.ref('AccessPoint', ap_path)
		self.wifi_signals_ap.setdefault(ap.uid, set()).add(
			(yield ap.signal('PropertiesChanged', self.wifi_update_ap_changed)) )
		ap_props = dict()
		for k in 'Ssid', 'Mode', 'Flags', 'Strength', 'HwAddress', 'MaxBitrate':
			ap_props[k] = yield ap.get(k)
		ap_props['RsnFlags'] = ap_props['WpaFlags'] = None # should be fetched
		ap_params = yield self.wifi_update_ap_changed(ap, ap_props, as_dict=True)
		ap_params['dbus_path'] = ap_path

		ap_uuid = NMAP.get_uuid(ap_params['hwaddr'])
		try:
			conn_path = yield self.dbus.nm_settings.GetConnectionByUuid(ap_uuid)
		except txdbus_error.RemoteError as err:
			if err.errName != nm_iface_full('Settings.InvalidConnection'): raise
			ap_params['auto'] = True
		else:
			conn_obj = self.dbus.ref('Settings.Connection', conn_path)
			settings = yield conn_obj.GetSettings()
			ap_params['auto'] = settings['connection'].get('autoconnect', False)

		self.wifi_update_ap(force_new=True, **ap_params)

	@defer.inlineCallbacks
	def wifi_update_ap_changed( self, ap, props, as_dict=False,
			_as_is=dict(Strength='strength', Mode='mode', HwAddress='hwaddr', MaxBitrate='bitrate') ):
		ap_update = dict()
		for k, v in props.viewitems():
			if k in ['RsnFlags', 'WpaFlags']:
				sec_id = yield ap.get('RsnFlags')
				if not sec_id: sec_id = yield ap.get('WpaFlags')
				ap_update['sec'] = self.wifi_ap_sec_translate(sec_id)
			elif k == 'Ssid':
				ap_update['ssid'] = ''.join(map(chr, v))
			elif k == 'Flags':
				ap_update['private'] = bool(v & self.wifi_ap_flags['privacy'])
			elif k in _as_is: ap_update[_as_is[k]] = v
			else: self.log.warn('Unrecognized property in AP update: %r = %r', k, v)
		if ap_update.get('private') and ap_update['sec'] == 'none': ap_update['sec'] = 'wep'
		if as_dict: defer.returnValue(ap_update)
		else:
			self.wifi_update_ap(uid=NMAP.get_uid(ap.path), **ap_update)

	@defer.inlineCallbacks
	def wifi_update_ap_removed(self, dev, ap_path):
		ap_uid = NMAP.get_uid(ap_path)
		for sig_ref in self.wifi_signals_ap.get(ap_uid, set()): yield sig_ref.release()
		self.wifi_remove_ap(ap_uid)



dbus_iface_nm_ns = 'org.freedesktop.NetworkManager'
dbus_iface_props = 'org.freedesktop.DBus.Properties'
dbus_bus_name_nm = dbus_iface_nm_ns

def nm_iface_full(iface, fallback=None):
	if fallback is not None and iface is None: iface = fallback
	if iface is not None and (
			not iface.startswith(dbus_iface_nm_ns) and (not iface or iface[0].isupper()) ):
		if iface: iface = '.' + iface
		iface = dbus_iface_nm_ns + iface
	return iface

def nm_iface_short(iface):
	if iface.startswith(dbus_iface_nm_ns):
		iface = iface[len(dbus_iface_nm_ns):].lstrip('.')
	return iface

def dbus_variant_sanitize( data,
		bytearrays=True, empty_lists=True ):
	'''Detects and gives proper types to things like bytearrays and strips
		empty lists, which break marshaling as their type cannot be determined.'''
	kws = dict(bytearrays=bytearrays, empty_lists=empty_lists)
	if isinstance(data, dict):
		data = dict(zip(
			dbus_variant_sanitize(data.keys(), bytearrays=False),
			dbus_variant_sanitize(data.values(), **kws) ))
		if empty_lists:
			for k,v in data.items():
				if not (isinstance(v, list) and not v): continue
				if empty_lists is True: del data[k]
				else: data[k] = type('list_sig', (list,), dict(dbusSignature=empty_lists))()
	elif isinstance(data, list):
		data = map(ft.partial(dbus_variant_sanitize, **kws), data)
		if bytearrays and data\
				and all((isinstance(v, int) and v <= 255) for v in data):
			data = map(txdbus_marshal.Byte, data)
	return data



class DBusUnknownEnumValue(Exception): pass

class DBusSignalRef(namedtuple('DBusSignalRef', 'name obj proxy rule_id')):

	def release(self):
		return self.proxy.signal_del(self.name, self.obj, self.rule_id)

class DBusRef(object):

	iface_wrappers = {}

	prop_wrappers = {
		'Device': dict(
			DeviceType=dict(enumerate( 'unknown ethernet wifi'
				' unused1 unused2 bt olpc_mesh wimax modem infiniband bond vlan'.split() )),
			State={
				0: 'unknown', 10: 'unmanaged', 20: 'unavailable', 30: 'disconnected',
				40: 'prepare', 50: 'config', 60: 'need_auth', 70: 'ip_config', 80: 'ip_check',
				90: 'secondaries', 100: 'activated', 110: 'deactivating', 120: 'failed' },
			Reason={
				0: 'unknown',
				1: 'none',
				2: 'now_managed',
				3: 'now_unmanaged',
				4: 'config_failed',
				5: 'config_unavailable',
				6: 'config_expired',
				7: 'no_secrets',
				8: 'supplicant_disconnect',
				9: 'supplicant_config_failed',
				10: 'supplicant_failed',
				11: 'supplicant_timeout',
				12: 'ppp_start_failed',
				13: 'ppp_disconnect',
				14: 'ppp_failed',
				15: 'dhcp_start_failed',
				16: 'dhcp_error',
				17: 'dhcp_failed',
				18: 'shared_start_failed',
				19: 'shared_failed',
				20: 'autoip_start_failed',
				21: 'autoip_error',
				22: 'autoip_failed',
				23: 'modem_busy',
				24: 'modem_no_dial_tone',
				25: 'modem_no_carrier',
				26: 'modem_dial_timeout',
				27: 'modem_dial_failed',
				28: 'modem_init_failed',
				29: 'gsm_apn_failed',
				30: 'gsm_registration_not_searching',
				31: 'gsm_registration_denied',
				32: 'gsm_registration_timeout',
				33: 'gsm_registration_failed',
				34: 'gsm_pin_check_failed',
				35: 'firmware_missing',
				36: 'removed',
				37: 'sleeping',
				38: 'connection_removed',
				39: 'user_requested',
				40: 'carrier',
				41: 'connection_assumed',
				42: 'supplicant_available',
				43: 'modem_not_found',
				44: 'bt_failed',
				45: 'gsm_sim_not_inserted',
				46: 'gsm_sim_pin_required',
				47: 'gsm_sim_puk_required',
				48: 'gsm_sim_wrong',
				49: 'infiniband_mode',
				50: 'dependency_failed',
				51: 'br2684_failed',
				52: 'modem_manager_unavailable',
				53: 'ssid_not_found',
				54: 'secondary_connection_failed' } ),
		'AccessPoint': dict(
			Mode={0: 'unknown', 1: 'adhoc', 2: 'infrastructure'} )
	}

	def __init__(self, proxy, iface, path, bus_name=None):
		self.iface_short = nm_iface_short(iface)
		self.iface_full = nm_iface_full(iface)
		self.proxy, self.path, self.bus_name = proxy, path, bus_name
		self.log = logging.getLogger('dbus.ref')

	def __hash__(self):
		return hash((self.path, self.iface_full))

	def __repr__(self):
		return '<DBusRef {} {}>'.format(self.iface_short, self.path)

	def interpret_wrapper(self, func):
		try: return self.iface_wrappers[self.iface_short][func]
		except KeyError: return self.proxy.call

	def interpret_prop_value(self, k, v, strict=False):
		if not strict and isinstance(v, types.StringTypes): return v
		try: v_dict = self.prop_wrappers[self.iface_short][k]
		except KeyError: return v
		try: v = v_dict[v]
		except KeyError:
			if strict: raise DBusUnknownEnumValue(v_dict, v)
			if strict or v is not None:
				self.log.warn('Unrecognized enum value for %s/%s: %s', self.iface_short, k, v)
			v = v_dict.get(None, v_dict.get(0)) # should return something like "unknown"
		return v

	def resolve(self, bus_name=None):
		assert '//' not in self.path, self
		if bus_name is None: bus_name = self.bus_name
		if bus_name is None: bus_name = dbus_bus_name_nm
		return self.proxy.ref_resolve(self, bus_name)

	def __getattr__(self, func):
		return ft.partial(self.interpret_wrapper(func), self, func)


	def _resolve_iface(func):
		@ft.wraps(func)
		def _wrapper(self, *args, **kws):
			iface = kws.get('iface')
			kws['iface'] = nm_iface_full(iface, self.iface_full)
			return func(self, *args, **kws)
		return _wrapper

	@_resolve_iface
	@defer.inlineCallbacks
	def get(self, k, iface=None):
		v = yield self.proxy.call(self, 'Get', iface, k, _interface=dbus_iface_props)
		defer.returnValue(self.interpret_prop_value(k, v))

	@_resolve_iface
	def set(self, k, v, iface=None):
		if isinstance(v, bool): v = txdbus_marshal.Boolean(v)
		return self.proxy.call(self, 'Set', iface, k, v, _interface=dbus_iface_props)

	@_resolve_iface
	@defer.inlineCallbacks
	def signal(self, name, callback, iface=None, pass_ref=True):
		if pass_ref:
			if pass_ref is True: pass_ref = self
			callback = ft.partial(callback, self)
		wrapper = ft.partial(self._signal_wrapper, self.path, name, callback)
		obj = yield self.resolve()
		rule_id = yield self.proxy.signal_add(obj, name, wrapper, _interface=iface)
		defer.returnValue(DBusSignalRef(name, obj, self.proxy, rule_id))

	def _signal_wrapper(self, path, name, callback, *args, **kws):
		self.log.noise('Signal: %s %s %s %s', path, name, args, kws)
		reactor.callLater(0, callback, *args, **kws)


class DBusProxy(object):

	dbus_addr = 'system'
	dbus_call_defaults = dict(
		expectReply=True, autoStart=False, timeout=20, interface=None )

	nm_ping_interval = 60
	nm_wait_limit, nm_wait_retry_delay, nm_wait_retry_factor = 300, 1, 1.2

	def __init__(self, secrets):
		self._conn_lock = defer.DeferredLock() # released/unset after connection
		self._conn_lock.acquire()
		self._secrets = secrets
		self._rules, self._refs = dict(), WeakKeyDictionary()
		self.log = logging.getLogger('dbus.proxy')

		# Static refs (XXX: nm-specific)
		self.nm = self.ref('')
		self.nm_settings = self.ref('Settings')

		reactor.callLater(0, self._dbus_connect)


	@defer.inlineCallbacks
	def _dbus_connect(self):
		assert self._conn_lock
		try:
			conn = yield txdbus_client.connect(reactor, self.dbus_addr)
			self._conn = conn
			yield self._dbus_exports()
		except:
			self.log.fatal('Exiting due to unrecoverable dbus failure')
			utils.stop()
			raise
		self.log.debug('Connected to DBus instance (address: %r)', self.dbus_addr)

		# Make sure NM is running and reachable
		try:
			delay, deadline = self.nm_wait_retry_delay, time.time() + self.nm_wait_limit
			while time.time() < deadline:
				nm_alive = yield self._dbus_test()
				if nm_alive: break
				yield utils.timeout(delay)
				delay *= self.nm_wait_retry_factor
			if not nm_alive:
				raise NMConnectionError('Failed to connect to NetworkManager dbus interface')
		except NMConnectionError as err:
			self.log.fatal('Exiting due to unrecoverable NM connection failure')
			utils.stop()
			raise
		reactor.callLater(0, self._dbus_disconnect_handler)

		self._conn_lock.release()
		self._conn_lock = None

	@defer.inlineCallbacks
	def _dbus_exports(self):
		agent = DBusSecretAgent(self._secrets)
		yield self._conn.exportObject(agent)
		reactor.callLater(0, lambda: self.ref('AgentManager').Register(nm_secret_agent_guid))

	@defer.inlineCallbacks
	def _dbus_test(self):
		try:
			nm_obj = yield self._ref_resolve(self._conn, self.nm) # doesn't grab _conn_lock
			perms = yield self.call(nm_obj, 'GetPermissions', _interface=dbus_iface_nm_ns)
			if set(perms.viewvalues()).difference(['yes']):
				raise NMConnectionError('Insufficient NM object access permissions')
		except Exception as err:
			if isinstance(err, NMConnectionError): raise
			err_type = err.__class__.__name__
			self.log.debug('Failed to query NetworkManager dbus interface: (%s) %s', err_type, err)
		else: defer.returnValue(True)

	@defer.inlineCallbacks
	def _dbus_disconnect_handler(self, nm_obj=None, reason=None, watchdog=False):
		if nm_obj is None and not watchdog:
			(yield self.nm.resolve()).notifyOnDisconnect(self._dbus_disconnect_handler)
			self._dbus_disconnect_task = task.LoopingCall(self._dbus_disconnect_handler, watchdog=True)
			self._dbus_disconnect_task.start(self.nm_ping_interval, now=False)
			defer.returnValue(None)
		elif watchdog:
			if (yield self._dbus_test()): defer.returnValue(None)
		utils.stop()

	def _connected(func):
		@ft.wraps(func)
		@defer.inlineCallbacks
		def _wrapper(self, *args, **kws):
			if self._conn_lock:
				try: yield self._conn_lock.acquire()
				finally: self._conn_lock.release()
			res = yield func(self, self._conn, *args, **kws)
			defer.returnValue(res)
		return _wrapper


	@_connected
	def ref_resolve(self, conn, ref, bus_name=None):
		return self._ref_resolve(conn, ref, bus_name)

	@defer.inlineCallbacks
	def _ref_resolve(self, conn, ref, bus_name=None):
		assert ref.proxy is self, [ref.proxy, self]
		if bus_name is None: bus_name = dbus_bus_name_nm
		try: obj = self._refs[ref][bus_name]
		except KeyError:
			if ref not in self._refs: self._refs[ref] = dict()
			self.log.noise('Resolve: %s %s', bus_name, ref.path)
			obj = yield conn.getRemoteObject(bus_name, ref.path)
			self._refs[ref][bus_name] = obj
		defer.returnValue(obj)

	def ref(self, iface, path=None):
		assert '/' not in iface, [iface, path]
		iface = nm_iface_full(iface)
		if path is None: path = '.{}'.format(iface).replace('.', '/')
		return DBusRef(self, iface, path)


	@defer.inlineCallbacks
	def _process_obj_iface_specs(self, obj_or_ref, kws, defaults=None):
		if '_nm_interface' in kws:
			assert '_interface' not in kws, kws
			kws['_interface'] = nm_iface_full(kws.pop('_nm_interface'))
		if '_interface' not in kws and isinstance(obj_or_ref, DBusRef):
			kws['_interface'] = obj_or_ref.iface_full
		if defaults is None: defaults = kws
		for k, v in defaults.viewitems():
			k = k.lstrip('_')
			kws[k] = kws.pop('_{}'.format(k), v)
		if isinstance(obj_or_ref, DBusRef): obj_or_ref = yield obj_or_ref.resolve()
		assert isinstance(obj_or_ref, txdbus_objects.RemoteDBusObject), [type(obj_or_ref), obj_or_ref]
		defer.returnValue(obj_or_ref)

	@defer.inlineCallbacks
	def call(self, obj_or_ref, func, *args, **kws):
		obj = yield self._process_obj_iface_specs(obj_or_ref, kws, self.dbus_call_defaults)
		self.log.noise( 'Call: %s %s %s %s %s', obj.objectPath,
			map(op.attrgetter('name'), obj.interfaces), func, args, kws )
		res = yield obj.callRemote(func, *args, **kws)
		defer.returnValue(res)

	@defer.inlineCallbacks
	def signal_add(self, obj_or_ref, name, callback, **kws):
		obj = yield self._process_obj_iface_specs(obj_or_ref, kws)
		assert not set(kws.keys()).difference(['interface']), kws
		rule_id = yield obj.notifyOnSignal(name, callback, **kws)
		self.log.noise( 'Signal add: %s %s (iface: %s), rule=%s',
			obj.objectPath, name, kws.get('interface'), rule_id )
		defer.returnValue(rule_id)

	@defer.inlineCallbacks
	def signal_del(self, name, obj, rule_id):
		self.log.noise('Signal del: %s %s, rule=%s', name, obj.objectPath, rule_id)
		yield obj.cancelSignalNotification(rule_id)



def _dbus_log_calls(func):
	func_name = func.func_name
	if func_name.startswith('dbus_'): func_name = func_name[5:]
	@ft.wraps(func)
	@defer.inlineCallbacks
	def _wrapper(self, *args, **kws):
		call_id = os.urandom(2).encode('hex')
		self.log.noise('Call[%s]: %s %s %s', call_id, func_name, args, kws)
		try: res = yield func(self, *args, **kws)
		except Exception as err:
			err_type = err.__class__.__name__
			if not isinstance(err, DBusSecretAgentError):
				self.log.exception('Call[%s] unhandled error: (%s) %s', call_id, err_type, err)
			else: self.log.debug('Call[%s] error return: (%s) %s', call_id, err_type, err)
			raise
		self.log.noise('Call[%s] result: %s', call_id, res)
		defer.returnValue(res)
	return _wrapper


nm_secret_agent_guid = 'nah.naah.naaaah.SecretAgent' # XXX: some proper product-related guid?


class DBusSecretAgentError(Exception):

	dbusErrorName = '{}.Error'.format(nm_secret_agent_guid)


class DBusSecretAgent(txdbus_objects.DBusObject):

	_method = txdbus_iface.Method

	dbusInterfaces = [txdbus_iface.DBusInterface(
		nm_iface_full('SecretAgent'),
		_method('GetSecrets', arguments='a{sa{sv}}osasu', returns='a{sa{sv}}'),
		_method('CancelGetSecrets', arguments='os', returns=''),
		_method('SaveSecrets', arguments='a{sa{sv}}o', returns=''),
		_method('DeleteSecrets', arguments='a{sa{sv}}o', returns='') )]

	def __init__(self, secrets):
		self.log = logging.getLogger('nm.secrets')
		self.secrets = secrets
		super(DBusSecretAgent, self).__init__(
			'/{}'.format(nm_iface_full('SecretAgent').replace('.', '/')) )

	@_dbus_log_calls
	def dbus_GetSecrets(self, connection, connection_path, setting_name, hints, flags):
		assert setting_name == '802-11-wireless-security', setting_name
		ap_uuid = connection['connection']['uuid']
		pw = self.secrets.get(ap_uuid).get('p')
		if connection['802-11-wireless-security'].get('key-mgmt') != 'none': # wpa
			pw_prev = connection['802-11-wireless-security'].get('psk')
			if flags & 0x02 and pw == pw_prev: # prev auth with stored key has failed
				self.secrets.update(ap_uuid, state='error') # redundant with no_secrets nm-state-signal
				pw = None
			else: sec = {'psk': pw}
		else: # wep
			# WEP connections don't re-request key and fail with reason=ssid_not_found
			sec = dict(('wep-key{}'.format(n), pw) for n in xrange(4))
		if not pw: raise DBusSecretAgentError('No secrets available')
		return {'802-11-wireless-security': sec}

	@_dbus_log_calls
	def dbus_SaveSecrets(self, connection, connection_path): pass
	@_dbus_log_calls
	def dbus_CancelGetSecrets(self, connection_path, setting_name): pass
	@_dbus_log_calls
	def dbus_DeleteSecrets(self, connection, connection_path): pass
