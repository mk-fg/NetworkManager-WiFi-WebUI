#-*- coding: utf-8 -*-

from __future__ import print_function

from nm_wifi_webui import utils

from txsockjs.factory import SockJSResource
import jinja2

from twisted.internet import reactor, defer, task, protocol
from twisted.python.filepath import FilePath
from twisted.web.static import File
from twisted.web.client import urlunparse
from twisted.web.util import ParentRedirect
from twisted.web import resource, server, http

import itertools as it, operator as op, functools as ft
import logging, json


class EventProtocol(protocol.Protocol):

	def __init__(self):
		self.log = logging.getLogger('webui.event.protocol')
		self.log_peer = None

	def connectionMade(self):
		self.log_peer = str(self.transport.getPeer())
		self.log.debug('Connection to client: %s', self.log_peer)
		self.factory.clients.add(self)

	def dataReceived(self, data):
		self.log.noise('Data from client %s: %r', self.log_peer, data)
		self.factory.handle(data)

	def dataSend(self, data):
		self.log.noise('Sending to client %s: %r', self.log_peer, data)
		self.transport.write(data)

	def connectionLost(self, reason):
		self.log.debug('Lost connection to client %s: %s', self.log_peer, reason)
		self.factory.clients.remove(self)


class ClientEvents(protocol.Factory):

	protocol = EventProtocol

	def __init__(self, handler):
		self.log = logging.getLogger('webui.event.factory')
		self.clients, self.handler = set(), handler

	def handle(self, data):
		try: ev = json.loads(data)
		except ValueError:
			self.log.debug('Invalid event data, ignoring: %r', data)
			return
		return self.handler(ev)

	def send(self, ev):
		data = json.dumps(ev)
		for client in self.clients: client.dataSend(data)


class WebUIAction(ParentRedirect):

	isLeaf = True

	def __init__(self, webui, action, *action_args, **action_kws):
		resource.Resource.__init__(self)
		self.log = logging.getLogger('webui.actions')
		self.webui = webui
		self.action = ft.partial(getattr(self, action), *action_args, **action_kws)

	def nm_online(self):
		reactor.callLater(0, self.webui.nm.wifi_conn_enabled_set, True)

	def nm_offline(self):
		reactor.callLater(0, self.webui.nm.wifi_conn_enabled_set, False)

	def nm_scan(self):
		reactor.callLater(0, self.webui.nm.wifi_scan)

	def nm_disconnect(self, ap):
		self.webui.nm.wifi_disconnect(ap, action=True)

	def render(self, request):
		self.action()
		return ParentRedirect.render(self, request)


class WebUI(resource.Resource):

	nm = None # set externally
	url_events = 'events'
	post_nm_wait_max = 20

	def __init__(self, static_path, templates_path):
		resource.Resource.__init__(self)
		self.log = logging.getLogger('webui.core')

		for action in 'online', 'offline', 'scan':
			self.putChild(action, WebUIAction(self, 'nm_{}'.format(action)))

		if not isinstance(static_path, FilePath):
			static_path = FilePath(static_path)
		for p in static_path.listdir():
			self.putChild(p, File(static_path.child(p).path))

		if not isinstance(templates_path, FilePath):
			templates_path = FilePath(templates_path)
		self.templates = jinja2.Environment(
			loader=jinja2.FileSystemLoader(templates_path.path) )
		self.templates.filters['json'] = self.jinja2_json
		self.templates.filters['unless_false'] = self.jinja2_unless_false

		self.events = ClientEvents(self.handle_command)
		self.putChild('events', SockJSResource(self.events))


	def jinja2_json(self, val):
		return json.dumps(val)

	def jinja2_unless_false(self, res, val):
		return res if not val is False else ''


	def dispatch(self, ev):
		assert ev['q'] in ['online', 'new', 'update', 'remove', 'result', 'status'], ev
		assert (ev['q'] not in ['result', 'status'] and ev.get('ap'))\
			or (ev['q'] != 'result' or ev['id']), ev
		assert ev['q'] != 'status' or (ev.get('status') and ev.get('action')), ev
		self.events.send(ev)

	def dispatch_status(self, status=None, action=None, code=None, ap_uid=None, config=None):
		if not (status or action or config):
			code, ap = self.nm.wifi_conn_res_code, self.nm.wifi_conn_res_ap
			status, action = self.nm.wifi_conn_res_last, self.nm.wifi_conn_res_act
			config = self.nm.wifi_conn_res_config
			ap_uid = ap and ap.uid
		config = self.get_config_params(config) if config else dict()
		self.dispatch(dict( q='status',
			status=status, action=action, code=code, ap_uid=ap_uid, config=config ))

	def dispatch_online(self, val=None):
		if val is None: val = self.nm.wifi_conn_enabled
		self.dispatch(dict(q='online', value=val))


	@defer.inlineCallbacks
	def handle_command(self, ev):
		assert ev['q'] in ['online', 'connect', 'disconnect', 'scan', 'sync', 'auto'] and ev['id'], ev
		dispatch = lambda r,**kw: self.dispatch(dict(q='result', id=ev['id'], r=r, **kw))

		if ev['q'] == 'online':
			yield self.nm.wifi_conn_enabled_set(bool(ev['value']), action=True)
			dispatch('done')

		if ev['q'] == 'disconnect':
			try: yield self.nm.wifi_disconnect(action=True)
			except self.nm.NMActionError: pass
			dispatch('done')

		elif ev['q'] == 'connect':
			form = dict()
			for v in ev['form']:
				form.setdefault(v['name'], list()).append(v['value'])
			form = self.ap_info_args(form)
			try: conn_res = yield self.nm.wifi_connect(form)
			except Exception as err:
				self.log.error('NM connection attempt failed (%s)', err)
				dispatch('fail')
			else:
				assert conn_res in self.nm.wifi_conn_res, conn_res
				dispatch(conn_res)

		elif ev['q'] == 'scan':
			yield self.nm.wifi_scan()
			dispatch('done', aps=self.get_ap_data())

		elif ev['q'] == 'sync':
			self.dispatch_online()
			for ap in (yield self.nm.wifi_aps_list()):
				self.dispatch(dict(q='new', ap=self.ap_info(ap)))
			self.dispatch_status()
			dispatch('done', aps=self.get_ap_data())

		elif ev['q'] == 'auto':
			self.nm.wifi_update_ap_auto(ev['ap_uid'], ev['value'], action=True)
			dispatch('done')

	def handle_ap_update(self, ev, ap):
		assert ev in ['new', 'update', 'remove'], ev
		self.dispatch(dict(q=ev, ap=self.ap_info(ap)))

	def handle_status_update(self, status, action, code, ap, config):
		self.dispatch_status( status=status, action=action,
			code=code, ap_uid=ap and ap.uid, config=config )

	def handle_online_update(self, val=None):
		self.dispatch_online(val)


	def ap_info(self, ap):
		ap = ap.data
		ap['sec'] = ap['sec'].upper()
		ap['title'] = '\n'.join([ 'SSID: {0[ssid]}',
				'Mode: {0[mode]}', '{sec}',
				'Signal strength: {0[strength]}%',
				'Bitrate: {rate:.1f} Mbps', 'BSSID: {0[hwaddr]}' ])\
			.format( ap, rate=ap['bitrate'] / 1000.0,
				sec='Open Access Point' if not ap['private'] else 'Security: {}'.format(ap['sec']) )
		assert ap['pass_state'] in ['success', 'error', None], ap['pass_state']
		return ap

	def ap_info_args(self, args):
		ap = dict()
		for k in 'uid', 'p':
			v, = args[k]
			if isinstance(v, unicode): v = v.encode('utf-8')
			ap[k] = v
		ap['auto'] = bool(args.get('auto', False))
		for k in 'connect', 'disconnect': ap[k] = bool(args.get(k))
		return ap

	def get_ap_data(self):
		return map( self.ap_info,
			sorted(self.nm.wifi_aps.viewvalues(), key=op.attrgetter('uid')) )

	def get_config_params(self, config):
		addrs = list()
		for addr, prefix, gw in it.chain(config['ipv4_addrs'], config['ipv6_addrs']):
			gw = '' if not gw else ' (gw: {})'.format(gw)
			addrs.append('{}/{}{}'.format(addr, prefix, gw))
		if not addrs: return 'not configured'
		data = ['Address{}: {}'.format('es' if len(addrs) > 1 else '', ', '.join(sorted(addrs)))]
		nameservers = config.get('nameservers')
		if nameservers:
			data.append('Nameserver{}: {}'.format(
				's' if len(nameservers) > 1 else '', ', '.join(sorted(nameservers)) ))
		return '<br>'.join(data)


	def _render_headers(self, request, ct='text/html; charset=UTF-8'):
		request.setHeader('Expires', '-1')
		request.setHeader('Cache-Control', 'private, max-age=0')
		request.setHeader('X-UA-Compatible', 'IE=edge,chrome=1')
		request.setHeader('Content-Type', ct)


	def render_GET(self, request):
		sock = request.getHost()
		nm_code = self.nm.wifi_conn_res_code
		nm_connection = not (
			nm_code.startswith('idle_') or nm_code.startswith('fail_') )
		nm_config = self.nm.wifi_conn_res_config
		if nm_config: nm_config = self.get_config_params(nm_config)
		env = dict(
			ap_data=self.get_ap_data(),
			nm_enabled=self.nm.wifi_conn_enabled,
			nm_status=self.nm.wifi_conn_res_last,
			nm_action=self.nm.wifi_conn_res_act,
			nm_ap=self.nm.wifi_conn_res_ap,
			nm_code=nm_code,
			nm_config=nm_config,
			nm_connection=nm_connection,
			events_url=utils.build_url(
				sock.host, sock.port, path=self.url_events ) )
		self._render_headers(request)
		return self.templates.get_template('index.html').render(**env).encode('utf-8')


	def render_POST(self, request):
		'Used only for non-SockJS requests (i.e. no with JS enabled/supported).'
		try:
			ap = self.ap_info_args(request.args)
			if not (ap.get('connect') or ap.get('disconnect')): raise KeyError(ap)
		except KeyError:
			self.log.debug('Invalid form data, args: %s, ap: %s', request.args, ap)
			request.setResponseCode(http.BAD_REQUEST)
			return 'Invalid form data'
		if ap.get('connect'):
			reactor.callLater(0, self.render_nm_connection_result, request, ap)
		elif ap.get('disconnect'):
			reactor.callLater(0, self.render_nm_disconnect, request)
		return server.NOT_DONE_YET

	@defer.inlineCallbacks
	def render_nm_connection_result(self, request, ap):
		try:
			res = yield utils.timeout(
				self.post_nm_wait_max, self.nm.wifi_connect(ap) )
		except:
			self.log.exception('NM connection attempt failed')
			res = False
		if request._disconnected: defer.returnValue(None)
		dst_url = request.prePathURL()
		if res is None:
			self._render_headers(request)
			request.setResponseCode(http.OK)
			request.write( self.templates\
				.get_template('static_nm_redirect.html')\
				.render(url_base=dst_url).encode('utf-8') )
		else:
			request.redirect(dst_url)
		request.finish()

	@defer.inlineCallbacks
	def render_nm_disconnect(self, request):
		try: yield self.nm.wifi_disconnect(action=True)
		except self.nm.NMActionError: pass
		request.redirect(request.prePathURL())
		request.finish()
