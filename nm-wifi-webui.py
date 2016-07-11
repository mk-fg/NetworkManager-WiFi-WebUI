#!/usr/bin/env python2
#-*- coding: utf-8 -*-

from __future__ import print_function

from os.path import join, dirname
import os, sys, signal


def watchdog(interval):
	import time
	pid = os.getppid()

	got_reply = dict(pid=True)
	def _reply(sig, frm): got_reply[pid] = sig
	signal.signal(signal.SIGUSR2, _reply)

	while True:
		sleep_to = time.time() + interval
		while True:
			delay = sleep_to - time.time()
			if delay <= 0: break
			try: time.sleep(delay)
			except: return
		if not got_reply:
			os.kill(pid, signal.SIGABRT)
			return
		got_reply.clear()
		try:
			os.kill(pid, 0)
			os.kill(pid, signal.SIGUSR2)
		except OSError: return

def watchdog_reply_setup(pid):
	from twisted.internet import reactor
	def _reply(sig, frm):
		reactor.callFromThread(reactor.callLater, 0, os.kill, pid, signal.SIGUSR2)
	signal.signal(signal.SIGUSR2, _reply)


def main(argv=None):
	import argparse
	parser = argparse.ArgumentParser(
		description='Discoverable network manager WebUI.')

	parser.add_argument('-p', '--httpd-port',
		metavar='port', type=int, default=8080,
		help='Port to bind WebUI to (default: %(default)s).')
	parser.add_argument('--httpd-static',
		metavar='path', default=join(dirname(__file__), 'static'),
		help='Path to static web assets (default: %(default)s).')
	parser.add_argument('--httpd-templates',
		metavar='path', default=join(dirname(__file__), 'templates'),
		help='Path to templates (default: %(default)s).')

	parser.add_argument('--secrets-file',
		metavar='path', default=join(dirname(__file__), 'secrets.bencode'),
		help='Path to file were all secrets will be stored (default: %(default)s).')

	parser.add_argument('-w', '--watchdog-ping-interval',
		metavar='seconds', type=float, default=10,
		help='Interval between checks if main process is responsive (default: %(default)s).')

	# XXX: add manhole
	parser.add_argument('-l', '--only-logger', metavar='logger_name',
		help='Only display logging stream from specified'
			' logger name (example: nm.core) and errors from twisted logger.')
	parser.add_argument('--debug-memleaks', action='store_true',
		help='Import guppy and enable its manhole to debug memleaks (requires guppy module).')
	parser.add_argument('--debug-deferreds', action='store_true',
		help='Set debug mode for deferred objects to produce long tracebacks for unhandled errbacks.')
	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	parser.add_argument('--noise', action='store_true',
		help='In addition to --debug also dump e.g. all sent/received messages.')
	opts = parser.parse_args(argv or sys.argv[1:])

	# Forked watchdog pid makes sure that twisted reactor isn't stuck (on e.g. blocking call)
	pid = os.fork()
	if not pid:
		watchdog(opts.watchdog_ping_interval)
		sys.exit(0)
	watchdog_reply_setup(pid)

	from nm_wifi_webui.webui import WebUI
	from nm_wifi_webui.nm import NMInterface
	from nm_wifi_webui import utils

	from twisted.internet import reactor, defer
	from twisted.web import resource, server
	from twisted.application import strports, service
	from twisted.python.filepath import FilePath

	import logging

	log = dict()
	if opts.only_logger: log['one_logger'] = opts.only_logger
	utils.init_logging(debug=opts.debug, noise=opts.noise, **log)
	log = logging.getLogger('interface.core')

	if opts.debug_memleaks:
		import guppy
		from guppy.heapy import Remote
		Remote.on()
	if opts.debug_deferreds: defer.Deferred.debug = True

	app = service.MultiService()
	webui = WebUI(static_path=opts.httpd_static, templates_path=opts.httpd_templates)
	webui.putChild('', webui)

	site = server.Site(webui)
	site.noisy = False
	site.displayTracebacks = False
	strports.service('tcp:{}'.format(opts.httpd_port), site).setServiceParent(app)

	nm = NMInterface(opts.secrets_file, webui)
	nm.setServiceParent(app)

	app.startService()
	reactor.addSystemEventTrigger('before', 'shutdown', app.stopService)

	log.debug('Starting...')
	reactor.run()
	log.debug('Finished (exit code: %s)', utils.exit_code)

	return utils.exit_code

if __name__ == '__main__': sys.exit(main())
