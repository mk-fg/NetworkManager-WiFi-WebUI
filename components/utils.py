#-*- coding: utf-8 -*-

from __future__ import print_function

from twisted.internet import reactor, defer, error
from twisted.python import log as twisted_log
from twisted.python.filepath import FilePath

from threading import Event
import os, sys, types, logging

try: from colorlog import ColoredFormatter
except ImportError: ColoredFormatter = None

log = logging.getLogger('utils.core')


exit_code = 0

def stop(code=1):
	global exit_code
	if code is not None: exit_code = code
	try: reactor.stop()
	except error.ReactorNotRunning: pass

def die(tb=False):
	import signal
	if tb:
		import traceback
		print(' -------- abort -------- ', file=sys.stderr)
		traceback.print_stack(file=sys.stderr)
	os.kill(0, signal.SIGABRT)


def force_bytes(bytes_or_unicode, encoding='utf-8', errors='backslashreplace'):
	if isinstance(bytes_or_unicode, bytes): return bytes_or_unicode
	return bytes_or_unicode.encode(encoding, errors)

def force_unicode(bytes_or_unicode, encoding='utf-8', errors='replace'):
	if isinstance(bytes_or_unicode, unicode): return bytes_or_unicode
	return bytes_or_unicode.decode(encoding, errors)

def to_bytes(obj, **conv_kws):
	if not isinstance(obj, types.StringTypes): obj = bytes(obj)
	return force_bytes(obj)


if hasattr(twisted_log, 'NewSTDLibLogObserver'):
	SmartPythonLogObserver = twisted_log.PythonLoggingObserver
else: # hack for older twisted
	class SmartPythonLogObserver(twisted_log.PythonLoggingObserver):
		'''PythonLoggingObserver that passes all the attributes from twisted
			eventDict to python logging subsystem, prefixing each key with "ev_".'''
		def emit(self, eventDict):
			if 'logLevel' in eventDict: level = eventDict['logLevel']
			elif eventDict['isError']: level = logging.ERROR
			else: level = logging.INFO
			text = twisted_log.textFromEventDict(eventDict)
			if text is None: return
			extra = dict(('ev_{}'.format(k), v) for k,v in eventDict.viewitems())
			extra['MESSAGE_ID'] = twisted_msg_id
			self.logger.log(level, text, extra=extra)

def init_logging( handler=None, debug=False, noise=False,
		one_logger=None, twisted_logger='twisted', _done=Event() ):
	assert not _done.is_set(), 'Should only be called once'

	if isinstance(twisted_logger, types.StringTypes):
		twisted_logger = logging.getLogger(twisted_logger)

	noise_level = logging.NOISE = max(1, logging.DEBUG - 5)
	logging.addLevelName(logging.NOISE, 'NOISE')
	def log_noise(self, msg, *args, **kwargs):
		if self.isEnabledFor(noise_level):
			self._log(noise_level, msg, args, **kwargs)
	logging.Logger.noise = log_noise

	logging.root.setLevel(0)
	twisted_log.defaultObserver.stop()

	formatter = logging.Formatter
	if handler is None:
		stream = sys.stderr
		handler = logging.StreamHandler(stream)
		if ColoredFormatter and getattr(stream, 'isatty', lambda: False)():
			def formatter(fmt, *args, **kws):
				assert 'log_colors' not in kws, kws
				kws['log_colors'] = dict( NOISE='white', DEBUG='white',
					INFO='green', WARNING='yellow', ERROR='bold_red', CRITICAL='bold_red' )
				return ColoredFormatter('%(log_color)s'+fmt, *args, **kws)

	handler.setFormatter(formatter(
		'%(asctime)s :: %(name)s %(levelname)s :: %(message)s',
		'%Y-%m-%d %H:%M:%S' ))
	if noise: level = logging.NOISE
	elif debug: level = logging.DEBUG
	else: level = logging.WARNING
	handler.setLevel(level)

	if not one_logger:
		logging.root.addHandler(handler)
	else:
		logging.root.addHandler(logging.NullHandler())
		if isinstance(one_logger, types.StringTypes):
			one_logger = logging.getLogger(one_logger)
		one_logger.setLevel(0)
		one_logger.addHandler(handler)
		twisted_logger.setLevel(logging.WARNING)
		twisted_logger.addHandler(handler)

	log_observer = SmartPythonLogObserver(loggerName=twisted_logger.name)
	log_observer.start()
	_done.set()


def build_url(host, port=None, scheme=None, path=''):
	if port is not None:
		port = int(port)
		if scheme is None:
			scheme = 'https' if port in [443, 8443] else 'http'
		if scheme == 'http' and port == 80: port = None
		elif scheme == 'https' and port == 443: port = None
		else: assert port > 0, port
		port = ':{}'.format(port)
	else: scheme, port = 'http', ''
	return '{}://{}{}/{}'.format(scheme, host, port, path)


@defer.inlineCallbacks
def first_result(*deferreds):
	try:
		res, idx = yield defer.DeferredList(
			deferreds, fireOnOneCallback=True, fireOnOneErrback=True )
	except defer.FirstError as err: err.subFailure.raiseException()
	defer.returnValue(res)

def timeout(delay, for_deferred=None, result=None):
	'''Returns deferred that gets callback with specified result (default: None)
		when delay expires or for_deferred fires (if passed, whichever first).'''
	d = defer.Deferred(canceller=lambda d: timer.cancel())
	timer = reactor.callLater(delay, d.callback, result)
	if for_deferred: return first_result(d, for_deferred)
	return d


@defer.inlineCallbacks
def log_errors(d):
	try: yield d
	except Exception as e:
		log.exception('Unhandled error: <%s> %s', type(e), e)
		raise
