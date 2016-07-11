#-*- coding: utf-8 -*-

from __future__ import print_function

from twisted.python.filepath import FilePath

import itertools as it, operator as op, functools as ft
from tempfile import NamedTemporaryFile
import os, sys

import bencode
bencode.encode_func[type(None)] = lambda x,r: r.append('n')
bencode.decode_func['n'] = lambda x,f: (None, f+1)


class SecretStorage(object):

	def __init__(self, path):
		if not isinstance(path, FilePath): path = FilePath(path)
		self.path, self.cache, self.cache_src = path, dict(), None
		self.load()

	def load(self):
		if self.path.exists():
			with self.path.open() as src:
				self.cache_src = src.read()
				self.cache = bencode.bdecode(self.cache_src)

	def dump(self):
		cache_dst = bencode.bencode(self.cache)
		if self.cache_src == cache_dst: return # no changes
		tmp_path = self.path.temporarySibling()
		try:
			with tmp_path.open('w') as tmp:
				os.fchmod(tmp.fileno(), 0600)
				tmp.write(cache_dst)
				tmp.flush()
				os.rename(tmp_path.path, self.path.path)
		finally:
			try: tmp_path.remove()
			except (OSError, IOError): pass
		self.cache_src = cache_dst

	def get(self, uuid, key=None):
		val = self.cache.get(uuid)
		if val and key is not None: val = val.get(key)
		return val

	def set(self, uuid, secret, *keys, **keymap):
		assert isinstance(secret, dict), secret
		if uuid not in self.cache: self.cache[uuid] = dict()
		if keymap: keys = list(keys) + keymap.items()
		if keys:
			for k in keys:
				k1, k2 = (k, k) if not isinstance(k, tuple) else k
				if k2 in secret: self.cache[uuid][k1] = secret[k2]
		else:
			self.cache[uuid].update(secret)
		self.dump()

	def update(self, uuid, **data):
		if uuid not in self.cache: self.cache[uuid] = dict()
		self.cache[uuid].update(data)
		self.dump()

	def remove(self, uuid, *keys):
		for k in keys: del self.cache[uuid][k]
		self.dump()

	def unset(self, uuid, _obj=object()):
		if self.cache.pop(uuid, _obj) is _obj: return
		self.dump()
