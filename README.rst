NetworkManager-WiFi-WebUI
=========================

Web interface (python2/twisted) for NetworkManager daemon, for managing its WiFi
connections.

Designed to work with JS enabled or not, dynamically updating through
websockets, http long-poll or whatever other mechanism SockJS supports.

Code is from back 2014, so is a bit rusty and bitrotten.

In particular, sockjs/websockets over insecure connection don't seem to work in
FF for me now, which might be triviall to fix though.

|

.. contents::
  :backlinks: none


Installation
------------

Process example::

  useradd nm-wifi-webui
  mkdir -m0700 ~nm-wifi-webui
  chown -R nm-wifi-webui: ~nm-wifi-webui
  su - nm-wifi-webui

  pip2 install --user twisted txsockjs jinja2 txdbus bencode

  git clone NetworkManager-WiFi-WebUI
  cd NetworkManager-WiFi-WebUI
  ./nm-wifi-webui.py --debug

  cat <<EOF >/etc/polkit-1/rules.d/50-nm-wifi-webui.rules
	polkit.addRule(function(action, subject) {
		if ( subject.user == "nm-wifi-webui"
			&& action.id.indexOf("org.freedesktop.NetworkManager.") == 0 ) return polkit.Result.YES })
	EOF

Requirements
````````````

* Python 2.7
* `Twisted <https://twistedmatrix.com/>`_
* `SockJS-Twisted / txsockjs <https://github.com/DesertBus/sockjs-twisted/>`_
* `Jinja2 <https://github.com/pallets/jinja>`_
* `TxDBus <https://github.com/cocagne/txdbus>`_
* `bencode <https://pypi.python.org/pypi/bencode/>`_
