NetworkManager-WiFi-WebUI
=========================

Simple web interface (python2/twisted) for NetworkManager daemon to manage
WiFi connections.

Designed to work with JS enabled or not, dynamically updating through
websockets, http long-poll or whatever other mechanism SockJS supports,
if possible.

Only requirement here is to be fairly lite/minimal, responsive, be able to
enable WiFi, pick AP to connect to and see status/scan updates, nothing fancy.

.. figure:: https://raw.githubusercontent.com/mk-fg/NetworkManager-WiFi-WebUI/master/doc/nm-wifi-webui.jpg
   :alt: nm-wifi-webui interface looks

Code is from back 2014, so is a bit rusty and bitrotten, fixes are most welcome.

In particular, sockjs/websockets over insecure connection don't seem to work in
modern FF for me, which might be trivial to fix though.

|

.. contents::
  :backlinks: none


Installation
------------

Process example::

  # useradd nm-wifi-webui
  # mkdir -m0700 ~nm-wifi-webui
  # chown -R nm-wifi-webui: ~nm-wifi-webui

  # cat <<EOF >/etc/polkit-1/rules.d/50-nm-wifi-webui.rules
  polkit.addRule(function(action, subject) {
    if ( subject.user == "nm-wifi-webui"
      && action.id.indexOf("org.freedesktop.NetworkManager.") == 0 ) return polkit.Result.YES })
  EOF

  # su - nm-wifi-webui

  % pip2 install --user twisted txsockjs jinja2 txdbus bencode

  % git clone NetworkManager-WiFi-WebUI
  % cd NetworkManager-WiFi-WebUI
  % ./nm-wifi-webui.py --debug

See ``./nm-wifi-webui.py --help`` output for more configuration options.

Requirements
````````````

* Python 2.7
* `Twisted <https://twistedmatrix.com/>`_
* `SockJS-Twisted / txsockjs <https://github.com/DesertBus/sockjs-twisted/>`_
* `Jinja2 <https://github.com/pallets/jinja>`_
* `TxDBus <https://github.com/cocagne/txdbus>`_
* `bencode <https://pypi.python.org/pypi/bencode/>`_
