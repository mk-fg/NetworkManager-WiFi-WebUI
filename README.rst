NetworkManager-WiFi-WebUI
=========================

Simple web interface (python2/twisted) for NetworkManager daemon to manage
WiFi connections.

Designed to work with JS enabled or not, dynamically updating through websockets
(though currently xhr-streaming transport is forced, see notes below), http
streaming, long-poll, jsonp or whatever other mechanism SockJS supports, if
possible.

Requirements for this UI are to be fairly lite/minimal, responsive, be able to
enable WiFi, pick AP, connect/disconnect to and get basic status/scan updates,
nothing fancy, can almost be considered to be a proof of concept.

.. figure:: https://raw.githubusercontent.com/mk-fg/NetworkManager-WiFi-WebUI/master/doc/nm-wifi-webui.jpg
   :alt: nm-wifi-webui interface looks

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
  polkit.addRule(function(action, subject) { if ( subject.user == "nm-wifi-webui"
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


Notes
-----

* Obviously, being a WebUI, this thing is only accessible through some kind of
  network interface (loopback counts), and at the same time is responsible for
  setting one up, so keep that in mind wrt potential uses.

  Common use-case is to show up in kiosk-mode browser on something like
  Raspberry Pi (until there's net connection), or be accessible over (not
  managed by NM) ethernet link.

* Code is a bit rusty and bitrotten, fixes are most welcome.

  In particular, sockjs + websockets over insecure connection don't seem to work
  in modern FF for me (while forcing other transport like xhr-streaming works
  fine), which might be trivial to fix though.

  See also: https://github.com/sockjs/sockjs-client/issues/94

  Also, not using the thing (or NM) myself on a regular basis, so likely not a
  very well-maintained project.

* Doesn't need any extra webserver, as it runs on twisted.

* All communication with NM is done through DBus interface, so any permission
  errors there should be resolved either via ``/etc/dbus-1/system.d/*.conf``
  files or ``/etc/polkit-1/rules.d/*.rules`` files.

  Daemon checks all permissions on start, and will exit immediately if any of
  them aren't unambiguous "yes".

* Daemon registers its own "Secret Agent" and stores auth info in
  ``secrets.bencode`` file alongside main script by default.

  See also --secrets-file option.

* When debugging DBus or websocket stuff, running script with --noise option can
  be useful, as it'd dump all traffic on these, as script is sending/receiving it.
