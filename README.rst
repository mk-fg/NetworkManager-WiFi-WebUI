NetworkManager-WiFi-WebUI
=========================

**Deprecation Notice:**

  | This project should only be useful for reference, and maybe to port it
  | to something more modern. I'd be surprised if it even still works as-is.

Simple web (http/browser) interface for `NetworkManager
<https://wiki.gnome.org/Projects/NetworkManager>`_ daemon to manage WiFi
connections.

Designed to work with JS enabled or not, dynamically updating through websockets
(though currently xhr-streaming transport is forced, see notes below), http
streaming, long-poll, jsonp or whatever other mechanism SockJS supports, if
possible.

Requirements for this UI are to be fairly lite/minimal, responsive, be able to
enable WiFi, pick AP, connect/disconnect and get basic status/scan updates,
so nothing fancy, can almost be considered to be a proof of concept.

.. contents::
  :backlinks: none


Screenshot
----------

.. figure:: https://raw.githubusercontent.com/mk-fg/NetworkManager-WiFi-WebUI/master/doc/nm-wifi-webui.jpg
   :alt: nm-wifi-webui interface looks

Uses bundled (old v3.1.1) bootstrap icons/css/js, bootstrap-switch,
jquery/modernizr (both can probably be dropped by now), sockjs.
Doesn't make any external api requests, no images or other static.


Installation
------------

Process example (starting as root)::

  # useradd nm-wifi-webui
  # mkdir -m0700 ~nm-wifi-webui
  # chown -R nm-wifi-webui: ~nm-wifi-webui

  # mkdir -p /etc/polkit-1/rules.d/
  # cat >/etc/polkit-1/rules.d/50-nm-wifi-webui.rules <<EOF
  polkit.addRule(function(action, subject) { if ( subject.user == "nm-wifi-webui"
    && action.id.indexOf("org.freedesktop.NetworkManager.") == 0 ) return polkit.Result.YES })
  EOF

  # mkdir -p /etc/polkit-1/localauthority/50-local.d/
  # cat >/etc/polkit-1/localauthority/50-local.d/nm-wifi-webui.pkla <<EOF
  [nm-wifi-webui]
  Identity=unix-user:nm-wifi-webui
  Action=org.freedesktop.NetworkManager.*
  ResultAny=yes
  EOF

  # su - nm-wifi-webui

  % pip2 install --user twisted txsockjs jinja2 txdbus bencode

  % git clone --depth=1 https://github.com/mk-fg/NetworkManager-WiFi-WebUI
  % cd NetworkManager-WiFi-WebUI
  % ./nm-wifi-webui.py --debug

Note: "polkit-1/localauthority" is only for old polkit <= 0.105 (run ``pkaction
--version``), like ones that debians might still use.

See ``./nm-wifi-webui.py --help`` output for more configuration options.

Make sure that you also have NetworkManager itself installed and running.


Requirements
````````````

* `NetworkManager <https://wiki.gnome.org/Projects/NetworkManager>`_ installed and running.
* Python 2.7
* `Twisted <https://twistedmatrix.com/>`_
* `SockJS-Twisted / txsockjs <https://github.com/DesertBus/sockjs-twisted/>`_
* `Jinja2 <https://github.com/pallets/jinja>`_
* `TxDBus <https://github.com/cocagne/txdbus>`_
* `bencode <https://pypi.python.org/pypi/bencode/>`_


Notes
-----

* Code is old python2, rusty and bitrotten.

* Obviously, being a WebUI, this thing is only accessible through some kind of
  network interface (loopback counts), and at the same time is responsible for
  setting one up, so keep that in mind wrt potential uses.

  Common use-case is to show up in kiosk-mode browser on something like
  Raspberry Pi (until there's net connection), or be accessible over (not
  managed by NM) ethernet link.

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

* Note that gtk3 NM frontend(s) (e.g. default GNOME applet) can be used as a
  webui too with GDK_BACKEND=broadway, see:
  https://developer.gnome.org/gtk3/stable/gtk-broadway.html
