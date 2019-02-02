## `HAProxy` ACME domain validation plugin

[![License](https://img.shields.io/github/license/JoelLinn/haproxy-acme-validation-proxy-plugin.svg?maxAge=2592000)]()

[release]: https://github.com/janeczku/haproxy-acme-validation-plugin/releases

HAProxy plugin implementing [ACME http-01](https://github.com/ietf-wg-acme/acme/) validation for split dns domains isolated to the internet by HAProxy instances. The plugin leverages HAProxy's Lua API to allow HAProxy to forward validation challenges using token/key-auth provisioned by an ACME client on the intranet over http.

## Compatible ACME clients

The plugin is compatible with all ACME clients supporting http-01 challenges.

## Lightweight

Can run in an existing haproxy instance, only one additional lua file, lua-http and lua-sockets are needed.

## Installation instructions

### Prerequesites

You need to be rolling HAProxy version `1.6.0` or later with Lua support enabled.
To check if your HAProxy binary was compiled with Lua support run the following command:

	haproxy -vv

If there is a line similar to this you are good to go:

	Built with Lua version

If your binary doesn't come with Lua bindings, you can download Debian/Ubuntu packages of the latest v1.6 release from the [Debian HAProxy packaging team](http://haproxy.debian.net/).

### Installation

Copy `acme-http01-webroot.lua` to a location accessible by HAProxy.

To activate the plugin you just need to add **three lines** to your `haproxy.cfg`:

In the `global` section insert

	lua-load /etc/haproxy/acme-http01-webroot.lua

to invoke the Lua plugin.

In the `frontend` section serving the domain(s) for which you want to create/renew certificates insert:

	acl url_acme_http01 path_beg /.well-known/acme-challenge/
    http-request use-service lua.acme-http01 if METH_GET url_acme_http01

This will pass ACME http-01 validation requests to the Lua plugin handler.

*Note:* ACME protocol stipulates validation on port 80. If your HTTP frontend listens on a non-standard port, make sure to add a port 80 bind directive.

Finally, soft-restart HAProxy (see below for instructions) to apply the updated configuration.

## Getting certificates

Make sure your desired domain globally (on the internet) resolves to haproxy or a firewall/gateway that forwards port 80 to your haproxy instance.
The system haproxy runs on needs to be configured to use the local dns so it forwards all challenge requests to machines on the intranet and not itself.
