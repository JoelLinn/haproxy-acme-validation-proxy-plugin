-- ACME http-01 domain validation plugin for Haproxy 1.6+
-- copyright (C) 2015 Jan Broer
--
-- usage:
--
-- 1) copy acme-webroot.lua in your haproxy config dir
--
-- 2) Invoke the plugin by adding in the 'global' section of haproxy.cfg:
--
--    lua-load /etc/haproxy/acme-webroot.lua
--
-- 3) insert these two lines in every http frontend that is
--    serving domains for which you want to create certificates:
--
--    acl url_acme_http01 path_beg /.well-known/acme-challenge/
--    http-request use-service lua.acme-http01 if METH_GET url_acme_http01
--
-- 4) reload haproxy
--
-- 5) create a certificate:
--
-- ./letsencrypt-auto certonly --text --webroot --webroot-path /var/tmp -d blah.example.com --renew-by-default --agree-tos --email my@email.com
--

acme = {}
acme.version = "0.1.3"

-- A more recent version 3 of Lua-cURL is required for the API used
cURL = require("cURL")

--
-- Configuration
--
-- When the acme clients use redirects to serve the challenges, you must set enable_redirects to true

acme.conf = {
	["enable_redirects"] = (os.getenv("ACME_HTTP01_ENABLE_REDIRECTS") == "1" or string.lower(os.getenv("ACME_HTTP01_ENABLE_REDIRECTS")) == "true")
}

--
-- Startup
--
acme.startup = function()
	core.Info("[acme] http-01 plugin v" .. acme.version);
end

--
-- ACME http-01 validation endpoint
--
acme.http01 = function(applet)
	local response = ""
	local reqPath = applet.path
	local src = applet.sf:src()
	local token = reqPath:match( ".+/(.*)$" )
	local host = applet.headers.host

	if token then
		token = sanitizeToken(token)
	end

	if (host and host[0]) then
		host = sanitizeHost(host[0])
	else
		host = nil
	end

	if (token == nil or token == '' or host == nil or host == '') then
		response = "bad request\n"
		applet:set_status(400)
		core.Warning("[acme] malformed request (client-ip: " .. tostring(src) .. ")")
	else
		auth = getKeyAuth(host, token)
		if (auth and auth:len() >= 1) then
			response = auth .. "\n"
			applet:set_status(200)
			core.Info("[acme] served http-01 token: " .. token .. " for host " .. host .. " (client-ip: " .. tostring(src) .. ")")
		else
			response = "resource not found\n"
			applet:set_status(404)
			core.Warning("[acme] http-01 token not found: " .. token .. " for host " .. host .. " (client-ip: " .. tostring(src) .. ")")
		end
	end

	applet:add_header("Server", "haproxy/acme-http01-authenticator")
	applet:add_header("Content-Length", string.len(response))
	applet:add_header("Content-Type", "text/plain")
	applet:start_response()
	applet:send(response)
end

--
-- strip chars that are not in the URL-safe Base64 alphabet
-- see https://github.com/letsencrypt/acme-spec/blob/master/draft-barnes-acme.md
--
function sanitizeToken(token)
	_strip="[^%a%d%+%-%_=]"
	token = token:gsub(_strip,'')
	return token
end

function sanitizeHost(host)
	_keep="[%d%a][%d%a_%-%.]*[%d%a]"
	host = host:match(_keep)
	return host
end

--
-- get key auth from token file
--
function getKeyAuth(host, token)
	local url = "http://"..host.."/.well-known/acme-challenge/"..token
	local r = ""
	c = cURL.easy{
		url            = url,
		ssl_verifypeer = false,
		ssl_verifyhost = false,
		followlocation = acme.conf.enable_redirects,
		writefunction  = function(str)
		  r = r..str
		  return string.len(r) <= 1024
		end
	}
	function curlperform()
		c:perform()
	end
	function curlerror(err)
		core.Info("[acme] Curl error: "..tostring(err))
	end
	if not xpcall(curlperform, curlerror) then
		c:close()
		return nil
	end
	local s = c:getinfo(cURL.INFO_RESPONSE_CODE)
	c:close()

	if s == 200 then
		return r:match(token:gsub("-","%%-").."%.[%d%a_%-]+")
	elseif (s == 301 or s == 302) then
		core.Info("[acme] http-01 token returns http redirect " .. tostring(c) .. ", but they are disabled.")
		return nil
	else
		core.Info("[acme] http-01 token returns http code " .. tostring(c) .. ".")
		return nil
	end
end

core.register_init(acme.startup)
core.register_service("acme-http01", "http", acme.http01)
