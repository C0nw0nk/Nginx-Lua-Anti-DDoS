
--[[
Introduction and details :

Copyright Conor McKnight

https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS

Information :
My name is Conor McKnight I am a developer of Lua, PHP, HTML, Javascript, MySQL, Visual Basics and various other languages over the years.
This script was my soloution to check web traffic comming into webservers to authenticate that the inbound traffic is a legitimate browser and request,
It was to help the main internet structure aswell as every form of webserver that sends traffic by HTTP(S) protect themselves from the DoS / DDoS (Distributed Denial of Service) antics of the internet.

If you have any bugs issues or problems just post a Issue request. https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/issues

If you fork or make any changes to improve this or fix problems please do make a pull request for the community who also use this. https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/pulls


Disclaimer :
I am not responsible for what you do with this script nor liable.

Contact : (You can also contact me via github)
https://www.facebook.com/C0nw0nk

]]


--[[
Configuration :
]]

--[[
localize all standard Lua and Spring API functions I use for better performance.
]]
local os = os
local string = string
local math = math
local table = table
local tonumber = tonumber
local tostring = tostring
local next = next
--[[
End localization
]]

--[[
Shared memory cache

If you use this make sure you add this to your nginx configuration

http { #inside http block
     lua_shared_dict antiddos 10m; #Anti-DDoS shared memory zone
}

]]
--local shared_memory = ngx.shared.antiddos --What ever memory space your server has set / defined for this to use

--[[
This is a password that encrypts our puzzle and cookies unique to your sites and servers you should change this from the default.
]]
local secret = " enigma" --Signature secret key --CHANGE ME FROM DEFAULT!

--[[
Unique id to identify each individual user and machine trying to access your website IP address works well.

ngx.var.http_cf_connecting_ip --If you proxy your traffic through cloudflare use this
ngx.var.http_x_forwarded_for --If your traffic is proxied through another server / service.
ngx.var.remote_addr --Users IP address
ngx.var.binary_remote_addr --Users IP address in binary
ngx.var.http_user_agent --use this to protect Tor servers from DDoS

You can combine multiple if you like. You can do so like this.
local remote_addr = ngx.var.remote_addr .. ngx.var.http_user_agent

remote_addr = "tor" this will mean this script will be functioning for tor users only
remote_addr = "auto" the script will automatically get the clients IP this is the default it is the smartest and most compatible method with every service proxy etc
]]
local remote_addr = "auto" --Default Automatically get the Clients IP address

--[[
How long when a users request is authenticated will they be allowed to browse and access the site until they will see the auth page again.

The time is expressed in seconds.
None : 0 (This would result in every page and request showing the auth before granting access) --DO NOT SET AS 0 I recommend nothing less than 30 seconds.
One minute: 60
One hour: 3600
One day: 86400
One week: 604800
One month: 2628000
One year: 31536000
Ten years: 315360000
]]
local expire_time = 86400 --One day

--[[
The type of javascript based pingback authentication method to use if it should be GET or POST or can switch between both making it as dynamic as possible.
1 = GET
2 = POST
3 = DYNAMIC
]]
local javascript_REQUEST_TYPE = 2 --Default 2

--[[
Timer to refresh auth page
Time is in seconds only.
]]
local refresh_auth = 5

--[[
Javascript variable checks
These custom javascript checks are to prevent our authentication javascript puzzle / question being solved by the browser if the browser is a fake ghost browser / bot etc.
Only if the web browser does not trigger any of these or does not match conditions defined will the browser solve the authentication request.
]]
local JavascriptVars_opening = [[
if(!window._phantom || !window.callPhantom){/*phantomjs*/
if(!window.__phantomas){/*phantomas PhantomJS-based web perf metrics + monitoring tool*/
if(!window.Buffer){/*nodejs*/
if(!window.emit){/*couchjs*/
if(!window.spawn){/*rhino*/
if(!window.webdriver){/*selenium*/
if(!window.domAutomation || !window.domAutomationController){/*chromium based automation driver*/
if(!window.document.documentElement.getAttribute("webdriver")){
/*if(navigator.userAgent){*/
if(!/bot|curl|kodi|xbmc|wget|urllib|python|winhttp|httrack|alexa|ia_archiver|facebook|twitter|linkedin|pingdom/i.test(navigator.userAgent)){
/*if(navigator.cookieEnabled){*/
/*if(document.cookie.match(/^(?:.*;)?\s*[0-9a-f]{32}\s*=\s*([^;]+)(?:.*)?$/)){*//*HttpOnly Cookie flags prevent this*/
]]

--[[
Javascript variable blacklist
]]
local JavascriptVars_closing = [[
/*}*/
/*}*/
}
/*}*/
}
}
}
}
}
}
}
}
]]

--[[
Javascript Puzzle for web browser to solve do not touch this unless you understand Javascript, HTML and Lua
]]
--Simple static Javascript puzzle where every request all year round the question and answer would be the same pretty predictable for bots.
--local JavascriptPuzzleVars = [[22 + 22]] --44
--local JavascriptPuzzleVars_answer = "44" --if this does not equal the equation above you will find access to your site will be blocked make sure you can do maths!?

--Make our Javascript puzzle a little bit more dynamic than the static equation above it will change every 24 hours :) I made this because the static one is pretty poor security compared to this but this can be improved allot though.
--TODO: IMPROVE THIS!
local JavascriptPuzzleVars = [[parseInt("]] .. os.date("%Y%m%d",os.time()-24*60*60) .. [[", 10) + parseInt("]] .. os.date("%d%m%Y",os.time()-24*60*60) ..[[", 10)]] --Javascript output of our two random numbers
local JavascriptPuzzleVars_answer = os.date("%Y%m%d",os.time()-24*60*60) + os.date("%d%m%Y",os.time()-24*60*60) --lua output of our two random numbers
local JavascriptPuzzleVars_answer = math.floor(JavascriptPuzzleVars_answer+0.5) --fix bug removing the 0. decimal on the end of the figure
local JavascriptPuzzleVars_answer = tostring(JavascriptPuzzleVars_answer) --convert the numeric output to a string

--[[
X-Auth-Header to be static or Dynamic setting this as dynamic is the best form of security
1 = Static
2 = Dynamic
]]
local x_auth_header = 2 --Default 2
local x_auth_header_name = "x-auth-answer" --the header our server will expect the client to send us with the javascript answer this will change if you set the config as dynamic

--[[
Cookie Anti-DDos names
]]
local challenge = "__uip" --this is the first main unique identification of our cookie name
local cookie_name_start_date = challenge.."_start_date" --our cookie start date name of our firewall
local cookie_name_end_date = challenge.."_end_date" --our cookie end date name of our firewall
local cookie_name_encrypted_start_and_end_date = challenge.."_combination" --our cookie challenge unique id name

--[[
Anti-DDoS Cookies to be Encrypted for better security
1 = Cookie names will be plain text above
2 = Encrypted cookie names unique to each individual client/user
]]
local encrypt_anti_ddos_cookies = 2 --Default 2

--[[
Encrypt/Obfuscate Javascript output to prevent content scrappers and bots decrypting it to try and bypass the browser auth checks. Wouldn't want to make life to easy for them now would I.
0 = Random Encryption Best form of security and default
1 = No encryption / Obfuscation
2 = Base64 Data URI only
3 = Hex encryption
4 = Base64 Javascript Encryption
5 = Conor Mcknight's Javascript Scrambler (Obfuscate Javascript by putting it into vars and shuffling them like a deck of cards)
]]
local encrypt_javascript_output = 0

--[[
IP Address Whitelist
Any IP Addresses specified here will be whitelisted to grant direct access to your site bypassing our firewall checks
you can specify IP's like search engine crawler ip addresses here most search engines are smart enough they do not need to be specified,
Major search engines can execute javascript such as Google, Yandex, Bing, Baidu and such so they can solve the auth page puzzle and index your site same as how companies like Cloudflare, Succuri, BitMitigate etc work and your site is still indexed.
Supports IPv4 and IPv6 addresses aswell as subnet ranges
To find all IP ranges of an ASN use : https://www.enjen.net/asn-blocklist/index.php?asn=16509&type=iplist
]]
local ip_whitelist_remote_addr = "auto" --Automatically get the Clients IP address
local ip_whitelist = {
--"127.0.0.1", --localhost
--"192.168.0.1", --localhost
}

--[[
IP Address Blacklist
To block access to any abusive IP's that you do not want to ever access your website
Supports IPv4 and IPv6 addresses aswell as subnet ranges
To find all IP ranges of an ASN use : https://www.enjen.net/asn-blocklist/index.php?asn=16276&type=iplist
For the worst Botnet ASN IP's see here : https://www.spamhaus.org/statistics/botnet-asn/ You can add their IP addresses. https://www.abuseat.org/public/asninfections.html
]]
local ip_blacklist_remote_addr = "auto" --Automatically get the Clients IP address
local ip_blacklist = {
--"127.0.0.1/30", --localhost
--"192.168.0.1", --localhost
--ASN AS16276 OVH IP ranges Block all OVH Servers
"107.189.64.0/18","91.90.92.0/24","198.245.48.0/20","185.243.16.0/24","217.182.0.0/16","51.79.128.0/17","103.5.12.0/22","198.27.64.0/18","46.105.200.0/24","51.79.0.0/17","2607:5300::/32","144.217.0.0/16","46.244.32.0/20","46.105.201.0/24","46.105.198.0/24","54.39.0.0/16","46.105.203.0/24","51.81.128.0/17","46.105.0.0/16","51.178.0.0/16","167.114.128.0/18","91.90.88.0/24","8.7.244.0/24","139.99.128.0/17","144.2.32.0/19","51.38.0.0/16","91.90.94.0/24","8.33.128.0/21","8.21.41.0/24","216.32.194.0/24","51.89.0.0/16","5.196.0.0/16","195.110.30.0/23","51.195.0.0/16","2001:41d0::/32","91.90.93.0/24","8.29.224.0/24","167.114.192.0/19","8.24.8.0/21","91.90.90.0/24","167.114.0.0/17","91.121.0.0/16","51.91.0.0/16","139.99.0.0/17","178.32.0.0/15","8.26.94.0/24","51.77.0.0/16","91.90.89.0/24","185.228.97.0/24","151.80.0.0/16","213.251.128.0/18","149.56.0.0/16","37.59.0.0/16","213.186.32.0/19","2402:1f00::/32","193.70.0.0/17","142.44.128.0/17","51.161.0.0/17","54.38.0.0/16","185.228.98.0/24","91.90.88.0/21","216.32.220.0/24","92.222.0.0/16","147.135.128.0/17","142.4.192.0/19","5.135.0.0/16","192.95.0.0/18","46.105.202.0/24","185.12.32.0/23","145.239.0.0/16","213.32.0.0/17","37.187.0.0/16","37.60.48.0/21","198.100.144.0/20","149.202.0.0/16","94.23.0.0/16","167.114.224.0/19","193.109.63.0/24","51.254.0.0/15","91.90.91.0/24","216.32.213.0/24","216.32.218.0/24","8.33.96.0/21","5.39.0.0/17","185.228.96.0/24","164.132.0.0/16","158.69.0.0/16","46.105.199.0/24","8.30.208.0/21","54.37.0.0/16","46.105.204.0/24","2402:1f00:8100::/40","87.98.128.0/17","51.68.0.0/16","37.60.56.0/21","8.20.110.0/24","51.83.0.0/16","185.45.160.0/22","216.32.192.0/24","198.50.128.0/17","205.218.49.0/24","216.32.216.0/24","51.75.0.0/16","195.246.232.0/23","91.90.95.0/24","51.81.0.0/17","2402:1f00:8000::/40","23.92.224.0/19","192.240.152.0/21","91.134.0.0/16","92.246.224.0/19","176.31.0.0/16","79.137.0.0/17","193.104.19.0/24","137.74.0.0/16","192.99.0.0/16","198.27.92.0/24","147.135.0.0/17","8.33.136.0/24","2604:2dc0::/32","8.33.137.0/24","188.165.0.0/16","66.70.128.0/17","8.18.172.0/24","185.228.99.0/24","54.36.0.0/16","8.18.128.0/24",
--ASN AS12876 ONLINE S.A.S. IP ranges
"62.4.0.0/19","151.115.0.0/18","51.15.0.0/17","163.172.208.0/20","212.129.0.0/18","2001:bc8::/32","212.83.160.0/19","212.47.224.0/19","2001:bc8:1c00::/38","51.158.128.0/17","163.172.0.0/16","212.83.128.0/19","51.158.0.0/15","195.154.0.0/16","51.15.0.0/16","62.210.0.0/16",
}

--[[
Allow or block all Tor users
1 = Allow
2 = block
]]
local tor = 1 --Allow Tor Users

--[[
Unique ID to identify each individual Tor user who connects to the website
Using their User-Agent as a static variable to latch onto works well.
ngx.var.http_user_agent --Default
]]
local tor_remote_addr = ngx.var.http_user_agent

--[[
X-Tor-Header to be static or Dynamic setting this as dynamic is the best form of security
1 = Static
2 = Dynamic
]]
local x_tor_header = 2 --Default 2
local x_tor_header_name = "x-tor" --tor header name
local x_tor_header_name_allowed = "true" --tor header value when we want to allow access
local x_tor_header_name_blocked = "blocked" --tor header value when we want to block access

--[[
Tor Cookie values
]]
local cookie_tor = challenge.."_tor" --our tor cookie
local cookie_tor_value_allow = "allow" --the value of the cookie when we allow access
local cookie_tor_value_block = "deny" --the value of the cookie when we block access

--[[
TODO:
Google ReCaptcha
]]

--[[
Charset output of HTML page and scripts
]]
local default_charset = "utf-8"

--[[
Enable/disable script this feature allows you to turn on or off this script so you can leave this file in your nginx configuration permamently.

This way you don't have to remove access_by_lua_file anti_ddos_challenge.lua; to stop protecting your websites :) you can set up your nginx config and use this feature to enable or disable protection

1 = enabled (Enabled Anti-DDoS authentication on all sites and paths)
2 = disabled (Won't show anywhere)
3 = custom (Will enable script on sites / URL paths and disable it on those specified)
]]
local master_switch = 1 --enabled by default

--[[
This feature is if you set "master_switch = 3" what this does is if you host multiple websites / services of one server / machine you can have this script disabled for all those websites / domain names other than those you specifiy.
For example you set master_switch to 3 and specifiy ".onion" then all Tor websites you host on your server will be protected by this script while the rest of the websites you host will not be authenticated. (pretty clever huh)
You can also specify full domain names like "github.com" to protect specific domains you can add as many as you like.

1 = run auth checks
2 = bypass auth checks
]]
local master_switch_custom_hosts = {
	{
		1, --run auth checks
		"localhost/ddos.*", --authenticate Tor websites
	},
	{
		1, --run auth checks
		".onion/.*", --authenticate Tor websites
	},
	{
		1, --run auth checks
		"github.com/.*", --authenticate github
	},
	--[[
	{
		1, --run auth checks
		"localhost",
	}, --authenticate localhost
	]]
	--[[
	{
		1, --run auth checks
		"127.0.0.1",
	}, --authenticate localhost
	]]
	--[[
	{
		1, --run auth checks
		".com",
	}, --authenticate .com domains
	]]
}

--[[
Enable/disable credits It would be nice if you would show these to help the community grow and make the internet safer for everyone
but if not I completely understand hence why I made it a option to remove them for you.

1 = enabled
2 = disabled
]]
local credits = 1 --enabled by default

--[[
Javascript variables generated by the script to be static in length or Dynamic setting this as dynamic is the best form of security

1 = Static
2 = Dynamic
]]
local dynamic_javascript_vars_length = 2 --dynamic default
local dynamic_javascript_vars_length_static = 10 --how many chars in length should static be
local dynamic_javascript_vars_length_start = 1 --for dynamic randomize min value to max this is min value
local dynamic_javascript_vars_length_end = 10 --for dynamic randomize min value to max this is max value

--[[
User-Agent Blacklist
If you want to block access to bad bots / specific user-agents you can use this.
1 = case insensative
2 = case sensative
3 = regex case sensative
4 = regex lower case insensative

I added some examples of bad bots to block access to.
]]
local user_agent_blacklist_var = ngx.var.http_user_agent or ""
local user_agent_blacklist_table = {
	{
		"^$",
		3,
	}, --blocks blank / empty user-agents
	{
		"Kodi",
		1,
	},
	{
		"XBMC",
		1,
	},
	{
		"curl",
		1,
	},
	{
		"winhttp",
		1,
	},
	{
		"HTTrack",
		1,
	},
	{
		"libwww-perl",
		1,
	},
	{
		"python",
		1,
	},
}

--[[
User-Agent Whitelist
If you want to allow access to specific user-agents use this.
1 case insensative
2 case sensative
3 regex case sensative
4 regex lower case insensative

I added some examples of user-agents you could whitelist mostly search engine crawlers.
]]
local user_agent_whitelist_var = ngx.var.http_user_agent or ""
local user_agent_whitelist_table = {
--[[
	{
		"^Mozilla%/5%.0 %(compatible%; Googlebot%/2%.1%; %+http%:%/%/www%.google%.com%/bot%.html%)$",
		2,
	},
	{
		"^Mozilla%/5%.0 %(compatible%; Bingbot%/2%.0%; %+http%:%/%/www%.bing%.com%/bingbot%.htm%)$",
		2,
	},
	{
		"^Mozilla%/5%.0 %(compatible%; Yahoo%! Slurp%; http%:%/%/help%.yahoo%.com%/help%/us%/ysearch%/slurp%)$",
		2,
	},
	{
		"^DuckDuckBot%/1%.0%; %(%+http%:%/%/duckduckgo%.com%/duckduckbot%.html%)$",
		2,
	},
	{
		"^Mozilla%/5%.0 %(compatible%; Baiduspider%/2%.0%; %+http%:%/%/www%.baidu%.com%/search%/spider%.html%)$",
		2,
	},
	{
		"^Mozilla%/5%.0 %(compatible%; YandexBot%/3%.0%; %+http%:%/%/yandex%.com%/bots%)$",
		2,
	},
	{
		"^facebot$",
		2,
	},
	{
		"^facebookexternalhit%/1%.0 %(%+http%:%/%/www%.facebook%.com%/externalhit_uatext%.php%)$",
		2,
	},
	{
		"^facebookexternalhit%/1%.1 %(%+http%:%/%/www%.facebook%.com%/externalhit_uatext%.php%)$",
		2,
	},
	{
		"^ia_archiver %(%+http%:%/%/www%.alexa%.com%/site%/help%/webmasters%; crawler%@alexa%.com%)$",
		2,
	},
]]
}

--[[
Authorization Required Box Restricted Access Field
This will NOT use Javascript to authenticate users trying to access your site instead it will use a username and password that can be static or dynamic to grant users access
0 = Disabled
1 = Enabled Browser Sessions (You will see the box again when you restart browser)
2 = Enabled Cookie session (You won't see the box again until the expire_time you set passes)
]]
local authorization = 0

--[[
authorization domains / file paths to protect / restrict access to

1 = Allow showing auth box on matching path(s)
2 = Disallow Showing box matching path(s)

Regex matching file path (.*) will match any

If we should show the client seeing the box what login they can use (Tor websites do this what is why i made this a feature)
0 = Don't display login details
1 = Display login details
]]
local authorization_paths = {
	{
		1, --show auth box on this path
		"localhost/ddos.*", --regex paths i recommend having the domain in there too
		1, --display username/password
	},
	{
		1, --show auth box on this path
		".onion/administrator.*", --regex paths i recommend having the domain in there too
		0, --do NOT display username/password
	},
	{
		1, --show auth box on this path
		".com/admin.*", --regex paths i recommend having the domain in there too
		0, --do NOT display username/password
	},
	--[[
	{ --Show on All sites and paths
		1, --show auth box on this path
		".*", --match all sites/domains paths
		1, --display username/password
	},
	]]
}

--[[
Static or Dynamic username and password for Authorization field
0 = Static
1 = Dynamic
]]
local authorization_dynamic = 0 --Static will use list
local authorization_dynamic_length = 5 --max length of our dynamic generated username and password

--[[
Auth box Message
]]
local authorization_message = "Restricted Area " --Message to be displayed with box
local authorization_username_message = "Your username is :" --Message to show username
local authorization_password_message = "Your password is :" --Message to show password

local authorization_logins = { --static password list
	{
		"userid1", --username
		"pass1", --password
	},
	{
		"userid2", --username
		"pass2", --password
	},
}

--[[
Authorization Box cookie name for sessions
]]
local authorization_cookie = challenge.."_authorization" --our authorization cookie

--[[
WAF Web Application Firewall Filter for Post requests

This feature allows you to intercept incomming client POST data read their POST data and filter out any unwanted code junk etc and block their POST request.

Highly usefull for protecting your web application and backends from attacks zero day exploits and hacking attempts from hackers and bots.
]]
local WAF_POST_Request_table = {
--[[
	{
		"^task$", --match post data in requests with value task
		".*", --matching any
	},
	{
		"^name1$", --regex match
		"^.*y$", --regex or exact match
	},
]]
}

--[[
WAF Web Application Firewall Filter for Headers in requests

You can use this to block exploits in request headers such as malicious cookies clients try to send

Header exploits in requests they might send such as SQL info to inject into sites highly useful for blocking SQLi and many other attack types
]]
local WAF_Header_Request_table = {
--[[
	{
		"^foo$", --match header name
		".*", --matching any value
	},
	{
		"^user-agent$", --header name
		"^.*MJ12Bot.*$", --block a bad bot with user-agent header
	},
	{
		"^cookie$", --Block a Cookie Exploit
		".*SNaPjpCNuf9RYfAfiPQgklMGpOY.*",
	},
]]
}

--[[
WAF Web Application Firewall Filter for query strings in requests

To block exploits in query strings from potential bots and hackers
]]
local WAF_query_string_Request_table = {
	--[[
		PHP easter egg exploit blocking
		[server with expose_php = on]
		.php?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000
		.php?=PHPE9568F34-D428-11d2-A769-00AA001ACF42
		.php?=PHPE9568F35-D428-11d2-A769-00AA001ACF42
		.php?=PHPE9568F36-D428-11d2-A769-00AA001ACF42
	]]
	{
		"^.*$", --match any name
		"^PHP.*$", --matching any value
	},
	{
		"base64%_encode", --regex match name
		"^.*$", --regex or exact match value
	},
	{
		"base64%_decode", --regex match name
		"^.*$", --regex or exact match value
	},
	--[[
		File injection protection
	]]
	{
		"[a-zA-Z0-9_]", --regex match name
		"http%:%/%/", --regex or exact match value
	},
	{
		"[a-zA-Z0-9_]", --regex match name
		"https%:%/%/", --regex or exact match value
	},
	--[[
		SQLi SQL Injections
	]]
	{
		"^.*$",
		"union.*select.*%(",
	},
	{
		"^.*$",
		"concat.*%(",
	},
	{
		"^.*$",
		"union.*all.*select.*",
	},
}

--[[
WAF Web Application Firewall Filter for URL Paths in requests

You can use this to protect server configuration files / paths and sensative material on sites
]]
local WAF_URI_Request_table = {
	{
		"^.*$", --match any website on server
		".*%.htaccess.*", --protect apache server .htaccess files
	},
	{
		"^.*$", --match any website on server
		".*config%.php.*", --protect config files
	},
	{
		"^.*$", --match any website on server
		".*configuration%.php.*", --protect joomla configuration.php files
	},
	--[[
		Disallow direct access to system directories
	]]
	{
		"^.*$", --match any website on server
		".*%/cache.*", --protect /cache folder
	},
}

--[[
Caching Speed and Performance
]]
--[[
Enable Query String Sort

This will treat files with the same query strings as the same file, regardless of the order of the query strings.

Example :
Un-Ordered : .com/index.html?lol=1&char=2
Ordered : .com/index.html?char=2&lol=1

This will result in your backend applications and webserver having better performance because of a Higher Cache HIT Ratio.

0 = Disabled
1 = Enabled
]]
local query_string_sort_table = {
	{
		".*", --regex match any site / path
		1, --enable
	},
	{
		"domain.com/.*", --regex match this domain
		1, --enable
	},
}

--[[
Query String Expected arguments Whitelist only

So this is useful for those who know what URL arguments their sites use and want to whitelist those ONLY so any other arguments provided in the URL never reach the backend or web application and are dropped from the URL.
]]
local query_string_expected_args_only_table = {
--[[
	{
		".*", --any site
		{ --query strings to allow ONLY all others apart from those you list here will be removed from the URL
			"punch",
			"chickens",
		},
	},
	{
		"domain.com", --this domain
		{ --query strings to allow ONLY all others apart from those you list here will be removed from the URL
			"punch",
			"chickens",
		},
	},
]]
	--for all sites specific static files that should never have query strings on the end of the URL (This will improve Caching and performance)
	{
		"%/.*%.js",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.css",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.ico",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.jpg",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.jpeg",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.bmp",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.gif",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.xml",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.txt",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.png",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.swf",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.pdf",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.zip",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.rar",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.7z",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.woff2",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.woff",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.wof",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.eot",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.ttf",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.svg",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.ejs",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.ps",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.pict",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.webp",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.eps",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.pls",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.csv",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.mid",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.doc",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.ppt",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.tif",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.xls",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.otf",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.jar",
		{}, --no args to accept so any provided in the url will be removed.
	},
	--video file formats
	{
		"%/.*%.mp4",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.webm",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.ogg",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.flv",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.mov",
		{}, --no args to accept so any provided in the url will be removed.
	},
	--music file formats
	{
		"%/.*%.mp3",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.m4a",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.aac",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.oga",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.flac",
		{}, --no args to accept so any provided in the url will be removed.
	},
	{
		"%/.*%.wav",
		{}, --no args to accept so any provided in the url will be removed.
	},
}

--[[
Query String Remove arguments

To remove Query strings that bypass the cache Intentionally Facebook and Google is the biggest culprit in this. It is commonly known as Cache Busting.

Traffic to your site from facebook Posts / Shares the URL's will all contain this .com/index.html?fbclid=blah-blah-blah
]]
local query_string_remove_args_table = {
	{
		".*", --all sites
		{ --query strings to remove to improve Cache HIT Ratios and Stop attacks / Cache bypassing and Busting.
			--Cloudflare cache busting query strings (get added to url from captcha and javascript pages very naughty breaking sites caches)
			"__cf_chl_jschl_tk__",
			"__cf_chl_captcha_tk__",
			--facebook cache busting query strings
			"fb_action_ids",
			"fb_action_types",
			"fb_source",
			"fbclid",
			--google cache busting query strings
			"_ga",
			"gclid",
			"utm_source",
			"utm_campaign",
			"utm_medium",
			"utm_expid",
			"utm_term",
			"utm_content",
			--other cache busting query strings
			"cache",
			"caching",
			"age-verified",
			"ao_noptimize",
			"usqp",
			"cn-reloaded",
			"dos",
			"ddos",
			"lol",
			"rnd",
			"random",
			"v", --some urls use ?v1.2 as a file version causing cache busting
			"ver",
			"version",
		},
	},
	{
		"domain.com/.*", --this site
		{ --query strings to remove to improve Cache HIT Ratios and Stop attacks / Cache bypassing and Busting.
			--facebook cache busting query strings
			"fbclid",
		},
	},
}

--[[
To restore original visitor IP addresses at your origin web server this will send a request header to your backend application or proxy containing the clients real IP address
]]
local send_ip_to_backend_custom_headers = {
	{
		".*",
		{
			{"CF-Connecting-IP",}, --CF-Connecting-IP Cloudflare CDN
			{"True-Client-IP",}, --True-Client-IP Akamai CDN
			{"X-Client-IP",} --Amazon Cloudfront
		},
	},
	--[[
	{
		"%/.*%.mp4", --custom url paths
		{
			{"CF-Connecting-IP",}, --CF-Connecting-IP
			{"True-Client-IP",}, --True-Client-IP
		},
	},
	]]
}

--[[
Custom headers

To add custom headers to URLs paths to increase server performance and speed to cache items
and to remove headers for security purposes that could expose software the server is running etc
]]
local custom_headers = {
	{
		".*",
		{ --headers to improve server security for all websites
			{"Server",nil,}, --Server version / identity exposure remove
			{"X-Powered-By",nil,}, --PHP Powered by version / identity exposure remove
			{"X-Content-Encoded-By",nil,}, --Joomla Content encoded by remove
			{"X-Content-Type-Options","nosniff",}, --block MIME-type sniffing
			{"X-XSS-Protection","1; mode=block",}, --block cross-site scripting (XSS) attacks
			{"x-turbo-charged-by",nil,}, --remove x-turbo-charged-by LiteSpeed
		},
	},
	{
		"%/.*%.js",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.css",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.ico",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.jpg",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.jpeg",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.bmp",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.gif",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.xml",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.txt",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.png",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.swf",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.pdf",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.zip",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.rar",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.7z",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.woff2",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.woff",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.wof",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.eot",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.ttf",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.svg",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.ejs",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.ps",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.pict",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.webp",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.eps",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.pls",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.csv",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.mid",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.doc",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.ppt",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.tif",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.xls",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.otf",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.jar",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	--video file formats
	{
		"%/.*%.mp4",
		{
			{"X-Frame-Options","SAMEORIGIN",}, --this file can only be embeded within a iframe on the same domain name stops hotlinking and leeching
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.webm",
		{
			{"X-Frame-Options","SAMEORIGIN",}, --this file can only be embeded within a iframe on the same domain name stops hotlinking and leeching
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.ogg",
		{
			{"X-Frame-Options","SAMEORIGIN",}, --this file can only be embeded within a iframe on the same domain name stops hotlinking and leeching
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.flv",
		{
			{"X-Frame-Options","SAMEORIGIN",}, --this file can only be embeded within a iframe on the same domain name stops hotlinking and leeching
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.mov",
		{
			{"X-Frame-Options","SAMEORIGIN",}, --this file can only be embeded within a iframe on the same domain name stops hotlinking and leeching
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	--music file formats
	{
		"%/.*%.mp3",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.m4a",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.aac",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.oga",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.flac",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
	{
		"%/.*%.wav",
		{
			{"Cache-Control","max-age=315360000, stale-while-revalidate=315360000, stale-if-error=315360000, public, immutable",}, --cache headers to save server bandwidth.
			{"Pragma","public",},
		},
	},
}

--[[
End Configuration


Users with little understanding don't edit beyond this point you will break the script most likely. (You should not need to be warned but now you have been told.) Proceed at own Risk!

Please do not touch anything below here unless you understand the code you read and know the consiquences.

This is where things get very complex. ;)

]]


--[[
Begin Required Functions
]]

--[[
Add to your nginx config http://nginx.org/en/docs/ngx_core_module.html#pcre_jit

pcre_jit on;

The options I enable to make regex cache for performance gains.
j = enable PCRE JIT compilation
o = compile-once mode (similar to Perl's /o modifier), to enable the worker-process-level compiled-regex cache
]]
local ngx_re_options = "jo" --boost regex performance by caching

--[[
Localized vars for use later
]]
local scheme = ngx.var.scheme --scheme is HTTP or HTTPS
local host = ngx.var.host --host is website domain name
local request_uri = ngx.var.request_uri --request uri is full URL link including query strings and arguements
local URL = scheme .. "://" .. host .. request_uri
local user_agent = ngx.var.http_user_agent --user agent of browser
--[[
Localized vars for use later
]]

--[[
Header Modifications
]]
local function header_modification()
	local custom_headers_length = #custom_headers
	for i=1,custom_headers_length do --for each host in our table
		local v = custom_headers[i]
		if string.match(URL, v[1]) then --if our host matches one in the table
			local table_length = #v[2]
			for first=1,table_length do --for each arg in our table
				local value1 = v[2][first][1]
				local value2 = v[2][first][2]
				if value1 ~= nil and value2 ~= nil then
					ngx.header[value1] = value2
				end
				if value2 == nil then
					ngx.header[value1] = nil --remove the header
				end
			end
		end
	end
end
header_modification()
--[[
End Header Modifications
]]

--automatically figure out the IP address of the connecting Client
if remote_addr == "auto" then
	if ngx.var.http_cf_connecting_ip ~= nil then
		remote_addr = ngx.var.http_cf_connecting_ip
	elseif ngx.var.http_x_forwarded_for ~= nil then
		remote_addr = ngx.var.http_x_forwarded_for
	else
		remote_addr = ngx.var.remote_addr
	end
end
if ip_whitelist_remote_addr == "auto" then
	if ngx.var.http_cf_connecting_ip ~= nil then
		ip_whitelist_remote_addr = ngx.var.http_cf_connecting_ip
	elseif ngx.var.http_x_forwarded_for ~= nil then
		ip_whitelist_remote_addr = ngx.var.http_x_forwarded_for
	else
		ip_whitelist_remote_addr = ngx.var.remote_addr
	end
end
if ip_blacklist_remote_addr == "auto" then
	if ngx.var.http_cf_connecting_ip ~= nil then
		ip_blacklist_remote_addr = ngx.var.http_cf_connecting_ip
	elseif ngx.var.http_x_forwarded_for ~= nil then
		ip_blacklist_remote_addr = ngx.var.http_x_forwarded_for
	else
		ip_blacklist_remote_addr = ngx.var.remote_addr
	end
end

--[[
headers to restore original visitor IP addresses at your origin web server
]]
local function header_append_ip()
	local custom_headers_length = #send_ip_to_backend_custom_headers
	for i=1,custom_headers_length do --for each host in our table
		local v = custom_headers[i]
		if string.match(URL, v[1]) then --if our host matches one in the table
			local table_length = #v[2]
			for first=1,table_length do --for each arg in our table
				local value1 = v[2][first][1]
				if value1 ~= nil then
					ngx.req.set_header(value1, remote_addr)
				end
			end
		end
	end
end
header_append_ip()
--[[
End headers to restore original visitor IP addresses at your origin web server
]]

--if host of site is a tor website connecting clients will be tor network clients
if string.match(string.lower(host), ".onion") then
	remote_addr = "tor"
end
if remote_addr == "tor" then
	remote_addr = tor_remote_addr
end

--[[
Query String Remove arguments
]]
local function query_string_remove_args()
	local args = ngx.req.get_uri_args() --grab our query string args and put them into a table
	local modified = nil

	local query_string_remove_args_table_length = #query_string_remove_args_table
	for i=1,query_string_remove_args_table_length do --for each host in our table
		local v = query_string_remove_args_table[i]
		if string.match(URL, v[1]) then --if our host matches one in the table
			local table_length = #v[2]
			for i=1,table_length do --for each arg in our table
				local value = v[2][i]
				args[value] = nil --remove the arguement from the args table
				modified = 1 --set args as modified
			end
			break --break out of the for each loop pointless to keep searching the rest since we matched our host
		end
	end
	if modified == 1 then --need to set our args as our new modified one
		ngx.req.set_uri_args(args) --set the args on the server as our new ordered args check ngx.var.args
	else
		return --carry on script functions
	end
end
query_string_remove_args()
--[[
Query String Remove arguments
]]

--if a table has a value inside of it
local function has_value(table_, val)
	for key, value in next, table_ do
		if value == val then
			return true
		end
	end
	return false
end

--[[
Query String Expected arguments Whitelist only
]]
local function query_string_expected_args_only()
	local args = ngx.req.get_uri_args() --grab our query string args and put them into a table
	local modified = nil

	local query_string_expected_args_only_table_length = #query_string_expected_args_only_table
	for i=1,query_string_expected_args_only_table_length do --for each host in our table
		local v = query_string_expected_args_only_table[i]
		if string.match(URL, v[1]) then --if our host matches one in the table
			for key, value in next, args do
				if has_value(v[2], tostring(key)) == false then
					args[key] = nil --remove the arguement from the args table
					modified = 1 --set args as modified
				end
			end
			break --break out of the for each loop pointless to keep searching the rest since we matched our host
		end
	end
	if modified == 1 then --need to set our args as our new modified one
		ngx.req.set_uri_args(args) --set the args on the server as our new ordered args check ngx.var.args
	else
		return --carry on script functions
	end
end
query_string_expected_args_only()
--[[
Query String Expected arguments Whitelist only
]]

--[[
Query String Sort
]]
local function query_string_sort()
	local allow_site = nil
	local query_string_sort_table_length = #query_string_sort_table
	for i=1,query_string_sort_table_length do --for each host in our table
		local v = query_string_sort_table[i]
		if string.match(URL, v[1]) then --if our host matches one in the table
			if v[2] == 1 then --run query string sort
				allow_site = 2 --run query string sort
			end
			if v[2] == 0 then --bypass
				allow_site = 1 --do not run query string sort
			end
			break --break out of the for each loop pointless to keep searching the rest since we matched our host
		end
	end
	if allow_site == 2 then --sort our query string
		local args = ngx.req.get_uri_args() --grab our query string args and put them into a table
		table.sort(args) --sort our query string args table into order
		ngx.req.set_uri_args(args) --set the args on the server as our new ordered args check ngx.var.args
	else --allow_site was 1
		return --carry on script functions
	end
end
query_string_sort()
--[[
End Query String Sort
]]

--[[
Start IP range function
]]
local function ip_address_in_range(input_ip, client_connecting_ip)
	if string.match(input_ip, "/") then --input ip is a subnet
		--do nothing
	else
		return
	end

	local ip_type = nil
	if string.match(input_ip, "%:") and string.match(client_connecting_ip, "%:") then --if both input and connecting ip are ipv6 addresses
		--ipv6
		ip_type = 1
	elseif string.match(input_ip, "%.") and string.match(client_connecting_ip, "%.") then --if both input and connecting ip are ipv4 addresses
		--ipv4
		ip_type = 2
	else
		return
	end
	if ip_type == nil then
		--input and connecting IP one is ipv4 and one is ipv6
		return
	end

	if ip_type == 1 then --ipv6

		local function explode(string, divide)
			if divide == '' then return false end
			local pos, arr = 0, {}
			local arr_table_length = 1
			--for each divider found
			for st, sp in function() return string.find(string, divide, pos, true) end do
				arr[arr_table_length] = string.sub(string, pos, st - 1 ) --attach chars left of current divider
				arr_table_length=arr_table_length+1
				pos = sp + 1 --jump past current divider
			end
				arr[arr_table_length] = string.sub(string, pos) -- Attach chars right of last divider
				arr_table_length=arr_table_length+1
			return arr
		end

		--[[
		Input IP
		]]
		--validate actual ip
		local a, b, ip, mask = input_ip:find('([%w:]+)/(%d+)')

		--get ip bits
		local ipbits = explode(ip, ':')

		--now to build an expanded ip
		local zeroblock
		local ipbits_length = #ipbits
		for i=1,ipbits_length do
			local k = i
			local v = ipbits[i]
			--length 0? we're at the :: bit
			if v:len() == 0 then
				zeroblock = k

				--length not 0 but not 4, prepend 0's
			elseif v:len() < 4 then
				local padding = 4 - v:len()
				for i = 1, padding do
					ipbits[k] = 0 .. ipbits[k]
				end
			end
		end
		if zeroblock and #ipbits < 8 then
			--remove zeroblock
			ipbits[zeroblock] = '0000'
			local padding = 8 - #ipbits

			for i = 1, padding do
				ipbits[zeroblock] = '0000'
				--ipbits_length=ipbits_length+1
			end
		end
		--[[
		End Input IP
		]]

		--[[
		Client IP
		]]
		--validate actual ip
		local a, b, clientip, mask_client = client_connecting_ip:find('([%w:]+)')

		--get ip bits
		local ipbits_client = explode(clientip, ':')

		--now to build an expanded ip
		local zeroblock_client
		local ipbits_client_length = #ipbits_client
		for i=1,ipbits_client_length do
			local k = i
			local v = ipbits_client[i]
			--length 0? we're at the :: bit
			if v:len() == 0 then
				zeroblock_client = k

				--length not 0 but not 4, prepend 0's
			elseif v:len() < 4 then
				local padding = 4 - v:len()
				for i = 1, padding do
					ipbits_client[k] = 0 .. ipbits_client[k]
				end
			end
		end
		if zeroblock_client and #ipbits_client < 8 then
			--remove zeroblock
			ipbits_client[zeroblock_client] = '0000'
			local padding = 8 - #ipbits_client

			for i = 1, padding do
				ipbits_client[zeroblock_client] = '0000'
				--ipbits_client_length=ipbits_client_length+1
			end
		end
		--[[
		End Client IP
		]]

		local expanded_ip_count = (ipbits[1] or "0000") .. ':' .. (ipbits[2] or "0000") .. ':' .. (ipbits[3] or "0000") .. ':' .. (ipbits[4] or "0000") .. ':' .. (ipbits[5] or "0000") .. ':' .. (ipbits[6] or "0000") .. ':' .. (ipbits[7] or "0000") .. ':' .. (ipbits[8] or "0000")
		expanded_ip_count = ngx.re.gsub(expanded_ip_count, ":", "", ngx_re_options)

		local client_connecting_ip_count = (ipbits_client[1] or "0000") .. ':' .. (ipbits_client[2] or "0000") .. ':' .. (ipbits_client[3] or "0000") .. ':' .. (ipbits_client[4] or "0000") .. ':' .. (ipbits_client[5] or "0000") .. ':' .. (ipbits_client[6] or "0000") .. ':' .. (ipbits_client[7] or "0000") .. ':' .. (ipbits_client[8] or "0000")
		client_connecting_ip_count = ngx.re.gsub(client_connecting_ip_count, ":", "", ngx_re_options)

		--generate wildcard from mask
		local indent = mask / 4

		expanded_ip_count = string.sub(expanded_ip_count, 0, indent)
		client_connecting_ip_count = string.sub(client_connecting_ip_count, 0, indent)

		local client_connecting_ip_expanded = ngx.re.gsub(client_connecting_ip_count, "....", "%1:", ngx_re_options)
		client_connecting_ip_expanded = ngx.re.gsub(client_connecting_ip_count, ":$", "", ngx_re_options)
		local expanded_ip = ngx.re.gsub(expanded_ip_count, "....", "%1:", ngx_re_options)
		expanded_ip = ngx.re.gsub(expanded_ip_count, ":$", "", ngx_re_options)

		local wildcardbits = {}
		local wildcardbits_table_length = 1
		for i = 0, indent - 1 do
			wildcardbits[wildcardbits_table_length] = 'f'
			wildcardbits_table_length=wildcardbits_table_length+1
		end
		for i = 0, 31 - indent do
			wildcardbits[wildcardbits_table_length] = '0'
			wildcardbits_table_length=wildcardbits_table_length+1
		end
		--convert into 8 string array each w/ 4 chars
		local count, index, wildcard = 1, 1, {}
		local wildcardbits_length = #wildcardbits
		for i=1,wildcardbits_length do
			local k = i
			local v = wildcardbits[i]
			if count > 4 then
				count = 1
				index = index + 1
			end
			if not wildcard[index] then wildcard[index] = '' end
			wildcard[index] = wildcard[index] .. v
			count = count + 1
		end

			--loop each letter in each ipbit group
			local topip = {}
			local bottomip = {}
			local ipbits_length = #ipbits
			for i=1,ipbits_length do
				local k = i
				local v = ipbits[i]
				local topbit = ''
				local bottombit = ''
				for i = 1, 4 do
					local wild = wildcard[k]:sub(i, i)
					local norm = v:sub(i, i)
					if wild == 'f' then
						topbit = topbit .. norm
						bottombit = bottombit .. norm
					else
						topbit = topbit .. '0'
						bottombit = bottombit .. 'f'
					end
				end
				topip[k] = topbit
				bottomip[k] = bottombit
			end

		--count ips in mask
		local ipcount = math.pow(2, 128 - mask)

		if expanded_ip == client_connecting_ip_expanded then
			--print("ipv6 is in range")
			return true
		end

		--output
		--[[
		print()
		print('indent' .. indent)
		print('client_ip numeric : ' .. client_connecting_ip_count )
		print('input ip numeric : ' .. expanded_ip_count )
		print('client_ip : ' .. client_connecting_ip_expanded )
		print('input ip : ' .. expanded_ip )
		print()
		print( '###### INFO ######' )
		print( 'IP in: ' .. ip )
		print( '=> Expanded IP: ' .. (ipbits[1] or "0000") .. ':' .. (ipbits[2] or "0000") .. ':' .. (ipbits[3] or "0000") .. ':' .. (ipbits[4] or "0000") .. ':' .. (ipbits[5] or "0000") .. ':' .. (ipbits[6] or "0000") .. ':' .. (ipbits[7] or "0000") .. ':' .. (ipbits[8] or "0000") )
		print( 'Mask in: /' .. mask )
		print( '=> Mask Wildcard: ' .. (wildcard[1] or "0000") .. ':' .. (wildcard[2] or "0000") .. ':' .. (wildcard[3] or "0000") .. ':' .. (wildcard[4] or "0000") .. ':' .. (wildcard[5] or "0000") .. ':' .. (wildcard[6] or "0000") .. ':' .. (wildcard[7] or "0000") .. ':' .. (wildcard[8] or "0000") )
		print( '\n###### BLOCK ######' )
		print( '#IP\'s: ' .. ipcount )
		print( 'Range Start: ' .. (topip[1] or "0000") .. ':' .. (topip[2] or "0000") .. ':' .. (topip[3] or "0000") .. ':' .. (topip[4] or "0000") .. ':' .. (topip[5] or "0000") .. ':' .. (topip[6] or "0000") .. ':' .. (topip[7] or "0000") .. ':' .. (topip[8] or "0000") )
		print( 'Range End: ' .. (bottomip[1] or "ffff") .. ':' .. (bottomip[2] or "ffff") .. ':' .. (bottomip[3] or "ffff") .. ':' .. (bottomip[4] or "ffff") .. ':' .. (bottomip[5] or "ffff") .. ':' .. (bottomip[6] or "ffff") .. ':' .. (bottomip[7] or "ffff") .. ':' .. (bottomip[8] or "ffff") )
		]]

	end

	if ip_type == 2 then --ipv4

		local a, b, ip1, ip2, ip3, ip4, mask = input_ip:find('(%d+).(%d+).(%d+).(%d+)/(%d+)')
		local ip = { tonumber( ip1 ), tonumber( ip2 ), tonumber( ip3 ), tonumber( ip4 ) }
		local a, b, client_ip1, client_ip2, client_ip3, client_ip4 = client_connecting_ip:find('(%d+).(%d+).(%d+).(%d+)')
		local client_ip = { tonumber( client_ip1 ), tonumber( client_ip2 ), tonumber( client_ip3 ), tonumber( client_ip4 ) }

		--list masks => wildcard
		local masks = {
			[1] = { 127, 255, 255, 255 },
			[2] = { 63, 255, 255, 255 },
			[3] = { 31, 255, 255, 255 },
			[4] = { 15, 255, 255, 255 },
			[5] = { 7, 255, 255, 255 },
			[6] = { 3, 255, 255, 255 },
			[7] = { 1, 255, 255, 255 },
			[8] = { 0, 255, 255, 255 },
			[9] = { 0, 127, 255, 255 },
			[10] = { 0, 63, 255, 255 },
			[11] = { 0, 31, 255, 255 },
			[12] = { 0, 15, 255, 255 },
			[13] = { 0, 7, 255, 255 },
			[14] = { 0, 3, 255, 255 },
			[15] = { 0, 1, 255, 255 },
			[16] = { 0, 0, 255, 255 },
			[17] = { 0, 0, 127, 255 },
			[18] = { 0, 0, 63, 255 },
			[19] = { 0, 0, 31, 255 },
			[20] = { 0, 0, 15, 255 },
			[21] = { 0, 0, 7, 255 },
			[22] = { 0, 0, 3, 255 },
			[23] = { 0, 0, 1, 255 },
			[24] = { 0, 0, 0, 255 },
			[25] = { 0, 0, 0, 127 },
			[26] = { 0, 0, 0, 63 },
			[27] = { 0, 0, 0, 31 },
			[28] = { 0, 0, 0, 15 },
			[29] = { 0, 0, 0, 7 },
			[30] = { 0, 0, 0, 3 },
			[31] = { 0, 0, 0, 1 }
		}

		--get wildcard
		local wildcard = masks[tonumber( mask )]

		--number of ips in mask
		local ipcount = math.pow(2, ( 32 - mask ))

		--network IP (route/bottom IP)
		local bottomip = {}
		local ip_length = #ip
		for i=1,ip_length do
			local k = i
			local v = ip[i]
			--wildcard = 0?
			if wildcard[k] == 0 then
				bottomip[k] = v
			elseif wildcard[k] == 255 then
				bottomip[k] = 0
			else
				local mod = v % (wildcard[k] + 1)
				bottomip[k] = v - mod
			end
		end

		--use network ip + wildcard to get top ip
		local topip = {}
		local bottomip_length = #bottomip
		for i=1,bottomip_length do
			local k = i
			local v = bottomip[i]
			topip[k] = v + wildcard[k]
		end

		--is input ip = network ip?
		local isnetworkip = ( ip[1] == bottomip[1] and ip[2] == bottomip[2] and ip[3] == bottomip[3] and ip[4] == bottomip[4] )
		local isbroadcastip = ( ip[1] == topip[1] and ip[2] == topip[2] and ip[3] == topip[3] and ip[4] == topip[4] )

		local ip1 = tostring(ip1)
		local ip2 = tostring(ip2)
		local ip3 = tostring(ip3)
		local ip4 = tostring(ip4)
		local client_ip1 = tostring(client_ip1)
		local client_ip2 = tostring(client_ip2)
		local client_ip3 = tostring(client_ip3)
		local client_ip4 = tostring(client_ip4)
		local in_range_low_end1 = tostring(bottomip[1])
		local in_range_low_end2 = tostring(bottomip[2])
		local in_range_low_end3 = tostring(bottomip[3])
		local in_range_low_end4 = tostring(bottomip[4])
		local in_range_top_end1 = tostring(topip[1])
		local in_range_top_end2 = tostring(topip[2])
		local in_range_top_end3 = tostring(topip[3])
		local in_range_top_end4 = tostring(topip[4])

		if tonumber(mask) == 1 then --127, 255, 255, 255
			if client_ip1 >= in_range_low_end1 --in range low end
			and client_ip1 <= in_range_top_end1 
			and client_ip2 >= in_range_low_end2 --in range low end
			and client_ip2 <= in_range_top_end2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 2 then --63, 255, 255, 255
			if client_ip1 >= in_range_low_end1 --in range low end
			and client_ip1 <= in_range_top_end1 
			and client_ip2 >= in_range_low_end2 --in range low end
			and client_ip2 <= in_range_top_end2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 3 then --31, 255, 255, 255
			if client_ip1 >= in_range_low_end1 --in range low end
			and client_ip1 <= in_range_top_end1 
			and client_ip2 >= in_range_low_end2 --in range low end
			and client_ip2 <= in_range_top_end2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 4 then --15, 255, 255, 255
			if client_ip1 >= in_range_low_end1 --in range low end
			and client_ip1 <= in_range_top_end1 
			and client_ip2 >= in_range_low_end2 --in range low end
			and client_ip2 <= in_range_top_end2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 5 then --7, 255, 255, 255
			if client_ip1 >= in_range_low_end1 --in range low end
			and client_ip1 <= in_range_top_end1 
			and client_ip2 >= in_range_low_end2 --in range low end
			and client_ip2 <= in_range_top_end2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 6 then --3, 255, 255, 255
			if client_ip1 >= in_range_low_end1 --in range low end
			and client_ip1 <= in_range_top_end1 
			and client_ip2 >= in_range_low_end2 --in range low end
			and client_ip2 <= in_range_top_end2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 7 then --1, 255, 255, 255
			if client_ip1 >= in_range_low_end1 --in range low end
			and client_ip1 <= in_range_top_end1 
			and client_ip2 >= in_range_low_end2 --in range low end
			and client_ip2 <= in_range_top_end2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 8 then --0, 255, 255, 255
			if ip1 == client_ip1 
			and client_ip2 >= in_range_low_end2 --in range low end
			and client_ip2 <= in_range_top_end2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 9 then --0, 127, 255, 255
			if ip1 == client_ip1 
			and client_ip2 >= in_range_low_end2 --in range low end
			and client_ip2 <= in_range_top_end2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 10 then --0, 63, 255, 255
			if ip1 == client_ip1 
			and client_ip2 >= in_range_low_end2 --in range low end
			and client_ip2 <= in_range_top_end2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 11 then --0, 31, 255, 255
			if ip1 == client_ip1 
			and client_ip2 >= in_range_low_end2 --in range low end
			and client_ip2 <= in_range_top_end2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 12 then --0, 15, 255, 255
			if ip1 == client_ip1 
			and client_ip2 >= in_range_low_end2 --in range low end
			and client_ip2 <= in_range_top_end2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 13 then --0, 7, 255, 255
			if ip1 == client_ip1 
			and client_ip2 >= in_range_low_end2 --in range low end
			and client_ip2 <= in_range_top_end2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 14 then --0, 3, 255, 255
			if ip1 == client_ip1 
			and client_ip2 >= in_range_low_end2 --in range low end
			and client_ip2 <= in_range_top_end2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 15 then --0, 1, 255, 255
			if ip1 == client_ip1 
			and client_ip2 >= in_range_low_end2 --in range low end
			and client_ip2 <= in_range_top_end2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 16 then --0, 0, 255, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 17 then --0, 0, 127, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 18 then --0, 0, 63, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 19 then --0, 0, 31, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 20 then --0, 0, 15, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 21 then --0, 0, 7, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 22 then --0, 0, 3, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 23 then --0, 0, 1, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 24 then --0, 0, 0, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and ip3 == client_ip3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 25 then --0, 0, 0, 127
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and ip3 == client_ip3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 26 then --0, 0, 0, 63
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and ip3 == client_ip3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 27 then --0, 0, 0, 31
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and ip3 == client_ip3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 28 then --0, 0, 0, 15
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and ip3 == client_ip3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 29 then --0, 0, 0, 7
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and ip3 == client_ip3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 30 then --0, 0, 0, 3
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and ip3 == client_ip3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if tonumber(mask) == 31 then --0, 0, 0, 1
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and ip3 == client_ip3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end

		--output
		--[[
		print()
		print( '###### INFO ######' )
		print( 'IP in: ' .. ip[1] .. '.' .. ip[2] .. '.' .. ip[3] .. '.' .. ip[4]  )
		print( 'Mask in: /' .. mask )
		print( '=> Mask Wildcard: ' .. wildcard[1] .. '.' .. wildcard[2] .. '.' .. wildcard[3] .. '.' .. wildcard[4]  )
		print( '=> in IP is network-ip: ' .. tostring( isnetworkip ) )
		print( '=> in IP is broadcast-ip: ' .. tostring( isbroadcastip ) )
		print( '\n###### BLOCK ######' )
		print( '#IP\'s: ' .. ipcount )
		print( 'Bottom/Network: ' .. bottomip[1] .. '.' .. bottomip[2] .. '.' .. bottomip[3] .. '.' .. bottomip[4] .. '/' .. mask )
		print( 'Top/Broadcast: ' .. topip[1] .. '.' .. topip[2] .. '.' .. topip[3] .. '.' .. topip[4] )
		print( 'Subnet Range: ' .. bottomip[1] .. '.' .. bottomip[2] .. '.' .. bottomip[3] .. '.' .. bottomip[4] .. ' - ' .. topip[1] .. '.' .. topip[2] .. '.' .. topip[3] .. '.' .. topip[4] )
		print( 'Host Range: ' .. bottomip[1] .. '.' .. bottomip[2] .. '.' .. bottomip[3] .. '.' .. bottomip[4] + 1 .. ' - ' .. topip[1] .. '.' .. topip[2] .. '.' .. topip[3] .. '.' .. topip[4] - 1 )
		]]

	end

end
--[[
usage
if ip_address_in_range("255.255.0.0/17", ngx.var.remote_addr) == true then --ipv4
	print("IPv4 in range")
end
if ip_address_in_range("2a02:0c68::/29", ngx.var.remote_addr) == true then --ipv6
	print("IPv6 in range")
end
]]
--[[
End IP range function
]]

--[[WAF Web Application Firewall POST Request arguments filter]]
local function WAF_Post_Requests()
	if next(WAF_POST_Request_table) ~= nil then --Check Post filter table has rules inside it

		ngx.req.read_body() --Grab the request Body
		local read_request_body_args = (ngx.req.get_body_data() or "") --Put the request body arguments into a variable
		local args = (ngx.decode_args(read_request_body_args) or "") --Put the Post args in to a table

		if next(args) ~= nil then --Check Post args table has contents	

			local arguement1 = nil --create empty variable
			local arguement2 = nil --create empty variable

			local WAF_table_length = #WAF_POST_Request_table
			for key, value in next, args do

				for i=1,WAF_table_length do
					arguement1 = nil --reset to nil each loop
					arguement2 = nil --reset to nil each loop
					local value = WAF_POST_Request_table[i] --put table value into variable
					local argument_name = value[1] or "" --get the WAF TABLE argument name or empty
					local argument_value = value[2] or "" --get the WAF TABLE arguement value or empty
					local args_name = tostring(key) or "" --variable to store POST data argument name
					local args_value = tostring(value) or "" --variable to store POST data argument value
					if string.match(args_name, argument_name) then --if the argument name in my table matches the one in the POST request
						arguement1 = 1
					end
					if string.match(args_value, argument_value) then --if the argument value in my table matches the one the POST request
						arguement2 = 1
					end
					if arguement1 and arguement2 then --if what would of been our empty vars have been changed to not empty meaning a WAF match then block the request
						local output = ngx.exit(ngx.HTTP_FORBIDDEN) --deny user access
						return output
					end
				end
			end
		end
	end
end
WAF_Post_Requests()
--[[End WAF Web Application Firewall POST Request arguments filter]]

--[[WAF Web Application Firewall Header Request arguments filter]]
local function WAF_Header_Requests()
	if next(WAF_Header_Request_table) ~= nil then --Check Header filter table has rules inside it

		local argument_request_headers = ngx.req.get_headers() --get our client request headers and put them into a table

		if next(argument_request_headers) ~= nil then --Check Header args table has contents	

			local arguement1 = nil --create empty variable
			local arguement2 = nil --create empty variable

			local WAF_table_length = #WAF_Header_Request_table
			for key, value in next, argument_request_headers do

				for i=1,WAF_table_length do
					arguement1 = nil --reset to nil each loop
					arguement2 = nil --reset to nil each loop
					local value = WAF_Header_Request_table[i] --put table value into variable
					local argument_name = value[1] or "" --get the WAF TABLE argument name or empty
					local argument_value = value[2] or "" --get the WAF TABLE arguement value or empty
					local args_name = tostring(key) or "" --variable to store Header data argument name
					local args_value = tostring(ngx.req.get_headers()[args_name]) or ""
					if string.match(args_name, argument_name) then --if the argument name in my table matches the one in the request
						arguement1 = 1
					end
					if string.match(args_value, argument_value) then --if the argument value in my table matches the one the request
						arguement2 = 1
					end
					if arguement1 and arguement2 then --if what would of been our empty vars have been changed to not empty meaning a WAF match then block the request
						local output = ngx.exit(ngx.HTTP_FORBIDDEN) --deny user access
						return output
					end
				end
			end
		end
	end
end
WAF_Header_Requests()
--[[End WAF Web Application Firewall Header Request arguments filter]]

--[[WAF Web Application Firewall Query String Request arguments filter]]
local function WAF_query_string_Request()
	if next(WAF_query_string_Request_table) ~= nil then --Check query string filter table has rules inside it

		local args = ngx.req.get_uri_args() --grab our query string args and put them into a table

		if next(args) ~= nil then --Check query string args table has contents

			local arguement1 = nil --create empty variable
			local arguement2 = nil --create empty variable

			local WAF_table_length = #WAF_query_string_Request_table
			for key, value in next, args do

				for i=1,WAF_table_length do
					arguement1 = nil --reset to nil each loop
					arguement2 = nil --reset to nil each loop
					local value = WAF_query_string_Request_table[i] --put table value into variable
					local argument_name = value[1] or "" --get the WAF TABLE argument name or empty
					local argument_value = value[2] or "" --get the WAF TABLE arguement value or empty
					local args_name = tostring(key) or "" --variable to store query string data argument name
					local args_value = tostring(ngx.req.get_uri_args()[args_name]) or "" --variable to store query string data argument value
					if string.match(args_name, argument_name) then --if the argument name in my table matches the one in the request
						arguement1 = 1
					end
					if string.match(args_value, argument_value) then --if the argument value in my table matches the one the request
						arguement2 = 1
					end
					if arguement1 and arguement2 then --if what would of been our empty vars have been changed to not empty meaning a WAF match then block the request
						local output = ngx.exit(ngx.HTTP_FORBIDDEN) --deny user access
						return output
					end
				end
			end
		end
	end
end
WAF_query_string_Request()
--[[End WAF Web Application Firewall Query String Request arguments filter]]

--[[WAF Web Application Firewall URI Request arguments filter]]
local function WAF_URI_Request()
	if next(WAF_URI_Request_table) ~= nil then --Check Post filter table has rules inside it

		--[[
		Because ngx.var.uri is a bit stupid I strip the query string of the request uri.
		The reason for this it is subject to normalisation
		Consecutive / characters are replace by a single / 
		and URL encoded characters are decoded 
		but then your back end webserver / application recieve the encoded uri!?
		So to keep the security strong I match the same version your web application would need protecting from (Yes the encoded copy that could contain malicious / exploitable contents)
		]]
		local args = string.gsub(request_uri, "?.*", "") --remove the query string from the uri
		
		local WAF_table_length = #WAF_URI_Request_table
		for i=1,WAF_table_length do --for each host in our table
			local v = WAF_URI_Request_table[i]
			if string.match(URL, v[1]) then --if our host matches one in the table
				if string.match(args, v[2]) then
					local output = ngx.exit(ngx.HTTP_FORBIDDEN) --deny user access
					return output
				end
			end
		end
	end
end
WAF_URI_Request()
--[[End WAF Web Application Firewall URI Request arguments filter]]

--function to check if ip address is whitelisted to bypass our auth
local function check_ip_whitelist(ip_table)
	local ip_table_length = #ip_table
	for i=1,ip_table_length do
		local value = ip_table[i]
		if value == ip_whitelist_remote_addr then --if our ip address matches with one in the whitelist
			local output = ngx.exit(ngx.OK) --Go to content
			return output
		elseif ip_address_in_range(value, ip_whitelist_remote_addr) == true then
			local output = ngx.exit(ngx.OK) --Go to content
			return output
		end
	end

	return --no ip was in the whitelist
end
check_ip_whitelist(ip_whitelist) --run whitelist check function

local function check_ip_blacklist(ip_table)
	local ip_table_length = #ip_table
	for i=1,ip_table_length do
		local value = ip_table[i]
		if value == ip_blacklist_remote_addr then
			local output = ngx.exit(ngx.HTTP_FORBIDDEN) --deny user access
			return output
		elseif ip_address_in_range(value, ip_blacklist_remote_addr) == true then
			local output = ngx.exit(ngx.HTTP_FORBIDDEN) --deny user access
			return output
		end
	end

	return --no ip was in blacklist
end
check_ip_blacklist(ip_blacklist) --run blacklist check function

local function check_user_agent_blacklist(user_agent_table)
	local user_agent_table_length = #user_agent_table
	for i=1,user_agent_table_length do
		local value = user_agent_table[i]
		if value[2] == 1 then --case insensative
			user_agent_blacklist_var = string.lower(user_agent_blacklist_var)
			value[1] = string.lower(value[1])
		end
		if value[2] == 2 then --case sensative
		end
		if value[2] == 3 then --regex case sensative
		end
		if value[2] == 4 then --regex lower case insensative
			user_agent_blacklist_var = string.lower(user_agent_blacklist_var)
		end
		if string.match(user_agent_blacklist_var, value[1])then
			local output = ngx.exit(ngx.HTTP_FORBIDDEN) --deny user access
			return output
		end
	end

	return --no user agent was in blacklist
end
check_user_agent_blacklist(user_agent_blacklist_table) --run user agent blacklist check function

local function check_user_agent_whitelist(user_agent_table)
	local user_agent_table_length = #user_agent_table
	for i=1,user_agent_table_length do
		local value = user_agent_table[i]
		if value[2] == 1 then --case insensative
			user_agent_whitelist_var = string.lower(user_agent_whitelist_var)
			value[1] = string.lower(value[1])
		end
		if value[2] == 2 then --case sensative
		end
		if value[2] == 3 then --regex case sensative
		end
		if value[2] == 4 then --regex lower case insensative
			user_agent_whitelist_var = string.lower(user_agent_whitelist_var)
		end
		if string.match(user_agent_whitelist_var, value[1]) then
			local output = ngx.exit(ngx.OK) --Go to content
			return output
		end
	end

	return --no user agent was in whitelist
end
check_user_agent_whitelist(user_agent_whitelist_table) --run user agent whitelist check function

--to have better randomization upon encryption
math.randomseed(os.time())

--function to encrypt strings with our secret key / password provided
local function calculate_signature(str)
	local output = ngx.encode_base64(ngx.hmac_sha1(secret, str))
	output = ngx.re.gsub(output, "[+]", "-", ngx_re_options) --Replace + with -
	output = ngx.re.gsub(output, "[/]", "_", ngx_re_options) --Replace / with _
	output = ngx.re.gsub(output, "[=]", "", ngx_re_options) --Remove =
	return output
end
--calculate_signature(str)

--generate random strings on the fly
--qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890
local charset = {}
local charset_table_length = 1
for i = 48,  57 do
charset[charset_table_length] = string.char(i)
charset_table_length=charset_table_length+1
end --0-9 numeric
--[[
for i = 65,  90 do
charset[charset_table_length] = string.char(i)
charset_table_length=charset_table_length+1
end --A-Z uppercase
]]
--[[
for i = 97, 122 do
charset[charset_table_length] = string.char(i)
charset_table_length=charset_table_length+1
end --a-z lowercase
]]
charset[charset_table_length] = string.char(95) --insert number 95 underscore
charset_table_length=charset_table_length+1
local stringrandom_table = {} --create table to store our generated vars to avoid duplicates
local stringrandom_table_new_length = 1
local function stringrandom(length)
	--math.randomseed(os.time())
	if length > 0 then
		local output = stringrandom(length - 1) .. charset[math.random(1, #charset)]
		local duplicate_found = 0 --mark if we find a duplicate or not
		local stringrandom_table_length = #stringrandom_table
		for i=1,stringrandom_table_length do --for each value in our generated var table
			if stringrandom_table[i] == output then --if a value in our table matches our generated var
				duplicate_found = 1 --mark as duplicate var
				output = "_" .. output --append an underscore to the duplicate var
				stringrandom_table[stringrandom_table_new_length] = output --insert to the table
				stringrandom_table_new_length=stringrandom_table_new_length+1
				break --break out of for each loop since we found a duplicate
			end
		end
		if duplicate_found == 0 then --if no duplicate found
			stringrandom_table[stringrandom_table_new_length] = output --insert the output to our table
			stringrandom_table_new_length=stringrandom_table_new_length+1
		end
		return output
	else
		return ""
	end
end
--stringrandom(10)

local stringrandom_length = "" --create our random length variable
if dynamic_javascript_vars_length == 1 then --if our javascript random var length is to be static
	stringrandom_length = dynamic_javascript_vars_length_static --set our length as our static value
else --it is to be dynamic
	stringrandom_length = math.random(dynamic_javascript_vars_length_start, dynamic_javascript_vars_length_end) --set our length to be our dynamic min and max value
end

--shuffle table function
function shuffle(tbl)
	local tbl_length = #tbl
	for i = tbl_length, 2, -1 do
		local j = math.random(i)
		tbl[i], tbl[j] = tbl[j], tbl[i]
	end
	return tbl
end

--for my javascript Hex output
local function sep(str, patt, re)
	local rstr = str:gsub(patt, "%1%" .. re)
	--local rstr = ngx.re.gsub(str, patt, "%1%" .. re, ngx_re_options) --this has a major issue no idea why need to investigate more
	return rstr:sub(1, #rstr - #re)
end

local function stringtohex(str)
	--return ngx.re.gsub(str, ".", function (c) print(tostring(c[0])) return string.format('%02X', string.byte(c[0])) end, ngx_re_options) --this has a major issue no idea why need to investigate more
	return str:gsub('.', function (c)
		return string.format('%02X', string.byte(c))
	end)
end

--encrypt_javascript function
local function encrypt_javascript(string1, type, defer_async, num_encrypt, encrypt_type, methods) --Function to generate encrypted/obfuscated output
	local output = "" --Empty var

	if type == 0 then
		type = math.random(3, 5) --Random encryption
	end

	if type == 1 or type == nil then --No encryption
		if defer_async == "0" or defer_async == nil then --Browser default loading / execution order
			output = "<script type=\"text/javascript\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. string1 .. "</script>"
		end
		if defer_async == "1" then --Defer
			output = "<script type=\"text/javascript\" defer=\"defer\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. string1 .. "</script>"
		end
		if defer_async == "2" then --Async
			output = "<script type=\"text/javascript\" async=\"async\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. string1 .. "</script>"
		end
	end

	--https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs
	--pass other encrypted outputs through this too ?
	if type == 2 then --Base64 Data URI
		local base64_data_uri = string1

		if tonumber(num_encrypt) ~= nil then --If number of times extra to rencrypt is set
			for i=1, #num_encrypt do --for each number
				string1 = ngx.encode_base64(base64_data_uri)
			end
		end

		if defer_async == "0" or defer_async == nil then --Browser default loading / execution order
			output = "<script type=\"text/javascript\" src=\"data:text/javascript;base64," .. ngx.encode_base64(string1) .. "\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\"></script>"
		end
		if defer_async == "1" then --Defer
			output = "<script type=\"text/javascript\" src=\"data:text/javascript;base64," .. ngx.encode_base64(string1) .. "\" defer=\"defer\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\"></script>"
		end
		if defer_async == "2" then --Async
			output = "<script type=\"text/javascript\" src=\"data:text/javascript;base64," .. ngx.encode_base64(string1) .. "\" async=\"async\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\"></script>"
		end
	end

	if type == 3 then --Hex
		local hex_output = stringtohex(string1) --ndk.set_var.set_encode_hex(string1) --Encode string in hex
		local hexadecimal_x = "" --Create var
		local encrypt_type_origin = encrypt_type --Store var passed to function in local var

		if tonumber(encrypt_type) == nil or tonumber(encrypt_type) <= 0 then
			encrypt_type = math.random(2, 2) --Random encryption
		end
		--I was inspired by http://www.hightools.net/javascript-encrypter.php so i built it myself
		if tonumber(encrypt_type) == 1 then
			hexadecimal_x = "%" .. sep(hex_output, "%x%x", "%") --hex output insert a char every 2 chars %x%x
		end
		if tonumber(encrypt_type) == 2 then
			hexadecimal_x = string.char(92) .. "x" .. sep(hex_output, "%x%x", string.char(92) .. "x") --hex output insert a char every 2 chars %x%x
		end

		--TODO: Fix this.
		--num_encrypt = "3" --test var
		if tonumber(num_encrypt) ~= nil then --If number of times extra to rencrypt is set
			for i=1, num_encrypt do --for each number
				if tonumber(encrypt_type) ~= nil then
					encrypt_type = math.random(1, 2) --Random encryption
					if tonumber(encrypt_type) == 1 then
						--hexadecimal_x = "%" .. sep(ndk.set_var.set_encode_hex("eval(decodeURIComponent('" .. hexadecimal_x .. "'))"), "%x%x", "%") --hex output insert a char every 2 chars %x%x
					end
					if tonumber(encrypt_type) == 2 then
						--hexadecimal_x = "\\x" .. sep(ndk.set_var.set_encode_hex("eval(decodeURIComponent('" .. hexadecimal_x .. "'))"), "%x%x", "\\x") --hex output insert a char every 2 chars %x%x
					end
				end
			end
		end

		if defer_async == "0" or defer_async == nil then --Browser default loading / execution order
			--https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/decodeURIComponent
			output = "<script type=\"text/javascript\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">eval(decodeURIComponent(escape('" .. hexadecimal_x .. "')));</script>"
		end
		if defer_async == "1" then --Defer
			output = "<script type=\"text/javascript\" defer=\"defer\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">eval(decodeURIComponent(escape('" .. hexadecimal_x .. "')));</script>"
		end
		if defer_async == "2" then --Defer
			output = "<script type=\"text/javascript\" async=\"async\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">eval(decodeURIComponent(escape('" .. hexadecimal_x .. "')));</script>"
		end
	end

	if type == 4 then --Base64 javascript decode
		local base64_javascript = "eval(decodeURIComponent(escape(window.atob('" .. ngx.encode_base64(string1) .. "'))))"

		if tonumber(num_encrypt) ~= nil then --If number of times extra to rencrypt is set
			for i=1, num_encrypt do --for each number
				base64_javascript = "eval(decodeURIComponent(escape(window.atob('" .. ngx.encode_base64(base64_javascript) .. "'))))"
			end
		end

		if defer_async == "0" or defer_async == nil then --Browser default loading / execution order
			output = "<script type=\"text/javascript\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. base64_javascript .. "</script>"
		end
		if defer_async == "1" then --Defer
			output = "<script type=\"text/javascript\" defer=\"defer\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. base64_javascript .. "</script>"
		end
		if defer_async == "2" then --Defer
			output = "<script type=\"text/javascript\" async=\"async\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. base64_javascript .. "</script>"
		end
	end

	if type == 5 then --Conor Mcknight's Javascript Scrambler (Obfuscate Javascript by putting it into vars and shuffling them like a deck of cards)
		local base64_javascript = ngx.encode_base64(string1) --base64 encode our script

		local l = #base64_javascript --count number of chars our variable has
		local i = 0 --keep track of how many times we pass through
		local r = math.random(1, l) --randomize where to split string
		local chunks = {} --create our chunks table for string storage
		local chunks_table_length = 1
		local chunks_order = {} --create our chunks table for string storage that stores the value only
		local chunks_order_table_length = 1
		local random_var = nil --create our random string variable to use

		while i <= l do
			random_var = stringrandom(stringrandom_length) --create a random variable name to use
			chunks_order[chunks_order_table_length] = "_" .. random_var .. "" --insert the value into our ordered table
			chunks_order_table_length=chunks_order_table_length+1
			chunks[chunks_table_length] = 'var _' .. random_var .. '="' .. base64_javascript:sub(i,i+r).. '";' --insert our value into our table we will scramble
			chunks_table_length=chunks_table_length+1

			i = i+r+1
		end

		shuffle(chunks) --scramble our table

		output = table.concat(chunks, "") --put our scrambled table into string
		output = output .. "eval(decodeURIComponent(escape(window.atob(" .. table.concat(chunks_order, " + " ) .. "))));" --put our scrambled table and ordered table into a string
		
		if defer_async == "0" or defer_async == nil then --Browser default loading / execution order
			output = "<script type=\"text/javascript\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. output .. "</script>"
		end
		if defer_async == "1" then --Defer
			output = "<script type=\"text/javascript\" defer=\"defer\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. output .. "</script>"
		end
		if defer_async == "2" then --Defer
			output = "<script type=\"text/javascript\" async=\"async\" charset=\"" .. default_charset .. "\" data-cfasync=\"false\">" .. output .. "</script>"
		end
	end

	return output
end
--end encrypt_javascript function

local currenttime = ngx.time() --Current time on server

local currentdate = "" --make current date a empty var

--Make sure our current date is in align with expires_time variable so that the auth page only shows when the cookie expires
if expire_time <= 60 then --less than equal to one minute
	currentdate = os.date("%M",os.time()-24*60*60) --Current minute
end
if expire_time > 60 then --greater than one minute
	currentdate = os.date("%H",os.time()-24*60*60) --Current hour
end
if expire_time > 3600 then --greater than one hour
	currentdate = os.date("%d",os.time()-24*60*60) --Current day of the year
end
if expire_time > 86400 then --greater than one day
	currentdate = os.date("%W",os.time()-24*60*60) --Current week
end
if expire_time > 6048000 then --greater than one week
	currentdate = os.date("%m",os.time()-24*60*60) --Current month
end
if expire_time > 2628000 then --greater than one month
	currentdate = os.date("%Y",os.time()-24*60*60) --Current year
end
if expire_time > 31536000 then --greater than one year
	currentdate = os.date("%z",os.time()-24*60*60) --Current time zone
end

local expected_header_status = 200
local authentication_page_status_output = 503

--Put our vars into storage for use later on
local challenge_original = challenge
local cookie_name_start_date_original = cookie_name_start_date
local cookie_name_end_date_original = cookie_name_end_date
local cookie_name_encrypted_start_and_end_date_original = cookie_name_encrypted_start_and_end_date

--[[
Start Tor detection
]]
if x_tor_header == 2 then --if x-tor-header is dynamic
	x_tor_header_name = calculate_signature(tor_remote_addr .. x_tor_header_name .. currentdate) --make the header unique to the client and for todays date encrypted so every 24 hours this will change and can't be guessed by bots gsub because header bug with underscores so underscore needs to be removed
	x_tor_header_name = ngx.re.gsub(x_tor_header_name, "_", "", ngx_re_options) --replace underscore with nothing
	x_tor_header_name_allowed = calculate_signature(tor_remote_addr .. x_tor_header_name_allowed .. currentdate) --make the header unique to the client and for todays date encrypted so every 24 hours this will change and can't be guessed by bots gsub because header bug with underscores so underscore needs to be removed
	x_tor_header_name_allowed = ngx.re.gsub(x_tor_header_name_allowed, "_", "", ngx_re_options) --replace underscore with nothing
	x_tor_header_name_blocked = calculate_signature(tor_remote_addr .. x_tor_header_name_blocked .. currentdate) --make the header unique to the client and for todays date encrypted so every 24 hours this will change and can't be guessed by bots gsub because header bug with underscores so underscore needs to be removed
	x_tor_header_name_blocked = ngx.re.gsub(x_tor_header_name_blocked, "_", "", ngx_re_options) --replace underscore with nothing
end

if encrypt_anti_ddos_cookies == 2 then --if Anti-DDoS Cookies are to be encrypted
	cookie_tor = calculate_signature(tor_remote_addr .. cookie_tor .. currentdate) --encrypt our tor cookie name
	cookie_tor_value_allow = calculate_signature(tor_remote_addr .. cookie_tor_value_allow .. currentdate) --encrypt our tor cookie value for allow
	cookie_tor_value_block = calculate_signature(tor_remote_addr .. cookie_tor_value_block .. currentdate) --encrypt our tor cookie value for block
end

--block tor function to block traffic from tor users
local function blocktor()
	local output = ngx.exit(ngx.HTTP_FORBIDDEN) --deny user access
	return output
end

--check the connecting client to see if they have our required matching tor cookie name in their request
local tor_cookie_name = "cookie_" .. cookie_tor
local tor_cookie_value = ngx.var[tor_cookie_name] or ""

if tor_cookie_value == cookie_tor_value_allow then --if their cookie value matches the value we expect
	if tor == 2 then --perform check if tor users should be allowed or blocked if tor users already browsing your site have been granted access and you change this setting you want them to be blocked now so this makes sure they are denied any further access before their cookie expires
		blocktor()
	end
	remote_addr = tor_remote_addr --set the remote_addr as the tor_remote_addr value
end

if tor_cookie_value == cookie_tor_value_block then --if the provided cookie value matches our block cookie value
	blocktor()
end

local cookie_tor_value = "" --create variable to store if tor should be allowed or disallowed
local x_tor_header_name_value = "" --create variable to store our expected header value

if tor == 1 then --if tor users should be allowed
	cookie_tor_value = cookie_tor_value_allow --set our value as our expected allow value
	x_tor_header_name_value = x_tor_header_name_allowed --set our value as our expected allow value
else --tor users should be blocked
	cookie_tor_value = cookie_tor_value_block --set our value as our expected block value
	x_tor_header_name_value = x_tor_header_name_blocked --set our value as our expected block value
end
--[[
End Tor detection
]]

--[[
Authorization / Restricted Access Area Box
]]
if encrypt_anti_ddos_cookies == 2 then --if Anti-DDoS Cookies are to be encrypted
	authorization_cookie = calculate_signature(remote_addr .. authorization_cookie .. currentdate) --encrypt our auth box session cookie name
end

local function check_authorization(authorization, authorization_dynamic)
	if authorization == 0 or nil then --auth box disabled
		return
	end

	local expected_cookie_value = nil
	local remote_addr = tor_remote_addr --set for compatibility with Tor Clients
	if authorization == 2 then --Cookie sessions
		local cookie_name = "cookie_" .. authorization_cookie
		local cookie_value = ngx.var[cookie_name] or ""
		expected_cookie_value = calculate_signature(remote_addr .. "authenticate" .. currentdate) --encrypt our expected cookie value
		if cookie_value == expected_cookie_value then --cookie value client gave us matches what we expect it to be
			ngx.exit(ngx.OK) --Go to content
		end
	end

	local allow_site = nil
	local authorization_display_user_details = nil
	local authorization_paths_length = #authorization_paths
	for i=1,authorization_paths_length do --for each host in our table
		local v = authorization_paths[i]
		if string.match(URL, v[2]) then --if our host matches one in the table
			if v[1] == 1 then --Showbox
				allow_site = 1 --showbox
			end
			if v[1] == 2 then --Don't show box
				allow_site = 2 --don't show box
			end
			authorization_display_user_details = v[3] --to show our username/password or to not display it
			break --break out of the for each loop pointless to keep searching the rest since we matched our host
		end
	end
	if allow_site == 1 then --checks passed site allowed grant direct access
		--showbox
	else --allow_site was 2
		return --carry on script functions to display auth page
	end

	local allow_access = nil
	local authorization_username = nil
	local authorization_password = nil

	local req_headers = ngx.req.get_headers() --get all request headers

	if authorization_dynamic == 0 then --static
		local authorization_logins_length = #authorization_logins
		for i=1,authorization_logins_length do --for each login
			local value = authorization_logins[i]
			authorization_username = value[1] --username
			authorization_password = value[2] --password
			local base64_expected = authorization_username .. ":" .. authorization_password --convert to browser format
			base64_expected = ngx.encode_base64(base64_expected) --base64 encode like browser format
			local authroization_user_pass = "Basic " .. base64_expected --append Basic to start like browser header does
			if req_headers["Authorization"] == authroization_user_pass then --if the details match what we expect
				if authorization == 2 then --Cookie sessions
					set_cookie1 = authorization_cookie.."="..expected_cookie_value.."; path=/; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";"
					set_cookies = {set_cookie1}
					ngx.header["Set-Cookie"] = set_cookies --send client a cookie for their session to be valid
				end
				allow_access = 1 --grant access
				break --break out foreach loop since our user and pass was correct
			end
		end
	end
	if authorization_dynamic == 1 then --dynamic
		authorization_username = calculate_signature(remote_addr .. "username" .. currentdate) --encrypt username
		authorization_password = calculate_signature(remote_addr .. "password" .. currentdate) --encrypt password
		authorization_username = string.sub(authorization_username, 1, authorization_dynamic_length) --change username to set length
		authorization_password = string.sub(authorization_password, 1, authorization_dynamic_length) --change password to set length

		local base64_expected = authorization_username .. ":" .. authorization_password --convert to browser format
		base64_expected = ngx.encode_base64(base64_expected) --base64 encode like browser format
		local authroization_user_pass = "Basic " .. base64_expected --append Basic to start like browser header does
		if req_headers["Authorization"] == authroization_user_pass then --if the details match what we expect
			if authorization == 2 then --Cookie sessions
				set_cookie1 = authorization_cookie.."="..expected_cookie_value.."; path=/; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";"
				set_cookies = {set_cookie1}
				ngx.header["Set-Cookie"] = set_cookies --send client a cookie for their session to be valid
			end
			allow_access = 1 --grant access
		end
	end

	if allow_access == 1 then
		ngx.exit(ngx.OK) --Go to content
	else
		ngx.status = ngx.HTTP_UNAUTHORIZED --send client unathorized header
		if authorization_display_user_details == 0 then
			ngx.header['WWW-Authenticate'] = 'Basic realm="' .. authorization_message .. '", charset="' .. default_charset .. '"' --send client a box to input required username and password fields
		else
			ngx.header['WWW-Authenticate'] = 'Basic realm="' .. authorization_message .. ' ' .. authorization_username_message .. ' ' .. authorization_username .. ' ' .. authorization_password_message .. ' ' .. authorization_password .. '", charset="' .. default_charset .. '"' --send client a box to input required username and password fields
		end
		ngx.exit(ngx.HTTP_UNAUTHORIZED) --deny access any further
	end
end
check_authorization(authorization, authorization_dynamic)
--[[
Authorization / Restricted Access Area Box
]]

--[[
master switch
]]
--master switch check
local function check_master_switch()
	if master_switch == 2 then --script disabled
		local output = ngx.exit(ngx.OK) --Go to content
		return output
	end
	if master_switch == 3 then --custom host selection
		local allow_site = nil
		local master_switch_custom_hosts_length = #master_switch_custom_hosts
		for i=1,master_switch_custom_hosts_length do --for each host in our table
			local v = master_switch_custom_hosts[i]
			if string.match(URL, v[2]) then --if our host matches one in the table
				if v[1] == 1 then --run auth
					allow_site = 2 --run auth checks
				end
				if v[1] == 2 then --bypass
					allow_site = 1 --bypass auth achecks
				end
				break --break out of the for each loop pointless to keep searching the rest since we matched our host
			end
		end
		if allow_site == 1 then --checks passed site allowed grant direct access
			local output = ngx.exit(ngx.OK) --Go to content
			return output
		else --allow_site was 2 to disallow direct access we matched a host to protect
			return --carry on script functions to display auth page
		end
	end
end
check_master_switch()
--[[
master switch
]]

local answer = calculate_signature(remote_addr) --create our encrypted unique identification for the user visiting the website.

if x_auth_header == 2 then --if x-auth-header is dynamic
	x_auth_header_name = calculate_signature(remote_addr .. x_auth_header_name .. currentdate) --make the header unique to the client and for todays date encrypted so every 24 hours this will change and can't be guessed by bots gsub because header bug with underscores so underscore needs to be removed
	x_auth_header_name = ngx.re.gsub(x_auth_header_name, "_", "", ngx_re_options) --replace underscore with nothing
end

if encrypt_anti_ddos_cookies == 2 then --if Anti-DDoS Cookies are to be encrypted
	--make the cookies unique to the client and for todays date encrypted so every 24 hours this will change and can't be guessed by bots
	challenge = calculate_signature(remote_addr .. challenge .. currentdate)
	cookie_name_start_date = calculate_signature(remote_addr .. cookie_name_start_date .. currentdate)
	cookie_name_end_date = calculate_signature(remote_addr .. cookie_name_end_date .. currentdate)
	cookie_name_encrypted_start_and_end_date = calculate_signature(remote_addr .. cookie_name_encrypted_start_and_end_date .. currentdate)
end

--[[
Grant access function to either grant or deny user access to our website
]]
local function grant_access()
	--our uid cookie
	local cookie_name = "cookie_" .. challenge
	local cookie_value = ngx.var[cookie_name] or ""
	--our start date cookie
	local cookie_name_start_date_name = "cookie_" .. cookie_name_start_date
	local cookie_name_start_date_value = ngx.var[cookie_name_start_date_name] or ""
	local cookie_name_start_date_value_unix = tonumber(cookie_name_start_date_value)
	--our end date cookie
	local cookie_name_end_date_name = "cookie_" .. cookie_name_end_date
	local cookie_name_end_date_value = ngx.var[cookie_name_end_date_name] or ""
	--our start date and end date combined to a unique id
	local cookie_name_encrypted_start_and_end_date_name = "cookie_" .. cookie_name_encrypted_start_and_end_date
	local cookie_name_encrypted_start_and_end_date_value = ngx.var[cookie_name_encrypted_start_and_end_date_name] or ""

	if cookie_value ~= answer then --if cookie value not equal to or matching our expected cookie they should be giving us
		return --return to refresh the page so it tries again
	end

	--if x-auth-answer is correct to the user unique id time stamps etc meaning browser figured it out then set a new cookie that grants access without needed these checks
	local req_headers = ngx.req.get_headers() --get all request headers
	if req_headers["x-requested-with"] == "XMLHttpRequest" then --if request header matches request type of XMLHttpRequest
		if req_headers[x_tor_header_name] == x_tor_header_name_value and req_headers[x_auth_header_name] == JavascriptPuzzleVars_answer then --if the header and value are what we expect then the client is legitimate
			remote_addr = tor_remote_addr --set as our defined static tor variable to use
			
			challenge = calculate_signature(remote_addr .. challenge_original .. currentdate) --create our encrypted unique identification for the user visiting the website again. (Stops a double page refresh loop)
			answer = calculate_signature(remote_addr) --create our answer again under the new remote_addr (Stops a double page refresh loop)
			cookie_name_start_date = calculate_signature(remote_addr .. cookie_name_start_date_original .. currentdate) --create our cookie_name_start_date again under the new remote_addr (Stops a double page refresh loop)
			cookie_name_end_date = calculate_signature(remote_addr .. cookie_name_end_date_original .. currentdate) --create our cookie_name_end_date again under the new remote_addr (Stops a double page refresh loop)
			cookie_name_encrypted_start_and_end_date = calculate_signature(remote_addr .. cookie_name_encrypted_start_and_end_date_original .. currentdate) --create our cookie_name_encrypted_start_and_end_date again under the new remote_addr (Stops a double page refresh loop)

			set_cookie1 = challenge.."="..answer.."; path=/; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";" --apply our uid cookie incase javascript setting this cookies time stamp correctly has issues
			set_cookie2 = cookie_name_start_date.."="..currenttime.."; path=/; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";" --start date cookie
			set_cookie3 = cookie_name_end_date.."="..(currenttime+expire_time).."; path=/; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";" --end date cookie
			set_cookie4 = cookie_name_encrypted_start_and_end_date.."="..calculate_signature(remote_addr .. currenttime .. (currenttime+expire_time) ).."; path=/; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";" --start and end date combined to unique id
			set_cookie5 = cookie_tor.."="..cookie_tor_value.."; path=/; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";" --create our tor cookie to identify the client as a tor user

			set_cookies = {set_cookie1 , set_cookie2 , set_cookie3 , set_cookie4, set_cookie5}
			ngx.header["Set-Cookie"] = set_cookies
			ngx.header["X-Content-Type-Options"] = "nosniff"
			ngx.header["X-Frame-Options"] = "SAMEORIGIN"
			ngx.header["X-XSS-Protection"] = "1; mode=block"
			ngx.header["Cache-Control"] = "public, max-age=0 no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
			ngx.header["Pragma"] = "no-cache"
			ngx.header["Expires"] = "0"
			ngx.header.content_type = "text/html; charset=" .. default_charset
			ngx.status = expected_header_status
			ngx.exit(ngx.HTTP_NO_CONTENT)
		end
		if req_headers[x_auth_header_name] == JavascriptPuzzleVars_answer then --if the answer header provided by the browser Javascript matches what our Javascript puzzle answer should be
			set_cookie1 = challenge.."="..cookie_value.."; path=/; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";" --apply our uid cookie incase javascript setting this cookies time stamp correctly has issues
			set_cookie2 = cookie_name_start_date.."="..currenttime.."; path=/; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";" --start date cookie
			set_cookie3 = cookie_name_end_date.."="..(currenttime+expire_time).."; path=/; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";" --end date cookie
			set_cookie4 = cookie_name_encrypted_start_and_end_date.."="..calculate_signature(remote_addr .. currenttime .. (currenttime+expire_time) ).."; path=/; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";" --start and end date combined to unique id

			set_cookies = {set_cookie1 , set_cookie2 , set_cookie3 , set_cookie4}
			ngx.header["Set-Cookie"] = set_cookies
			ngx.header["X-Content-Type-Options"] = "nosniff"
			ngx.header["X-Frame-Options"] = "SAMEORIGIN"
			ngx.header["X-XSS-Protection"] = "1; mode=block"
			ngx.header["Cache-Control"] = "public, max-age=0 no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
			ngx.header["Pragma"] = "no-cache"
			ngx.header["Expires"] = "0"
			ngx.header.content_type = "text/html; charset=" .. default_charset
			ngx.status = expected_header_status
			ngx.exit(ngx.HTTP_NO_CONTENT)
		end
	end

	if cookie_name_start_date_value ~= nil and cookie_name_end_date_value ~= nil and cookie_name_encrypted_start_and_end_date_value ~= nil then --if all our cookies exist
		local cookie_name_end_date_value_unix = tonumber(cookie_name_end_date_value) or nil --convert our cookie end date provided by the user into a unix time stamp
		if cookie_name_end_date_value_unix == nil or cookie_name_end_date_value_unix == "" then --if our cookie end date date in unix does not exist
			return --return to refresh the page so it tries again
		end
		if cookie_name_end_date_value_unix <= currenttime then --if our cookie end date is less than or equal to the current date meaning the users authentication time expired
			return --return to refresh the page so it tries again
		end
		if cookie_name_encrypted_start_and_end_date_value ~= calculate_signature(remote_addr .. cookie_name_start_date_value_unix .. cookie_name_end_date_value_unix) then --if users authentication encrypted cookie not equal to or matching our expected cookie they should be giving us
			return --return to refresh the page so it tries again
		end
	end
	--else all checks passed bypass our firewall and show page content

	local output = ngx.exit(ngx.OK) --Go to content
	return output
end
--grant_access()

--[[
End Required Functions
]]

grant_access() --perform checks to see if user can access the site or if they will see our denial of service status below

--[[
Build HTML Template
]]

local title = host .. [[ | Anti-DDoS Flood Protection and Firewall]]

--[[
Javascript after setting cookie run xmlhttp GET request
if cookie did exist in GET request then respond with valid cookie to grant access
also
if GET request contains specific required headers provide a SETCOOKIE
then if GET request response had specific passed security check response header
run window.location.reload(); Javascript
]]
if javascript_REQUEST_TYPE == 3 then --Dynamic Random request
	javascript_REQUEST_TYPE = math.random (1, 2) --Randomize between 1 and 2
end
if javascript_REQUEST_TYPE == 1 then --GET request
	javascript_REQUEST_TYPE = "GET"
end
if javascript_REQUEST_TYPE == 2 then --POST request
	javascript_REQUEST_TYPE = "POST"
end

local javascript_POST_headers = "" --Create empty var
local javascript_POST_data = "" --Create empty var

if javascript_REQUEST_TYPE == "POST" then
	-- https://www.w3schools.com/xml/tryit.asp?filename=tryajax_post2
	javascript_POST_headers = [[xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
]]

	javascript_POST_data = [["name1=Henry&name2=Ford"]]

end

local JavascriptPuzzleVariable_name = "_" .. stringrandom(stringrandom_length)

--[[
Begin Tor Browser Checks
Because Tor blocks browser fingerprinting / tracking it actually makes it easy to detect by comparing screen window sizes if they do not match we know it is Tor
]]
local javascript_detect_tor = [[
var sw, sh, ww, wh, v;
sw = screen.width;
sh = screen.height;
ww = window.innerWidth || document.documentElement.clientWidth || document.body.clientWidth || 0;
wh = window.innerHeight || document.documentElement.clientHeight || document.body.clientHeight || 0;
if ((sw == ww) && (sh == wh)) {
    v = true;
    if (!(ww % 200) && (wh % 100)) {
        v = true;
    }
}
//v = true; //test var nulled out used for debugging purpose
if (v == true) {
	xhttp.setRequestHeader(']] .. x_tor_header_name .. [[', ']] .. x_tor_header_name_value .. [[');
}
]]
--[[
End Tor Browser Checks
]]

local javascript_REQUEST_headers = [[
xhttp.setRequestHeader(']] .. x_auth_header_name .. [[', ]] .. JavascriptPuzzleVariable_name .. [[); //make the answer what ever the browser figures it out to be
			xhttp.setRequestHeader('X-Requested-with', 'XMLHttpRequest');
			xhttp.setRequestHeader('X-Requested-TimeStamp', '');
			xhttp.setRequestHeader('X-Requested-TimeStamp-Expire', '');
			xhttp.setRequestHeader('X-Requested-TimeStamp-Combination', '');
			xhttp.setRequestHeader('X-Requested-Type', 'GET');
			xhttp.setRequestHeader('X-Requested-Type-Combination', 'GET'); //Encrypted for todays date
			xhttp.withCredentials = true;
]] .. javascript_detect_tor

local JavascriptPuzzleVariable = [[
var ]] .. JavascriptPuzzleVariable_name .. [[=]] .. JavascriptPuzzleVars ..[[;
]]

-- https://www.w3schools.com/xml/tryit.asp?filename=try_dom_xmlhttprequest
local javascript_anti_ddos = [[
(function(){
	var a = function() {try{return !!window.addEventListener} catch(e) {return !1} },
	b = function(b, c) {a() ? document.addEventListener("DOMContentLoaded", b, c) : document.attachEvent("onreadystatechange", b)};
	b(function(){
		var timeleft = ]] .. refresh_auth .. [[;
		var downloadTimer = setInterval(function(){
			timeleft--;
			document.getElementById("countdowntimer").textContent = timeleft;
			if(timeleft <= 0)
			clearInterval(downloadTimer);
		},1000);
		setTimeout(function(){
			var now = new Date();
			var time = now.getTime();
			time += 300 * 1000;
			now.setTime(time);
			document.cookie = ']] .. challenge .. [[=]] .. answer .. [[' + '; expires=' + ']] .. ngx.cookie_time(currenttime+expire_time) .. [[' + '; path=/';
			//javascript puzzle for browser to figure out to get answer
			]] .. JavascriptVars_opening .. [[
			]] .. JavascriptPuzzleVariable .. [[
			]] .. JavascriptVars_closing .. [[
			//end javascript puzzle
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function() {
				if (xhttp.readyState === 4) {
					document.getElementById("status").innerHTML = "Refresh your page.";
					location.reload(true);
				}
			};
			xhttp.open("]] .. javascript_REQUEST_TYPE .. [[", "]] .. request_uri .. [[", true);
			]] .. javascript_REQUEST_headers .. [[
			]] .. javascript_POST_headers .. [[
			xhttp.send(]] .. javascript_POST_data .. [[);
		}, ]] .. refresh_auth+1 .. [[000); /*if correct data has been sent then the auth response will allow access*/
	}, false);
})();
]]

--TODO: include Captcha like Google ReCaptcha

--[[
encrypt/obfuscate the javascript output
]]
if encrypt_javascript_output == 1 then --No encryption/Obfuscation of Javascript so show Javascript in plain text
javascript_anti_ddos = [[<script type="text/javascript" charset="]] .. default_charset .. [[" data-cfasync="false">
]] .. javascript_anti_ddos .. [[
</script>]]
else --some form of obfuscation has been specified so obfuscate the javascript output
javascript_anti_ddos = encrypt_javascript(javascript_anti_ddos, encrypt_javascript_output) --run my function to encrypt/obfuscate javascript output
end


--Adverts positions
local head_ad_slot = [[
<!-- Start: Ad code and script tags for header of page -->
<!-- End: Ad code and script tags for header of page -->
]]
local top_body_ad_slot = [[
<!-- Start: Ad code and script tags for top of page -->
<!-- End: Ad code and script tags for top of page -->
]]
local left_body_ad_slot = [[
<!-- Start: Ad code and script tags for left of page -->
<!-- End: Ad code and script tags for left of page -->
]]
local right_body_ad_slot = [[
<!-- Start: Ad code and script tags for right of page -->
<!-- End: Ad code and script tags for right of page -->
]]
local footer_body_ad_slot = [[
<!-- Start: Ad code and script tags for bottom of page -->
<!-- End: Ad code and script tags for bottom of page -->
]]
--End advert positions

local ddos_credits = [[
<div class="credits" style="text-align:center;font-size:100%;">
<a href="//facebook.com/C0nw0nk" target="_blank">DDoS protection by &copy; Conor McKnight</a>
</div>
]]

if credits == 2 then
ddos_credits = "" --make empty string
end

--Fix remote_addr output as what ever IP address the Client is using
if ngx.var.http_cf_connecting_ip ~= nil then
remote_addr = ngx.var.http_cf_connecting_ip
elseif ngx.var.http_x_forwarded_for ~= nil then
remote_addr = ngx.var.http_x_forwarded_for
else
remote_addr = ngx.var.remote_addr
end

local request_details = [[
<br>
<div id="status" style="color:#bd2426;font-size:200%;">
<noscript>Please turn JavaScript on and reload the page.<br></noscript>
This process is automatic. Your browser will redirect to your requested content shortly.
<br>
Please allow up to <span id="countdowntimer">]] .. refresh_auth .. [[</span> seconds&hellip;
</div>
<br>
<br>
<h3 style="color:#bd2426;">Request Details :</h3>
IP address : ]] .. remote_addr .. [[
<br>
Request URL : ]] .. URL .. [[
<br>
User-Agent : ]] .. user_agent .. [[
<br>
]]

local style_sheet = [[
html, body {/*width: 100%; height: 100%;*/ margin: 0; padding: 0; overflow-wrap: break-word; word-wrap: break-word;}
body {background-color: #ffffff; font-family: Helvetica, Arial, sans-serif; font-size: 100%;}
h1 {font-size: 1.5em; color: #404040; text-align: center;}
p {font-size: 1em; color: #404040; text-align: center; margin: 10px 0 0 0;}
#spinner {margin: 0 auto 30px auto; display: block;}
.attribution {margin-top: 20px;}
@-webkit-keyframes bubbles { 33%: { -webkit-transform: translateY(10px); transform: translateY(10px); } 66% { -webkit-transform: translateY(-10px); transform: translateY(-10px); } 100% { -webkit-transform: translateY(0); transform: translateY(0); } }
@keyframes bubbles { 33%: { -webkit-transform: translateY(10px); transform: translateY(10px); } 66% { -webkit-transform: translateY(-10px); transform: translateY(-10px); } 100% { -webkit-transform: translateY(0); transform: translateY(0); } }
.bubbles { background-color: #404040; width:15px; height: 15px; margin:2px; border-radius:100%; -webkit-animation:bubbles 0.6s 0.07s infinite ease-in-out; animation:bubbles 0.6s 0.07s infinite ease-in-out; -webkit-animation-fill-mode:both; animation-fill-mode:both; display:inline-block; }
]]

local anti_ddos_html_output = [[
<!DOCTYPE html>
<html>
<head>
<meta charset="]] .. default_charset .. [[" />
<meta http-equiv="Content-Type" content="text/html; charset=]] .. default_charset .. [[" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge,chrome=1" />
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
<meta name="robots" content="noindex, nofollow" />
<title>]] .. title .. [[</title>
<style type="text/css">
]] .. style_sheet .. [[
</style>
]] .. head_ad_slot .. [[
]] .. javascript_anti_ddos .. [[
</head>
<body style="background-color:#EEEEEE;color:#000000;font-family:Arial,Helvetica,sans-serif;font-size:100%;">
<div style="width:auto;margin:16px auto;border:1px solid #CCCCCC;background-color:#FFFFFF;border-radius:3px 3px 3px 3px;padding:10px;">
<div style="float:right;margin-top:10px;">
<br>
<h1>Checking your browser</h1>
</div>
<br>
<h1>]] .. title .. [[</h1>
<p>
<b>Please wait a moment while we verify your request</b>
<br>
<br>
<br>
]] .. top_body_ad_slot .. [[
<br>
<br>
<center>
<h2>Information :</h2>
]] .. request_details .. [[
</center>
]] .. footer_body_ad_slot .. [[
</div>
]] .. ddos_credits .. [[
</body>
</html>
]]

--All previous checks failed and no access_granted permited so display authentication check page.
--Output Anti-DDoS Authentication Page
if set_cookies == nil then
set_cookies = challenge.."="..answer.."; path=/; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";" --apply our uid cookie in header here incase browsers javascript can't set cookies due to permissions.
end
ngx.header["Set-Cookie"] = set_cookies
ngx.header["X-Content-Type-Options"] = "nosniff"
ngx.header["X-Frame-Options"] = "SAMEORIGIN"
ngx.header["X-XSS-Protection"] = "1; mode=block"
ngx.header["Cache-Control"] = "public, max-age=0 no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
ngx.header["Pragma"] = "no-cache"
ngx.header["Expires"] = "0"
if credits == 1 then
ngx.header["X-Anti-DDoS"] = "Conor McKnight | facebook.com/C0nw0nk"
end
ngx.header.content_type = "text/html; charset=" .. default_charset
ngx.status = authentication_page_status_output
ngx.say(anti_ddos_html_output)
ngx.exit(ngx.HTTP_OK)
