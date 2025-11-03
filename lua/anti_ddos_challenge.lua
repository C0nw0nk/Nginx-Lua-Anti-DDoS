
--[[
Introduction and details :
Script Version: 2.8

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
localize all standard Lua and ngx functions I use for better performance.
]]
local localized = {}
localized.tonumber = tonumber
localized.tostring = tostring
localized.next = next
localized.type = type
localized.os_date = os.date
localized.math_random = math.random
localized.math_floor = math.floor
localized.math_sin = math.sin
localized.math_pow = math.pow
localized.math_pi = math.pi
localized.math_sqrt = math.sqrt
localized.math_randomseed = math.randomseed
localized.table_sort = table.sort
localized.table_concat = table.concat
localized.string_match = string.match
localized.string_gmatch = string.gmatch
localized.string_lower = string.lower
localized.string_find = string.find
localized.string_sub = string.sub
localized.string_len = string.len
localized.string_char = string.char
localized.string_gsub = string.gsub
localized.string_format = string.format
localized.string_byte = string.byte
localized.bit_bxor = bit.bxor
localized.ngx = ngx
localized.ngx_hmac_sha1 = localized.ngx.hmac_sha1
localized.ngx_encode_base64 = localized.ngx.encode_base64
localized.ngx_req_get_uri_args = localized.ngx.req.get_uri_args
localized.ngx_req_set_header = localized.ngx.req.set_header
localized.ngx_req_get_headers = localized.ngx.req.get_headers
localized.ngx_req_set_uri_args = localized.ngx.req.set_uri_args
localized.ngx_req_read_body = localized.ngx.req.read_body
localized.ngx_req_get_body_data = localized.ngx.req.get_body_data
localized.ngx_req_get_body_file = localized.ngx.req.get_body_file
localized.ngx_decode_args = localized.ngx.decode_args
localized.ngx_cookie_time = localized.ngx.cookie_time
localized.ngx_time = localized.ngx.time
localized.ngx_header = localized.ngx.header
localized.ngx_var = localized.ngx.var
localized.ngx_status = localized.ngx.status
localized.ngx_exit = localized.ngx.exit
localized.ngx_say = localized.ngx.say
--HTTP overrides old nginx lua versions do not have the response status codes so i create them keeps the script backwards compatible
localized.ngx_HTTP_CONTINUE = localized.ngx.HTTP_CONTINUE or 100 --(100)
localized.ngx_HTTP_SWITCHING_PROTOCOLS = localized.ngx.HTTP_SWITCHING_PROTOCOLS or 101 --(101)
localized.ngx_HTTP_OK = localized.ngx.HTTP_OK or 200 --(200)
localized.ngx_HTTP_CREATED = localized.ngx.HTTP_CREATED or 201 --(201)
localized.ngx_HTTP_ACCEPTED = localized.ngx.HTTP_ACCEPTED or 202 --(202)
localized.ngx_HTTP_NO_CONTENT = localized.ngx.HTTP_NO_CONTENT or 204 --(204)
localized.ngx_HTTP_PARTIAL_CONTENT = localized.ngx.HTTP_PARTIAL_CONTENT or 206 --(206)
localized.ngx_HTTP_SPECIAL_RESPONSE = localized.ngx.HTTP_SPECIAL_RESPONSE or 300 --(300)
localized.ngx_HTTP_MOVED_PERMANENTLY = localized.ngx.HTTP_MOVED_PERMANENTLY or 301 --(301)
localized.ngx_HTTP_MOVED_TEMPORARILY = localized.ngx.HTTP_MOVED_TEMPORARILY or 302 --(302)
localized.ngx_HTTP_SEE_OTHER = localized.ngx.HTTP_SEE_OTHER or 303 --(303)
localized.ngx_HTTP_NOT_MODIFIED = localized.ngx.HTTP_NOT_MODIFIED or 304 --(304)
localized.ngx_HTTP_TEMPORARY_REDIRECT = localized.ngx.HTTP_TEMPORARY_REDIRECT or 307 --(307)
localized.ngx_HTTP_PERMANENT_REDIRECT = localized.ngx.HTTP_PERMANENT_REDIRECT or 308 --(308)
localized.ngx_HTTP_BAD_REQUEST = localized.ngx.HTTP_BAD_REQUEST or 400 --(400)
localized.ngx_HTTP_UNAUTHORIZED = localized.ngx.HTTP_UNAUTHORIZED or 401 --(401)
localized.ngx_HTTP_PAYMENT_REQUIRED = localized.ngx.HTTP_PAYMENT_REQUIRED or 402 --(402)
localized.ngx_HTTP_FORBIDDEN = localized.ngx.HTTP_FORBIDDEN or 403 --(403)
localized.ngx_HTTP_NOT_FOUND = localized.ngx.HTTP_NOT_FOUND or 404 --(404)
localized.ngx_HTTP_NOT_ALLOWED = localized.ngx.HTTP_NOT_ALLOWED or 405 --(405)
localized.ngx_HTTP_NOT_ACCEPTABLE = localized.ngx.HTTP_NOT_ACCEPTABLE or 406 --(406)
localized.ngx_HTTP_REQUEST_TIMEOUT = localized.ngx.HTTP_REQUEST_TIMEOUT or 408 --(408)
localized.ngx_HTTP_CONFLICT = localized.ngx.HTTP_CONFLICT or 409 --(409)
localized.ngx_HTTP_GONE = localized.ngx.HTTP_GONE or 410 --(410)
localized.ngx_HTTP_UPGRADE_REQUIRED = localized.ngx.HTTP_UPGRADE_REQUIRED or 426 --(426)
localized.ngx_HTTP_TOO_MANY_REQUESTS = localized.ngx.HTTP_TOO_MANY_REQUESTS or 429 --(429)
localized.ngx_HTTP_CLOSE = localized.ngx.HTTP_CLOSE or 444 --(444)
localized.ngx_HTTP_ILLEGAL = localized.ngx.HTTP_ILLEGAL or 451 --(451)
localized.ngx_HTTP_INTERNAL_SERVER_ERROR = localized.ngx.HTTP_INTERNAL_SERVER_ERROR or 500 --(500)
localized.ngx_HTTP_NOT_IMPLEMENTED = localized.ngx.HTTP_NOT_IMPLEMENTED or 501 --(501)
localized.ngx_HTTP_METHOD_NOT_IMPLEMENTED = localized.ngx.HTTP_METHOD_NOT_IMPLEMENTED or 501 --(501)
localized.ngx_HTTP_BAD_GATEWAY = localized.ngx.HTTP_BAD_GATEWAY or 502 --(502)
localized.ngx_HTTP_SERVICE_UNAVAILABLE = localized.ngx.HTTP_SERVICE_UNAVAILABLE or 503 --(503)
localized.ngx_HTTP_GATEWAY_TIMEOUT = localized.ngx.HTTP_GATEWAY_TIMEOUT or 504 --(504)
localized.ngx_HTTP_VERSION_NOT_SUPPORTED = localized.ngx.HTTP_VERSION_NOT_SUPPORTED or 505 --(505)
localized.ngx_HTTP_INSUFFICIENT_STORAGE = localized.ngx.HTTP_INSUFFICIENT_STORAGE or 507 --(507)
--HTTP Method overrides old nginx lua versions do not have some of these
localized.ngx_HTTP_GET = localized.ngx.HTTP_GET
localized.ngx_HTTP_HEAD = localized.ngx.HTTP_HEAD
localized.ngx_HTTP_PUT = localized.ngx.HTTP_PUT
localized.ngx_HTTP_POST = localized.ngx.HTTP_POST
localized.ngx_HTTP_DELETE = localized.ngx.HTTP_DELETE
localized.ngx_HTTP_OPTIONS = localized.ngx.HTTP_OPTIONS
localized.ngx_HTTP_MKCOL = localized.ngx.HTTP_MKCOL
localized.ngx_HTTP_COPY = localized.ngx.HTTP_COPY
localized.ngx_HTTP_MOVE = localized.ngx.HTTP_MOVE
localized.ngx_HTTP_PROPFIND = localized.ngx.HTTP_PROPFIND
localized.ngx_HTTP_PROPPATCH = localized.ngx.HTTP_PROPPATCH
localized.ngx_HTTP_LOCK = localized.ngx.HTTP_LOCK
localized.ngx_HTTP_UNLOCK = localized.ngx.HTTP_UNLOCK
localized.ngx_HTTP_PATCH = localized.ngx.HTTP_PATCH
localized.ngx_HTTP_TRACE = localized.ngx.HTTP_TRACE
--localized.ngx_HTTP_CONNECT = localized.ngx.HTTP_CONNECT --does not exist but put here never know in the future
localized.ngx_OK = localized.ngx.OK --go to content
localized.ngx_var_http_cf_connecting_ip = localized.ngx_var.http_cf_connecting_ip or nil
localized.ngx_var_http_x_forwarded_for = localized.ngx_var.http_x_forwarded_for or nil
localized.ngx_var_remote_addr = localized.ngx_var.remote_addr
localized.ngx_var_binary_remote_addr = localized.ngx_var_remote_addr --set binary to remote for the sake of logs displaying ips
localized.ngx_var_http_user_agent = localized.ngx_var.http_user_agent
localized.ngx_log = localized.ngx.log
-- https://openresty-reference.readthedocs.io/en/latest/Lua_Nginx_API/#nginx-log-level-constants
localized.ngx_LOG_TYPE = localized.ngx.STDERR
localized.ngx_var_connection_requests = localized.ngx_var.connection_requests or 0 --default timeout per connection in nginx is 60 seconds unless you have changed your timeout configs
localized.ngx_var_request_length = localized.ngx_var.request_length or 0
localized.scheme = localized.ngx_var.scheme --scheme is HTTP or HTTPS
localized.host = localized.ngx_var.host --host is website domain name
localized.request_uri = localized.ngx_var.request_uri or "/" --request uri is full URL link including query strings and arguements
localized.URL = localized.scheme .. "://" .. localized.host .. localized.request_uri
localized.user_agent = localized.ngx_var_http_user_agent or "" --user agent of browser
localized.currenttime = localized.ngx_time() --Current time on server
localized.os_time_saved = localized.currenttime-24*60*60
--localized.os_clock = os.clock() --nulled out dev func to test speed
--[[
End localization
]]

--[[
Shared memory cache

If you use this make sure you add this to your nginx configuration

http { #inside http block
	lua_shared_dict antiddos 70m; #Anti-DDoS shared memory zone to track requests per each unique user
	lua_shared_dict antiddos_blocked 70m; #Anti-DDoS shared memory where blocked users are put
	lua_shared_dict ddos_counter 10m; #Anti-DDoS shared memory zone to track total number of blocked users
	lua_shared_dict jspuzzle_tracker 70m; #Anti-DDoS shared memory zone monitors each unique ip and number of times they stack up failing to solve the puzzle
	access_by_lua_file conf/lua/anti_ddos_challenge.lua;
}

]]

localized.anti_ddos_table = {
	{
		".*", --regex match any site / path

		--limit keep alive connections per ip address until timeout
		--the nginx config this is dependant on is keepalive_timeout 75s; https://nginx.org/en/docs/http/ngx_http_core_module.html#keepalive_timeout
		0, --unlimited
		--status code to exit with when to many requests from same ip are made
		--if you are under ddos and want to save bandwidth using localized.ngx_HTTP_CLOSE will save bandwidth.
		localized.ngx_HTTP_TOO_MANY_REQUESTS, --429 too many requests around 175 bytes per response
		--localized.ngx_HTTP_CLOSE, --444 connection reset 0 bytes per response

		--Limit minimum request size to this in bytes requests smaller than this size will be blocked.
		40, --0 for no minimum limit size in bytes including request headers
		--limit max request size to this in bytes so 1000 bytes is 1kb you can do 1e+9 = 1GB Gigabyte for large sizes
		1000000, --0 is unlimited or will fall back to the nginx config value client_max_body_size 1m; https://nginx.org/en/docs/http/ngx_http_core_module.html#client_max_body_size
		--status code to exit with when request size is larger than allowed size
		localized.ngx_HTTP_BAD_REQUEST,

		--enable or disable logging 1 to enable 0 to disable check your .log file to view logs
		1,

		--Rate limiting settings
		5, --5 second window
		60, --max 60 requests in 5s
		86400, --86400 seconds = 24 hour block time for ip flooding
		localized.ngx_HTTP_CLOSE, --444 connection reset 0 bytes per response

		--SlowHTTP / Slowloris settings
		128, --Minimum Content-Length in bytes between 0 and this value requests smaller than this will be blocked Expect: 100-continue
		10, --Request timeout in seconds requests that take longer than this will be blocked
		300, --connections header max timeout value Connection: Timeout=300,Max=1000
		100000, --connections header max conns number
		localized.ngx_HTTP_CLOSE, --444 connection reset 0 bytes per response

		--Range header filter
		0, --0 blacklist 1 whitelist
		{ --Range header protection SlowHTTP / Slowloris have a range header attack option this is useful to protect against that
			--If you set to 0 for blacklist specify each type you want to prevent range headers on like this.
			{"text",}, --block range headers on html/css/js pages
			--{"image",}, --block range headers on images
			--{"application",}, --block range headers on applications
			--{"multipart",}, --block range headers on multipart content
			{ --all types limit
				"", --empty for any type
				10, --Limit occurances block requests with to many 0-5,5-10,10-15,15-30,30-35 multipart/byteranges set to empty string "", to allow any amount
			},

			--[[
			--You can also allow range headers on all content types and block multi segment ranges like this
			{ --0 blacklist for ranges on any type block more than allowed number of segments
				"", --empty for any type
				10, --Limit occurances block requests with to many 0-5,5-10,10-15,15-30,30-35 multipart/byteranges set to empty string "", to allow any amount
				"","",--0,100, --if requesting bytes between 0-100 too small block set to empty string "", to allow any amount
				"", --"bytes", --bytes or set to empty string "", to allow any unit type
				"", --"[a-zA-Z0-9-%,%=%s+]", --valid chars a-z lowercase A-Z uppercase 0-9 - hyphen , comma = equals and spaces
				"",--100, --less than 100 bytes set to empty string "" to skip check
				4e+9, --more than 4GB Gigabyte in bytes set to empty string "" to skip check
				{ --9th as table to do more advanced range header filtering
					{ --1st occurance
						"","",--0,100, --between min - max set to empty string "" to skip min - max check
						90, --less than 90 bytes set to empty string "" to skip check
						"",--20, --more than set to empty string "" to skip check
					},
					"", --skip 2 set to empty string "" to skip occruance
					{ --3rd occurance
						"","", --set to empty string "" to skip min - max check
						"",--90, --less than 90 bytes set to empty string "" to skip check
						20, --more than 20 bytes set to empty string "" to skip check
					},
					"", --skip 4 set to empty string "" to skip occruance
				},
			},
			]]

			--[[
			{ --1 whitelist for video type range headers sent for other types not in the whitelist will be blocked
				"video", --content type for range request set to empty string "", for any content type
				10, --Limit occurances block requests with to many 0-5,5-10,10-15,15-30,30-35 multipart/byteranges set to empty string "", to allow any amount
				0,100, --if requesting bytes between 0-100 too small block set to empty string "", to allow any amount --curl -H "Range: bytes=0-5,5-10,10-15,15-30,30-35" http://localhost/video.mp4 --output "C:\Videos" -H "User-Agent: testagent"
				"bytes", --bytes or set to empty string "", to allow any unit type
				"[a-zA-Z0-9-%,%=%s+]", --valid chars a-z lowercase A-Z uppercase 0-9 - hyphen , comma = equals and spaces
				--100, --less than 100 bytes set to empty string "" to skip check
				--2e+10, --more than 20GB Gigabyte in bytes set to empty string "" to skip check
			},
			]]
		},

		--[[shared memory zones
		To use this feature put this in your nginx config

		lua_shared_dict antiddos 70m; #Anti-DDoS shared memory zone to track requests per each unique user
		lua_shared_dict antiddos_blocked 70m; #Anti-DDoS shared memory where blocked users are put
		lua_shared_dict ddos_counter 10m; #Anti-DDoS shared memory zone to track total number of blocked users
		lua_shared_dict jspuzzle_tracker 70m; #Anti-DDoS shared memory zone monitors each unique ip and number of times they stack up failing to solve the puzzle

		10m can store 160,000 ip addresses so 70m would be able to store around 1,000,000 yes 1 million ips :)
		]]
		localized.ngx.shared.antiddos, --this zone monitors each unique ip and number of requests they stack up
		localized.ngx.shared.antiddos_blocked, --this zone is where ips are put that exceed the max limit
		localized.ngx.shared.ddos_counter, --this zone is for the total number of ips in the list that are currently blocked

		--Unique identifyer to use IP address works well but set this to Auto if you expect proxy traffic like from cloudflare
		--localized.ngx_var_binary_remote_addr, --if you use binary remote addr and the antiddos shared address is 10m in size you can store 160k ip addresses before you need to increase the memory dedicated
		"auto", --auto is best but use binary above instead if you want

		--Automatic I am Under Attack Mode - authentication puzzle to automatically enable when ddos detected
		--1 to enable 0 to disable
		1,

		--total number of ips active in the block list to trigger I am Under Attack Mode and turn the auth puzzle on automatically
		100, --if over 100 ip addresses are currently in the block list for flooding behaviour you are under attack

		{ --headers to block i notice slowloris attacks send this header if your under attack and check your logs and see a header or something all attacker addresses have in common this can be useful to block that.
			{ --slowhttp / slowloris sends this referer header with all requests
				"referer", "http://code.google.com/p/slowhttptest", --header to match
				localized.ngx_HTTP_CLOSE, --close their connection
				1, --1 to add ip to ban list 0 to just send response above close the connection
			}, --slowloris referer header block
			{ --slowhttp / slowloris incase they set it as referrer spelt wrong Intentionally.
				"referrer", "http://code.google.com/p/slowhttptest", --header to match
				localized.ngx_HTTP_CLOSE, --close their connection
				1, --1 to add ip to ban list 0 to just send response above close the connection
			}, --slowloris referrer header block
		},

		{ --Any $request_method that you want to prohibit use this. Most sites legitimate expected request header is GET and POST thats it. Any other header request types you can block.
			{
				"HEAD", --https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods#safe_idempotent_and_cacheable_request_methods
				localized.ngx_HTTP_CLOSE, --close their connection
				1, --1 to add ip to ban list 0 to just send response above close the connection
			},
			{
				"PATCH", --https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods#safe_idempotent_and_cacheable_request_methods
				localized.ngx_HTTP_CLOSE, --close their connection
				1, --1 to add ip to ban list 0 to just send response above close the connection
			},
			{
				"PUT", --https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods#safe_idempotent_and_cacheable_request_methods
				localized.ngx_HTTP_CLOSE, --close their connection
				1, --1 to add ip to ban list 0 to just send response above close the connection
			},
			{
				"DELETE", --https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods#safe_idempotent_and_cacheable_request_methods
				localized.ngx_HTTP_CLOSE, --close their connection
				1, --1 to add ip to ban list 0 to just send response above close the connection
			},
			{
				"CONNECT", --https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods#safe_idempotent_and_cacheable_request_methods
				localized.ngx_HTTP_CLOSE, --close their connection
				1, --1 to add ip to ban list 0 to just send response above close the connection
			},
			{
				"OPTIONS", --https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods#safe_idempotent_and_cacheable_request_methods
				localized.ngx_HTTP_CLOSE, --close their connection
				1, --1 to add ip to ban list 0 to just send response above close the connection
			},
			{
				"TRACE", --https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods#safe_idempotent_and_cacheable_request_methods
				localized.ngx_HTTP_CLOSE, --close their connection
				1, --1 to add ip to ban list 0 to just send response above close the connection
			},
		},

		1, --0 disable compression 1 enable compression brotli,gzip etc for this domain / path if your under ddos attack the script will turn off gzip since nginx gzip will hog cpu so you dont have to worry about that.
		1, --0 disable 1 enable - automatically disable compression for all users if ddos attack detected if more than number of IPs end up in the ban list the server will prevent cpu intensive tasks like compression to stay online.

		--Javascript puzzle flood protection
		--In the event of an attack a user who fails to solve the javascript puzzle after a certain number of times will have their ip blocked
		--lua_shared_dict jspuzzle_tracker 70m; #Anti-DDoS shared memory zone monitors each unique ip and number of times they stack up failing to solve the puzzle
		localized.ngx.shared.jspuzzle_tracker, --this zone monitors each unique ip and number of times they stack up failing to solve the puzzle
		35, --35 second window
		4, --max 4 failures in 35s

		--When a IP is in the blocklist for flooding or attacking to prevent their request even reaching the nginx process you can use this to execute custom scripts or commands on your server to block the ip before it even reaches the nginx process
		--You can do this with linux so anyone who gets blocked will be blocked at the server / router level before they reach your nginx process.
		--Default is nil or "" to not do anything
		nil,
		--[[
		{ --Compaitbility across multiple systems will auto detect if your running windows the script will choose the Windows CMD same for linux, MacOS etc that way you can use the same script via network share or across multiple platforms
			--Windows
			"start cmd /c netsh advfirewall firewall add rule name=\"Block In "..localized.ngx_var_remote_addr.."\" protocol=any dir=in remoteip="..localized.ngx_var_remote_addr.." action=block",
			--Linux
			"iptables -A INPUT -s "..localized.ngx_var_remote_addr.." -j DROP",
			--"./do_something.sh "..localized.ngx_var_remote_addr.."", --run shell script to ban user instead
			--MacOS
			"sudo vim /etc/pf.conf && block drop from any to "..localized.ngx_var_remote_addr.." && sudo pfctl -f /etc/pf.conf && sudo pfctl -e",
		},
		]]

		--Protection from excessive log writes when under attack
		--This depends on the value in your Automatic I am Under Attack Mode setting by default its 100 ips if more than that logging stops i suggest leave at default
		1, --0 will continue to log 1 disable writting to log file when under attack to prevent disk I/O usage denial of service

	},
}

--[[
This is the equivilant of proxy_cache or fastcgi_cache Just better.
lua_shared_dict html_cache 10m; #HTML pages cache
lua_shared_dict mp4_cache 300m; #video mp4 cache

as a example with php you can do this and STATIC pages ARE cached and DYNAMIC content for logged in users will NOT be cached.
<?php

//Just change the code for your CMS / APP Joomla / Drupal etc have plenty of examples.
if($user->guest = 1){
//User in not logged in is a guest
$cookie_name = "logged_in";
$cookie_value = "0";
setcookie($cookie_name, $cookie_value, time() + (86400 * 30), "/"); // 86400 = 1 day
}
else
{
//User is logged in
$cookie_name = "logged_in";
$cookie_value = "1";
setcookie($cookie_name, $cookie_value, time() + (86400 * 30), "/"); // 86400 = 1 day
}
?>
]]
localized.content_cache = {
	--[[
	{
		".*", --regex match any site / path
		"text/html", --content-type valid types are text to match all text formats or text/css text/javascript etc
		--lua_shared_dict html_cache 10m; #HTML pages cache
		localized.ngx.shared.html_cache, --shared cache zone to use or empty string to not use "" lua_shared_dict html_cache 10m; #HTML pages cache
		60, --ttl for cache or ""
		1, --enable logging 1 to enable 0 to disable
		{200,206,}, --response status codes to cache
		{"GET",}, --request method to cache
		{ --bypass cache on cookie use nil or empty string "" to not bypass on cookies
			{
				".*", --cookie name regex ".*" for any cookie
				".*", --cookie value ".*" for any value
				0, --0 guest user cache only 1 both guest and logged in user cache useful if logged_in cookie is present then cache key will include cookies
			},
			--{"logged_in","1",0,},
		}, --bypass cache on cookie
		{"/login.html","/administrator","/admin*.$",}, --bypass cache urls use nil or empty string "" to not bypass on urls
		1, --Send cache status header X-Cache-Status: HIT, X-Cache-Status: MISS
		1, --if serving from cache or updating cache page remove cookie headers (for dynamic sites you should do this to stay as guest only cookie headers will be sent on bypass pages)
		localized.request_uri, --url to use you can do "/index.html", as an example localized.request_uri is best.
		false, --true to use lua resty.http library if exist if you set this to true you can change localized.request_uri above to "https://www.google.com/", as an example.
		{ --Content Modifier Modification/Minification / Minify HTML output
			--Usage :
			--Regex, Replacement
			--Text, Replacement
			--You can use this to alter contents of the page output.
			--Example :
			--{"replace me", " with me! ",},
			--{"</head>", "<script type='text/javascript' src='../jquery.min.js'></script></head>",} --inject javascript into html page
			--{"<!--[^>]-->", "",}, --remove nulled out html example !! I DO NOT RECOMMEND REMOVING COMMENTS, THIS COULD BREAK YOUR ENTIRE WEBSITE FOR OLD BROWSERS, BE AWARE
			--{"(//[^.*]*.\n)", "",}, -- Example: this //will remove //comments (result: this remove)
			--{"(/%*[^*]*%*/)", "",}, -- Example: this /*will*/ remove /*comments*/ (result: this remove)
			--{"<style>(.*)%/%*(.*)%*%/(.*)</style>", "<style>%1%3</style>",},
			--{"<script>(.*)%/%*(.*)%*%/(.*)</script>", "<script>%1%3</script>",},
			--{"[ \t]+$", "",}, --remove break lines (execution order of regex matters keep this last)
			--{"<!%-%-[^%[]-->", "",},
			--{"%s%s+", " ",},
			--{"\n\n*", " ",},
			--{"\n*$", ""},
		},
		"", --1e+6, --Maximum content size to cache in bytes 1e+6 = 1MB content larger than this wont be cached empty string "" to skip
		"", --Minimum content size to cache in bytes content smaller than this wont be cached empty string "" to skip
		{"content-type","content-range","content-length","etag","last-modified","set-cookie",}, --headers you can use this to specify what headers you want to keep on your cache HIT/UPDATING output
		--Request header forwarding / overrides :
		--the way ngx.location.capture works with request headers is it forwards your browser request headers to the ngx.location you can remove them using a table by setting the request header from your browser to nil
		--you can over ride your browsers request headers being sent to the backend using a table any headers your browser sends that is not specified in the table will not be overridden and will still go to the ngx location as is.
		--nil,--nil or empty table to use browsers request headers
		{ --override browsers request headers
			--["Content-Type"] = "application/x-www-form-urlencoded", --add this header to request being sent to backend
			--["Accept"] = localized.ngx_req_get_headers()["Accept"], --override this header being sent with the contents of browsers accept value
			--["host"] = "www.google.com", --override this header to request being sent to backend
			--["priority"] = "", --remove this header from the request being sent to the backened
		},
	},
	{
		".*", --regex match any site / path
		"video/mp4", --content-type valid types are video to match all video formats or video/mp4 video/webm etc
		--lua_shared_dict mp4_cache 300m; #video mp4 cache
		localized.ngx.shared.mp4_cache, --shared cache zone to use or empty string to not use "" lua_shared_dict mp4_cache 300m; #video mp4 cache
		60, --ttl for cache or ""
		1, --enable logging 1 to enable 0 to disable
		{200,206,}, --response status codes to cache
		{"GET",}, --request method to cache
		"", --nil or empty string "" to not bypass on cookies
		"", --nil or empty string "" to not bypass on urls
		1, --Send cache status header X-Cache-Status: HIT, X-Cache-Status: MISS
		1, --if serving from cache or updating cache page remove cookie headers (for dynamic sites you should do this to stay as guest only cookie headers will be sent on bypass pages)
		localized.request_uri, --url to use you can do "/index.html", as an example localized.request_uri is best.
		false, --true to use lua resty.http library if exist if you set this to true you can change localized.request_uri above to "https://www.google.com/", as an example.
		"", --content modified not needed for this format
		4e+7, --Maximum content size to cache in bytes 1e+6 = 1MB, 1e+7 = 10MB, 1e+8 = 100MB, 1e+9 = 1GB content larger than this wont be cached empty string "" to skip
		200000, --200kb --Minimum content size to cache in bytes content smaller than this wont be cached empty string "" to skip
		{"content-type","content-range","content-length","etag","last-modified","set-cookie",}, --headers you can use this to specify what headers you want to keep on your cache HIT/UPDATING output
		--Request header forwarding / overrides :
		--the way ngx.location.capture works with request headers is it forwards your browser request headers to the ngx.location you can remove them using a table by setting the request header from your browser to nil
		--you can over ride your browsers request headers being sent to the backend using a table any headers your browser sends that is not specified in the table will not be overridden and will still go to the ngx location as is.
		--nil,--nil or empty table to use browsers request headers
		{ --override browsers request headers
			--["Content-Type"] = "application/x-www-form-urlencoded", --add this header to request being sent to backend
			--["Accept"] = localized.ngx_req_get_headers()["Accept"], --override this header being sent with the contents of browsers accept value
			--["host"] = "www.google.com", --override this header to request being sent to backend
			--["priority"] = "", --remove this header from the request being sent to the backened
		},
	},
	{
		".*", --regex match any site / path
		"image", --content-type for image/png image/jpeg image/x-icon etc
		--lua_shared_dict image_cache 300m; #image cache
		localized.ngx.shared.image_cache, --shared cache zone to use or empty string to not use "" lua_shared_dict image_cache 300m; #image cache
		60, --ttl for cache or ""
		1, --enable logging 1 to enable 0 to disable
		{200,206,}, --response status codes to cache
		{"GET",}, --request method to cache
		nil, --nil or empty string "" to not bypass on cookies
		nil, --nil or empty string "" to not bypass on urls
		1, --Send cache status header X-Cache-Status: HIT, X-Cache-Status: MISS
		1, --if serving from cache or updating cache page remove cookie headers (for dynamic sites you should do this to stay as guest only cookie headers will be sent on bypass pages)
		localized.request_uri, --url to use you can do "/index.html", as an example localized.request_uri is best.
		false, --true to use lua resty.http library if exist if you set this to true you can change localized.request_uri above to "https://www.google.com/", as an example.
		"", --content modified not needed for this format
		"", --Maximum content size to cache in bytes 1e+6 = 1MB, 1e+7 = 10MB, 1e+8 = 100MB, 1e+9 = 1GB content larger than this wont be cached empty string "" to skip
		"", --200kb --Minimum content size to cache in bytes content smaller than this wont be cached empty string "" to skip
		{"content-type","content-range","content-length","etag","last-modified","set-cookie",}, --headers you can use this to specify what headers you want to keep on your cache HIT/UPDATING output
		--Request header forwarding / overrides :
		--the way ngx.location.capture works with request headers is it forwards your browser request headers to the ngx.location you can remove them using a table by setting the request header from your browser to nil
		--you can over ride your browsers request headers being sent to the backend using a table any headers your browser sends that is not specified in the table will not be overridden and will still go to the ngx location as is.
		--nil,--nil or empty table to use browsers request headers
		{ --override browsers request headers
			--["Content-Type"] = "application/x-www-form-urlencoded", --add this header to request being sent to backend
			--["Accept"] = localized.ngx_req_get_headers()["Accept"], --override this header being sent with the contents of browsers accept value
			--["host"] = "www.google.com", --override this header to request being sent to backend
			--["priority"] = "", --remove this header from the request being sent to the backened
		},
	},
	]]
}

--[[
This is a password that encrypts our puzzle and cookies unique to your sites and servers you should change this from the default.
]]
localized.secret = " enigma" --Signature secret key --CHANGE ME FROM DEFAULT!

--[[
Unique id to identify each individual user and machine trying to access your website IP address works well.

localized.ngx_var_http_cf_connecting_ip --If you proxy your traffic through cloudflare use this
localized.ngx_var_http_x_forwarded_for --If your traffic is proxied through another server / service.
localized.ngx_var_remote_addr --Users IP address
localized.ngx_var_http_user_agent or "" --User-Agent

You can combine multiple if you like. You can do so like this.
localized.remote_addr = localized.ngx_var_remote_addr .. localized.ngx_var_http_user_agent or ""

remote_addr = "tor" this will mean this script will be functioning for tor users only
remote_addr = "auto" the script will automatically get the clients IP this is the default it is the smartest and most compatible method with every service proxy etc
]]
localized.remote_addr = "auto" --Default Automatically get the Clients IP address

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
localized.expire_time = 86400 --One day

--[[
The type of javascript based pingback authentication method to use if it should be GET or POST or can switch between both making it as dynamic as possible.
1 = GET
2 = POST
3 = DYNAMIC
]]
localized.javascript_REQUEST_TYPE = 2 --Default 2

--[[
Timer to refresh auth page
Time is in seconds only.
]]
localized.refresh_auth = 5

--[[
Javascript variable checks
These custom javascript checks are to prevent our authentication javascript puzzle / question being solved by the browser if the browser is a fake ghost browser / bot etc.
Only if the web browser does not trigger any of these or does not match conditions defined will the browser solve the authentication request.
]]
localized.JavascriptVars_opening = [[
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
localized.JavascriptVars_closing = [[
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
X-Auth-Header to be static or Dynamic setting this as dynamic is the best form of security
1 = Static
2 = Dynamic
]]
localized.x_auth_header = 2 --Default 2
localized.x_auth_header_name = "x-auth-answer" --the header our server will expect the client to send us with the javascript answer this will change if you set the config as dynamic

--[[
Cookie Anti-DDos names
]]
localized.challenge = "__uip" --this is the first main unique identification of our cookie name
localized.cookie_name_start_date = localized.challenge.."_start_date" --our cookie start date name of our firewall
localized.cookie_name_end_date = localized.challenge.."_end_date" --our cookie end date name of our firewall
localized.cookie_name_encrypted_start_and_end_date = localized.challenge.."_combination" --our cookie challenge unique id name

--[[
Anti-DDoS Cookies to be Encrypted for better security
1 = Cookie names will be plain text above
2 = Encrypted cookie names unique to each individual client/user
]]
localized.encrypt_anti_ddos_cookies = 2 --Default 2

--[[
Encrypt/Obfuscate Javascript output to prevent content scrappers and bots decrypting it to try and bypass the browser auth checks. Wouldn't want to make life to easy for them now would I.
0 = Random Encryption Best form of security and default
1 = No encryption / Obfuscation
2 = Base64 Data URI only
3 = Hex encryption
4 = Base64 Javascript Encryption
5 = Conor Mcknight's Javascript Scrambler (Obfuscate Javascript by putting it into vars and shuffling them like a deck of cards)
]]
localized.encrypt_javascript_output = 0

--[[
IP Address Whitelist
Any IP Addresses specified here will be whitelisted to grant direct access to your site bypassing our browser Authentication checks
you can specify IP's like search engine crawler ip addresses here most search engines are smart enough they do not need to be specified,
Major search engines can execute javascript such as Google, Yandex, Bing, Baidu and such so they can solve the auth page puzzle and index your site same as how companies like Cloudflare, Succuri, BitMitigate etc work and your site is still indexed.
Supports IPv4 and IPv6 addresses aswell as subnet ranges
To find all IP ranges of an ASN use : https://www.enjen.net/asn-blocklist/index.php?asn=16509&type=iplist
]]
localized.ip_whitelist_remote_addr = "auto" --Automatically get the Clients IP address
--localized.ip_whitelist_remote_addr = localized.ngx_var_remote_addr
localized.ip_whitelist_block_mode = 0 --0 whitelist acts as a bypass to puzzle auth checks 1 is to enforce only allowing whitelisted addresses access other addresses will be blocked.
localized.ip_whitelist_bypass_flood_protection = 1 --0 IP's in whitelist can still be banned / blocked for DDoS flooding behaviour 1 IP's bypass the flood detection
localized.ip_whitelist = {
"127.0.0.0",
"127.0.0.1",
"127.0.0.2",
"::",
"::1",
"::2",
--IPV4 Local addresses ranges
"10.0.0.0/8", --localnetwork
"172.16.0.0/12", --localnetwork
"127.0.0.0/16", --localhost
"192.168.0.0/16", --localhost
--IPV6 Local addresses ranges
"::/128", --unspecified address = "::"
"::1/128", --localhost = http://[::1]:80/index.html
--"fc00::/8", --centrally assigned by unkown, routed within a site (RFC 4193)
--"fd00::/8", --free for all, global ID must be generated randomly with pseudo-random algorithm, routed within a site (RFC 4193)
--"ff00::/8", --multicast, following after the prefix ff there are 4 bits for flags and 4 bits for the scope
--"::ffff:0:0/96", --IPv4 to IPv6 Address, eg: ::ffff:10.10.10.10 (RFC 4038)
--"2001::/16", -- /32 subnets assigned to providers, they assign /48, /56 or /64 to the customer
"2001:db8::/32", --reserved for use in documentation
--"2002::/16", --6to4 scope, 2002:c058:6301:: is the 6to4 public router anycast (RFC 3068)
--https://developers.google.com/search/apis/ipranges/googlebot.json Google Bot Search engine crawler IP's
--"2001:4860:4801:10::/64","2001:4860:4801:12::/64","2001:4860:4801:13::/64","2001:4860:4801:14::/64","2001:4860:4801:15::/64","2001:4860:4801:16::/64","2001:4860:4801:17::/64","2001:4860:4801:18::/64","2001:4860:4801:19::/64","2001:4860:4801:1a::/64","2001:4860:4801:1b::/64","2001:4860:4801:1c::/64","2001:4860:4801:1d::/64","2001:4860:4801:1e::/64","2001:4860:4801:1f::/64","2001:4860:4801:20::/64","2001:4860:4801:21::/64","2001:4860:4801:22::/64","2001:4860:4801:23::/64","2001:4860:4801:24::/64","2001:4860:4801:25::/64","2001:4860:4801:26::/64","2001:4860:4801:27::/64","2001:4860:4801:28::/64","2001:4860:4801:29::/64","2001:4860:4801:2::/64","2001:4860:4801:2a::/64","2001:4860:4801:2b::/64","2001:4860:4801:2c::/64","2001:4860:4801:2d::/64","2001:4860:4801:2e::/64","2001:4860:4801:2f::/64","2001:4860:4801:30::/64","2001:4860:4801:31::/64","2001:4860:4801:32::/64","2001:4860:4801:33::/64","2001:4860:4801:34::/64","2001:4860:4801:35::/64","2001:4860:4801:36::/64","2001:4860:4801:37::/64","2001:4860:4801:38::/64","2001:4860:4801:39::/64","2001:4860:4801:3a::/64","2001:4860:4801:3b::/64","2001:4860:4801:3c::/64","2001:4860:4801:3d::/64","2001:4860:4801:3e::/64","2001:4860:4801:3f::/64","2001:4860:4801:40::/64","2001:4860:4801:41::/64","2001:4860:4801:42::/64","2001:4860:4801:43::/64","2001:4860:4801:44::/64","2001:4860:4801:45::/64","2001:4860:4801:46::/64","2001:4860:4801:47::/64","2001:4860:4801:48::/64","2001:4860:4801:49::/64","2001:4860:4801:4a::/64","2001:4860:4801:4b::/64","2001:4860:4801:4c::/64","2001:4860:4801:4d::/64","2001:4860:4801:4e::/64","2001:4860:4801:50::/64","2001:4860:4801:51::/64","2001:4860:4801:52::/64","2001:4860:4801:53::/64","2001:4860:4801:54::/64","2001:4860:4801:55::/64","2001:4860:4801:56::/64","2001:4860:4801:57::/64","2001:4860:4801:58::/64","2001:4860:4801:60::/64","2001:4860:4801:61::/64","2001:4860:4801:62::/64","2001:4860:4801:63::/64","2001:4860:4801:64::/64","2001:4860:4801:65::/64","2001:4860:4801:66::/64","2001:4860:4801:67::/64","2001:4860:4801:68::/64","2001:4860:4801:69::/64","2001:4860:4801:6a::/64","2001:4860:4801:6b::/64","2001:4860:4801:6c::/64","2001:4860:4801:6d::/64","2001:4860:4801:6e::/64","2001:4860:4801:6f::/64","2001:4860:4801:70::/64","2001:4860:4801:71::/64","2001:4860:4801:72::/64","2001:4860:4801:73::/64","2001:4860:4801:74::/64","2001:4860:4801:75::/64","2001:4860:4801:76::/64","2001:4860:4801:77::/64","2001:4860:4801:78::/64","2001:4860:4801:79::/64","2001:4860:4801:7a::/64","2001:4860:4801:7b::/64","2001:4860:4801:7c::/64","2001:4860:4801:7d::/64","2001:4860:4801:80::/64","2001:4860:4801:81::/64","2001:4860:4801:82::/64","2001:4860:4801:83::/64","2001:4860:4801:84::/64","2001:4860:4801:85::/64","2001:4860:4801:86::/64","2001:4860:4801:87::/64","2001:4860:4801:88::/64","2001:4860:4801:90::/64","2001:4860:4801:91::/64","2001:4860:4801:92::/64","2001:4860:4801:93::/64","2001:4860:4801:94::/64","2001:4860:4801:95::/64","2001:4860:4801:96::/64","2001:4860:4801:97::/64","2001:4860:4801:a0::/64","2001:4860:4801:a1::/64","2001:4860:4801:a2::/64","2001:4860:4801:a3::/64","2001:4860:4801:a4::/64","2001:4860:4801:a5::/64","2001:4860:4801:a6::/64","2001:4860:4801:a7::/64","2001:4860:4801:a8::/64","2001:4860:4801:a9::/64","2001:4860:4801:aa::/64","2001:4860:4801:ab::/64","2001:4860:4801:ac::/64","2001:4860:4801:ad::/64","2001:4860:4801:ae::/64","2001:4860:4801:b0::/64","2001:4860:4801:b1::/64","2001:4860:4801:b2::/64","2001:4860:4801:b3::/64","2001:4860:4801:b4::/64","2001:4860:4801:b5::/64","2001:4860:4801:c::/64","2001:4860:4801:f::/64","192.178.4.0/27","192.178.4.128/27","192.178.4.160/27","192.178.4.192/27","192.178.4.32/27","192.178.4.64/27","192.178.4.96/27","192.178.5.0/27","192.178.6.0/27","192.178.6.128/27","192.178.6.160/27","192.178.6.192/27","192.178.6.224/27","192.178.6.32/27","192.178.6.64/27","192.178.6.96/27","192.178.7.0/27","192.178.7.128/27","192.178.7.160/27","192.178.7.192/27","192.178.7.224/27","192.178.7.32/27","192.178.7.64/27","192.178.7.96/27","34.100.182.96/28","34.101.50.144/28","34.118.254.0/28","34.118.66.0/28","34.126.178.96/28","34.146.150.144/28","34.147.110.144/28","34.151.74.144/28","34.152.50.64/28","34.154.114.144/28","34.155.98.32/28","34.165.18.176/28","34.175.160.64/28","34.176.130.16/28","34.22.85.0/27","34.64.82.64/28","34.65.242.112/28","34.80.50.80/28","34.88.194.0/28","34.89.10.80/28","34.89.198.80/28","34.96.162.48/28","35.247.243.240/28","66.249.64.0/27","66.249.64.128/27","66.249.64.160/27","66.249.64.192/27","66.249.64.224/27","66.249.64.32/27","66.249.64.64/27","66.249.64.96/27","66.249.65.0/27","66.249.65.128/27","66.249.65.160/27","66.249.65.192/27","66.249.65.224/27","66.249.65.32/27","66.249.65.64/27","66.249.65.96/27","66.249.66.0/27","66.249.66.128/27","66.249.66.160/27","66.249.66.192/27","66.249.66.224/27","66.249.66.32/27","66.249.66.64/27","66.249.66.96/27","66.249.67.0/27","66.249.67.32/27","66.249.68.0/27","66.249.68.128/27","66.249.68.160/27","66.249.68.192/27","66.249.68.32/27","66.249.68.64/27","66.249.68.96/27","66.249.69.0/27","66.249.69.128/27","66.249.69.160/27","66.249.69.192/27","66.249.69.224/27","66.249.69.32/27","66.249.69.64/27","66.249.69.96/27","66.249.70.0/27","66.249.70.128/27","66.249.70.160/27","66.249.70.192/27","66.249.70.224/27","66.249.70.32/27","66.249.70.64/27","66.249.70.96/27","66.249.71.0/27","66.249.71.128/27","66.249.71.160/27","66.249.71.192/27","66.249.71.224/27","66.249.71.32/27","66.249.71.64/27","66.249.71.96/27","66.249.72.0/27","66.249.72.128/27","66.249.72.160/27","66.249.72.192/27","66.249.72.224/27","66.249.72.32/27","66.249.72.64/27","66.249.73.0/27","66.249.73.128/27","66.249.73.160/27","66.249.73.192/27","66.249.73.224/27","66.249.73.32/27","66.249.73.64/27","66.249.73.96/27","66.249.74.0/27","66.249.74.128/27","66.249.74.160/27","66.249.74.192/27","66.249.74.224/27","66.249.74.32/27","66.249.74.64/27","66.249.74.96/27","66.249.75.0/27","66.249.75.128/27","66.249.75.160/27","66.249.75.192/27","66.249.75.224/27","66.249.75.32/27","66.249.75.64/27","66.249.75.96/27","66.249.76.0/27","66.249.76.128/27","66.249.76.160/27","66.249.76.192/27","66.249.76.224/27","66.249.76.32/27","66.249.76.64/27","66.249.76.96/27","66.249.77.0/27","66.249.77.128/27","66.249.77.160/27","66.249.77.192/27","66.249.77.224/27","66.249.77.32/27","66.249.77.64/27","66.249.77.96/27","66.249.78.0/27","66.249.78.128/27","66.249.78.160/27","66.249.78.32/27","66.249.78.64/27","66.249.78.96/27","66.249.79.0/27","66.249.79.128/27","66.249.79.160/27","66.249.79.192/27","66.249.79.224/27","66.249.79.32/27","66.249.79.64/27","66.249.79.96/27",
--https://www.bing.com/toolbox/bingbot.json Bing Bots Search engine crawler IP's
--"157.55.39.0/24","207.46.13.0/24","40.77.167.0/24","13.66.139.0/24","13.66.144.0/24","52.167.144.0/24","13.67.10.16/28","13.69.66.240/28","13.71.172.224/28","139.217.52.0/28","191.233.204.224/28","20.36.108.32/28","20.43.120.16/28","40.79.131.208/28","40.79.186.176/28","52.231.148.0/28","20.79.107.240/28","51.105.67.0/28","20.125.163.80/28","40.77.188.0/22","65.55.210.0/24","199.30.24.0/23","40.77.202.0/24","40.77.139.0/25","20.74.197.0/28","20.15.133.160/27","40.77.177.0/24","40.77.178.0/23",
--Cloudflare IP's https://www.cloudflare.com/en-gb/ips/ set block mode to 1 and localized.ip_whitelist_remote_addr = localized.ngx_var_remote_addr to block all ips other than cloudflare from direct access to your server/sites.
"173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22","2400:cb00::/32","2606:4700::/32","2803:f800::/32","2405:b500::/32","2405:8100::/32","2a06:98c0::/29","2c0f:f248::/32",
--https://duckduckgo.com/duckduckbot.json
--https://duckduckgo.com/duckassistbot.json
--https://index.commoncrawl.org/ccbot.json
--https://search.developer.apple.com/applebot.json
--Full list https://search-engine-ip-tracker.merj.com/status
}

--[[
IP Address Blacklist
To block access to any abusive IP's that you do not want to ever access your website
Supports IPv4 and IPv6 addresses aswell as subnet ranges
To find all IP ranges of an ASN use : https://www.enjen.net/asn-blocklist/index.php?asn=16276&type=iplist
For the worst Botnet ASN IP's see here : https://www.spamhaus.org/statistics/botnet-asn/ You can add their IP addresses. https://www.abuseat.org/public/asninfections.html
]]
localized.ip_blacklist_remote_addr = "auto" --Automatically get the Clients IP address
localized.ip_blacklist = {
--"1.3.3.7", --Examples here : https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/wiki/configuration#ip-address-blacklist
}

--[[
Allow or block all Tor users
1 = Allow
2 = block
]]
localized.tor = 1 --Allow Tor Users

--[[
Unique ID to identify each individual Tor user who connects to the website
Using their User-Agent as a static variable to latch onto works well.
localized.tor_remote_addr = localized.ngx_var_remote_addr .. localized.os_date("%W",localized.os_time_saved) .. localized.ngx_var_http_user_agent or "" --Tor / Onion users can use this if you dont like the "auto" behaviour
]]
--localized.tor_remote_addr = "auto"
localized.tor_remote_addr = localized.ngx_var_remote_addr .. localized.os_date("%W",localized.os_time_saved) .. localized.ngx_var_http_user_agent or ""

--[[
X-Tor-Header to be static or Dynamic setting this as dynamic is the best form of security
1 = Static
2 = Dynamic
]]
localized.x_tor_header = 2 --Default 2
localized.x_tor_header_name = "x-tor" --tor header name
localized.x_tor_header_name_allowed = "true" --tor header value when we want to allow access
localized.x_tor_header_name_blocked = "blocked" --tor header value when we want to block access

--[[
Tor Cookie values
]]
localized.cookie_tor = localized.challenge.."_tor" --our tor cookie
localized.cookie_tor_value_allow = "allow" --the value of the cookie when we allow access
localized.cookie_tor_value_block = "deny" --the value of the cookie when we block access

--[[
TODO:
Google ReCaptcha
]]

--[[
Charset output of HTML page and scripts
]]
localized.default_charset = "utf-8"

--[[
Enable/disable script this feature allows you to turn on or off this script so you can leave this file in your nginx configuration permamently.

This way you don't have to remove access_by_lua_file anti_ddos_challenge.lua; to stop protecting your websites :) you can set up your nginx config and use this feature to enable or disable protection

1 = enabled (Enabled Anti-DDoS authentication on all sites and paths)
2 = disabled (Won't show anywhere)
3 = custom (Will enable script on sites / URL paths and disable it on those specified)
]]
localized.master_switch = 1 --enabled by default

--[[
This feature is if you set "localized.master_switch = 3" what this does is if you host multiple websites / services of one server / machine you can have this script disabled for all those websites / domain names other than those you specifiy.
For example you set localized.master_switch to 3 and specifiy ".onion" then all Tor websites you host on your server will be protected by this script while the rest of the websites you host will not be authenticated. (pretty clever huh)
You can also specify full domain names like "github.com" to protect specific domains you can add as many as you like.

1 = run auth checks
2 = bypass auth checks
]]
localized.master_switch_custom_hosts = {
	--[[
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
localized.credits = 1 --enabled by default

--[[
Javascript variables generated by the script to be static in length or Dynamic setting this as dynamic is the best form of security

1 = Static
2 = Dynamic
]]
localized.dynamic_javascript_vars_length = 2 --dynamic default
localized.dynamic_javascript_vars_length_static = 10 --how many chars in length should static be
-- IMPORTANT: Should probably increase this min value to exclude repeating variable names which can break some obfuscations (tested it once), up to the developer.
localized.dynamic_javascript_vars_length_start = 3 --for dynamic randomize min value to max this is min value 
localized.dynamic_javascript_vars_length_end = 10 --for dynamic randomize min value to max this is max value

--[[
User-Agent Blacklist
If you want to block access to bad bots / specific user-agents you can use this.
1 = case insensative
2 = case sensative
3 = regex case sensative
4 = regex lower case insensative

I added some examples of bad bots to block access to.
]]
localized.user_agent_blacklist_table = {
	{
		"^%s*$",
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
	{ -- Block AI bots / tools that steal and content scrape
		"ChatGPT",
		1,
	},
	{
		"GPTBot",
		1,
	},
	{
		"Deepseek",
		1,
	},
	{
		"OAI-",
		1,
	},
	{
		"AI2Bot",
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
localized.user_agent_whitelist_table = {
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
	{
		"googlebot",
		1,
	},
]]
}

--[[
Authorization Required Box Restricted Access Field
This will NOT use Javascript to authenticate users trying to access your site instead it will use a username and password that can be static or dynamic to grant users access
0 = Disabled
1 = Enabled Browser Sessions (You will see the box again when you restart browser)
2 = Enabled Cookie session (You won't see the box again until the localized.expire_time you set passes)
]]
localized.authorization = 0

--[[
authorization domains / file paths to protect / restrict access to

1 = Allow showing auth box on matching path(s)
2 = Disallow Showing box matching path(s)

Regex matching file path (.*) will match any

If we should show the client seeing the box what login they can use (Tor websites do this what is why i made this a feature)
0 = Don't display login details
1 = Display login details
]]
localized.authorization_paths = {
	--[[
	{
		1, --show auth box on this path
		"localhost.*/ddos.*", --regex paths i recommend having the domain in there too
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
	]]
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
localized.authorization_dynamic = 0 --Static will use list
localized.authorization_dynamic_length = 5 --max length of our dynamic generated username and password

--[[
Auth box Message
]]
localized.authorization_message = "Restricted Area " --Message to be displayed with box
localized.authorization_username_message = "Your username is :" --Message to show username
localized.authorization_password_message = "Your password is :" --Message to show password

localized.authorization_logins = { --static password list
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
localized.authorization_cookie = localized.challenge.."_authorization" --our authorization cookie

--[[
WAF Web Application Firewall Filter for Post requests

This feature allows you to intercept incomming client POST data read their POST data and filter out any unwanted code junk etc and block their POST request.

Highly usefull for protecting your web application and backends from attacks zero day exploits and hacking attempts from hackers and bots.
]]
localized.WAF_POST_Request_table = {
--[[
	{
		"^task$", --match post data in requests with value task
		".*", --matching any
	},
	{
		"^name3$", --regex match
		"^.*$", --regex or exact match
	},
]]
}

--[[
WAF Web Application Firewall Filter for Headers in requests

You can use this to block exploits in request headers such as malicious cookies clients try to send

Header exploits in requests they might send such as SQL info to inject into sites highly useful for blocking SQLi and many other attack types
]]
localized.WAF_Header_Request_table = {
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
localized.WAF_query_string_Request_table = {
	--[[
		PHP easter egg exploit blocking
		[server with expose_php = on]
		.php?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000
		.php?=PHPE9568F34-D428-11d2-A769-00AA001ACF42
		.php?=PHPE9568F35-D428-11d2-A769-00AA001ACF42
		.php?=PHPE9568F36-D428-11d2-A769-00AA001ACF42
	]]
	--[[
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
	]]
	--[[
		File injection protection
	]]
	--[[
	{
		"[a-zA-Z0-9_]", --regex match name
		"http%:%/%/", --regex or exact match value
	},
	{
		"[a-zA-Z0-9_]", --regex match name
		"https%:%/%/", --regex or exact match value
	},
	]]
	--[[
		SQLi SQL Injections
	]]
	--[[
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
	]]
}

--[[
WAF Web Application Firewall Filter for URL Paths in requests

You can use this to protect server configuration files / paths and sensative material on sites
]]
localized.WAF_URI_Request_table = {
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
localized.query_string_sort_table = {
	{
		".*", --regex match any site / path
		1, --enable
	},
	--[[
	{
		"domain.com/.*", --regex match this domain
		1, --enable
	},
	]]
}

--[[
Query String Expected arguments Whitelist only

So this is useful for those who know what URL arguments their sites use and want to whitelist those ONLY so any other arguments provided in the URL never reach the backend or web application and are dropped from the URL.
]]
localized.query_string_expected_args_only_table = {
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
	--[[
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
	]]
}

--[[
Query String Remove arguments

To remove Query strings that bypass the cache Intentionally Facebook and Google is the biggest culprit in this. It is commonly known as Cache Busting.

Traffic to your site from facebook Posts / Shares the URL's will all contain this .com/index.html?fbclid=blah-blah-blah
]]
localized.query_string_remove_args_table = {
	--[[
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
	]]
}

--[[
Security feature to prevent spoofing on the Proxy headers CF-Connecting-IP or X-forwarded-for user-agent.
For example a smart DDoS attack will send a fake CF-Connecting-IP header or X-Forwarded-For header in their request
They do this to see if your server will use their real ip or the fake header they provide to you most servers do not even check this I do :)
Add your ip ranges to the list of who you expect to send you a proxy header.
Example to test with : curl.exe "http://localhost/" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Accept-Language: en-GB,en;q=0.5" -H "Accept-Encoding: gzip, deflate, br, zstd" -H "DNT: 1" -H "Connection: keep-alive" -H "Cookie: name1=1; name2=2; logged_in=1" -H "Upgrade-Insecure-Requests: 1" -H "Sec-Fetch-Dest: document" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: none" -H "Sec-Fetch-User: ?1" -H "Priority: u=0, i" -H "Pragma: no-cache" -H "Cache-Control: no-cache" -H "User-Agent:testagent1" -H "CF-Connecting-IP: 1" -H "X-Forwarded-For: 1" -H "internal:1"
]]
localized.proxy_header_table = {
"127.0.0.0",
"127.0.0.1",
"127.0.0.2",
"::",
"::1",
"::2",
--IPV4 Local addresses ranges
"10.0.0.0/8", --localnetwork
"172.16.0.0/12", --localnetwork
"127.0.0.0/16", --localhost
"192.168.0.0/16", --localhost
--IPV6 Local addresses ranges
"::/128", --unspecified address = "::"
"::1/128", --localhost = http://[::1]:80/index.html
--"fc00::/8", --centrally assigned by unkown, routed within a site (RFC 4193)
--"fd00::/8", --free for all, global ID must be generated randomly with pseudo-random algorithm, routed within a site (RFC 4193)
--"ff00::/8", --multicast, following after the prefix ff there are 4 bits for flags and 4 bits for the scope
--"::ffff:0:0/96", --IPv4 to IPv6 Address, eg: ::ffff:10.10.10.10 (RFC 4038)
--"2001::/16", -- /32 subnets assigned to providers, they assign /48, /56 or /64 to the customer
"2001:db8::/32", --reserved for use in documentation
--"2002::/16", --6to4 scope, 2002:c058:6301:: is the 6to4 public router anycast (RFC 3068)
--Cloudflare IP's https://www.cloudflare.com/en-gb/ips/
"173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22","2400:cb00::/32","2606:4700::/32","2803:f800::/32","2405:b500::/32","2405:8100::/32","2a06:98c0::/29","2c0f:f248::/32",
}

--[[
To restore original visitor IP addresses at your origin web server this will send a request header to your backend application or proxy containing the clients real IP address
]]
localized.send_ip_to_backend_custom_headers = {
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
localized.custom_headers = {
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
	--[[
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
	]]
}

--[[
Logging of users ip address
This can be useful if you use fail2ban or banip that will read your log files
for users who lets say fail to solve the puzzle multiple times within minutes or hours you can ban those ip addresses since you know they are bots.
by default nginx syslog would be error.log file you can change the log type via `localized.ngx_LOG_TYPE =` variable

0 = Disable logging
1 = Enable logging
]]
localized.log_users_on_puzzle = 0
localized.log_on_puzzle_text_start = "[Deny] IP : "
localized.log_on_puzzle_text_end = " - Attempting to solve Auth puzzle"


localized.log_users_granted_access = 0
localized.log_on_granted_text_start = "[Grant] IP : "
localized.log_on_granted_text_end = " - Solved the puzzle"

--[[
useful for developers who do not want to trigger a exit status and do more things in other scripts.
true = localized.ngx_exit(localized.ngx_OK) --Go to content
false = nothing the script will run down to the end of the file and nginx will continue normally going to the next script on the server
]]
localized.exit_status = false --true or false

--[[
a fix for content-type miss matching and lets say a text/html page your nginx is providing application/octet-stream as the content-type
Setting this to false will not allow content-type matches on range filtering but range filtering will still work just ignoring the content-type you are matching
If you encounter requests hanging or subrequests issues set this to false the cause is proxy_max_temp_file_size 0; you either increase your buffer size or set this to false
]]
localized.content_type_fix = true --true or false

--[[
End Configuration


Users with little understanding don't edit beyond this point you will break the script most likely. (You should not need to be warned but now you have been told.) Proceed at own Risk!

Please do not touch anything below here unless you understand the code you read and know the consiquences.

This is where things get very complex. ;)

]]

--[[
Overrides for lua can be used via configuration file nginx.conf in the lua init block
https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/wiki/Script-Overrides
useful for those who do not want to modify the script but want to control settings via their nginx config
This way for each website or nginx config or vhost virtual host you can use the nginx config files to control this script
Example: nginx.conf inside the http block
http {
init_by_lua '
localized_global = {} --define global var that script can read
localized_global.secret = " enigma" --nginx config now sets secret key and the script will use the secret key from here
localized_global.credits = 2 --disable ddos credits
--clear the IP whitelists
localized_global.proxy_header_table = nil
localized_global.ip_whitelist = nil
';
}
]]
if localized_global ~= nil then
if localized_global.anti_ddos_table ~= nil then
localized.anti_ddos_table = localized_global.anti_ddos_table
end
if localized_global.content_cache ~= nil then
localized.content_cache = localized_global.content_cache
end
if localized_global.secret ~= nil then
localized.secret = localized_global.secret
end
if localized_global.remote_addr ~= nil then
localized.remote_addr = localized_global.remote_addr
end
if localized_global.expire_time ~= nil then
localized.expire_time = localized_global.expire_time
end
if localized_global.javascript_REQUEST_TYPE ~= nil then
localized.javascript_REQUEST_TYPE = localized_global.javascript_REQUEST_TYPE
end
if localized_global.refresh_auth ~= nil then
localized.refresh_auth = localized_global.refresh_auth
end
if localized_global.JavascriptVars_opening ~= nil then
localized.JavascriptVars_opening = localized_global.JavascriptVars_opening
end
if localized_global.JavascriptVars_closing ~= nil then
localized.JavascriptVars_closing = localized_global.JavascriptVars_closing
end
if localized_global.x_auth_header ~= nil then
localized.x_auth_header = localized_global.x_auth_header
end
if localized_global.x_auth_header_name ~= nil then
localized.x_auth_header_name = localized_global.x_auth_header_name
end
if localized_global.challenge ~= nil then
localized.challenge = localized_global.challenge
end
if localized_global.cookie_name_start_date ~= nil then
localized.cookie_name_start_date = localized_global.cookie_name_start_date
end
if localized_global.cookie_name_end_date ~= nil then
localized.cookie_name_end_date = localized_global.cookie_name_end_date
end
if localized_global.cookie_name_encrypted_start_and_end_date ~= nil then
localized.cookie_name_encrypted_start_and_end_date = localized_global.cookie_name_encrypted_start_and_end_date
end
if localized_global.encrypt_anti_ddos_cookies ~= nil then
localized.encrypt_anti_ddos_cookies = localized_global.encrypt_anti_ddos_cookies
end
if localized_global.encrypt_javascript_output ~= nil then
localized.encrypt_javascript_output = localized_global.encrypt_javascript_output
end
if localized_global.ip_whitelist_remote_addr ~= nil then
localized.ip_whitelist_remote_addr = localized_global.ip_whitelist_remote_addr
end
if localized_global.ip_whitelist_block_mode ~= nil then
localized.ip_whitelist_block_mode = localized_global.ip_whitelist_block_mode
end
if localized_global.ip_whitelist_bypass_flood_protection ~= nil then
localized.ip_whitelist_bypass_flood_protection = localized_global.ip_whitelist_bypass_flood_protection
end
if localized_global.ip_whitelist ~= nil then
localized.ip_whitelist = localized_global.ip_whitelist
end
if localized_global.ip_blacklist_remote_addr ~= nil then
localized.ip_blacklist_remote_addr = localized_global.ip_blacklist_remote_addr
end
if localized_global.ip_blacklist ~= nil then
localized.ip_blacklist = localized_global.ip_blacklist
end
if localized_global.tor ~= nil then
localized.tor = localized_global.tor
end
if localized_global.tor_remote_addr ~= nil then
localized.tor_remote_addr = localized_global.tor_remote_addr
end
if localized_global.x_tor_header ~= nil then
localized.x_tor_header = localized_global.x_tor_header
end
if localized_global.x_tor_header_name ~= nil then
localized.x_tor_header_name = localized_global.x_tor_header_name
end
if localized_global.x_tor_header_name_allowed ~= nil then
localized.x_tor_header_name_allowed = localized_global.x_tor_header_name_allowed
end
if localized_global.x_tor_header_name_blocked ~= nil then
localized.x_tor_header_name_blocked = localized_global.x_tor_header_name_blocked
end
if localized_global.cookie_tor ~= nil then
localized.cookie_tor = localized_global.cookie_tor
end
if localized_global.cookie_tor_value_allow ~= nil then
localized.cookie_tor_value_allow = localized_global.cookie_tor_value_allow
end
if localized_global.cookie_tor_value_block ~= nil then
localized.cookie_tor_value_block = localized_global.cookie_tor_value_block
end
if localized_global.default_charset ~= nil then
localized.default_charset = localized_global.default_charset
end
if localized_global.master_switch ~= nil then
localized.master_switch = localized_global.master_switch
end
if localized_global.master_switch_custom_hosts ~= nil then
localized.master_switch_custom_hosts = localized_global.master_switch_custom_hosts
end
if localized_global.credits ~= nil then
localized.credits = localized_global.credits
end
if localized_global.dynamic_javascript_vars_length ~= nil then
localized.dynamic_javascript_vars_length = localized_global.dynamic_javascript_vars_length
end
if localized_global.dynamic_javascript_vars_length_static ~= nil then
localized.dynamic_javascript_vars_length_static = localized_global.dynamic_javascript_vars_length_static
end
if localized_global.dynamic_javascript_vars_length_start ~= nil then
localized.dynamic_javascript_vars_length_start = localized_global.dynamic_javascript_vars_length_start
end
if localized_global.dynamic_javascript_vars_length_end ~= nil then
localized.dynamic_javascript_vars_length_end = localized_global.dynamic_javascript_vars_length_end
end
if localized_global.user_agent_blacklist_table ~= nil then
localized.user_agent_blacklist_table = localized_global.user_agent_blacklist_table
end
if localized_global.user_agent_whitelist_table ~= nil then
localized.user_agent_whitelist_table = localized_global.user_agent_whitelist_table
end
if localized_global.authorization ~= nil then
localized.authorization = localized_global.authorization
end
if localized_global.authorization_paths ~= nil then
localized.authorization_paths = localized_global.authorization_paths
end
if localized_global.authorization_dynamic ~= nil then
localized.authorization_dynamic = localized_global.authorization_dynamic
end
if localized_global.authorization_dynamic_length ~= nil then
localized.authorization_dynamic_length = localized_global.authorization_dynamic_length
end
if localized_global.authorization_message ~= nil then
localized.authorization_message = localized_global.authorization_message
end
if localized_global.authorization_username_message ~= nil then
localized.authorization_username_message = localized_global.authorization_username_message
end
if localized_global.authorization_password_message ~= nil then
localized.authorization_password_message = localized_global.authorization_password_message
end
if localized_global.authorization_logins ~= nil then
localized.authorization_logins = localized_global.authorization_logins
end
if localized_global.authorization_cookie ~= nil then
localized.authorization_cookie = localized_global.authorization_cookie
end
if localized_global.WAF_POST_Request_table ~= nil then
localized.WAF_POST_Request_table = localized_global.WAF_POST_Request_table
end
if localized_global.WAF_Header_Request_table ~= nil then
localized.WAF_Header_Request_table = localized_global.WAF_Header_Request_table
end
if localized_global.WAF_query_string_Request_table ~= nil then
localized.WAF_query_string_Request_table = localized_global.WAF_query_string_Request_table
end
if localized_global.WAF_URI_Request_table ~= nil then
localized.WAF_URI_Request_table = localized_global.WAF_URI_Request_table
end
if localized_global.query_string_sort_table ~= nil then
localized.query_string_sort_table = localized_global.query_string_sort_table
end
if localized_global.query_string_expected_args_only_table ~= nil then
localized.query_string_expected_args_only_table = localized_global.query_string_expected_args_only_table
end
if localized_global.query_string_remove_args_table ~= nil then
localized.query_string_remove_args_table = localized_global.query_string_remove_args_table
end
if localized_global.proxy_header_table ~= nil then
localized.proxy_header_table = localized_global.proxy_header_table
end
if localized_global.send_ip_to_backend_custom_headers ~= nil then
localized.send_ip_to_backend_custom_headers = localized_global.send_ip_to_backend_custom_headers
end
if localized_global.custom_headers ~= nil then
localized.custom_headers = localized_global.custom_headers
end
if localized_global.log_users_on_puzzle ~= nil then
localized.log_users_on_puzzle = localized_global.log_users_on_puzzle
end
if localized_global.log_on_puzzle_text_start ~= nil then
localized.log_on_puzzle_text_start = localized_global.log_on_puzzle_text_start
end
if localized_global.log_on_puzzle_text_end ~= nil then
localized.log_on_puzzle_text_end = localized_global.log_on_puzzle_text_end
end
if localized_global.log_users_granted_access ~= nil then
localized.log_users_granted_access = localized_global.log_users_granted_access
end
if localized_global.log_on_granted_text_start ~= nil then
localized.log_on_granted_text_start = localized_global.log_on_granted_text_start
end
if localized_global.log_on_granted_text_end ~= nil then
localized.log_on_granted_text_end = localized_global.log_on_granted_text_end
end
if localized_global.exit_status ~= nil then
localized.exit_status = localized_global.exit_status
end
if localized_global.content_type_fix ~= nil then
localized.content_type_fix = localized_global.content_type_fix
end
end

--Test as Tor network
--localized.host = "localhost.onion"
--localized.URL = localized.scheme .. "://" .. localized.host .. localized.request_uri

--Test clear the IP whitelists
--localized.proxy_header_table = nil
--localized.ip_whitelist = nil

--[[
Begin Required Functions
]]

--I made this function because string find / match can be slow so i can speed it up for basic regex examples / matches
--And it allows me to add more to the list easier rather than individually for each usage of string find / match
local function faster_than_match(match) --tested via 100,000,000 times in a for loop super fast
	--localized.ngx_log(localized.ngx_LOG_TYPE, " url to match : " .. localized.URL .. " - input :" .. match)
	if match == ".*"
	or match == "^.*$"
	or match == "*."
	or match == "."
	or match == "*"
	or match == ""
	or match == " "
	--[[
	or match == localized.URL
	or match == localized.URL .. "$"
	or match == "^" .. localized.URL
	or match == "^" .. localized.URL .. "$"
	or match == localized.request_uri
	or match == localized.request_uri .. "$"
	or match == "^" .. localized.request_uri
	or match == "^" .. localized.request_uri .. "$"
	or match == localized.host
	or match == localized.host .. "$"
	or match == "^" .. localized.host
	or match == "^" .. localized.host .. "$"
	or match == localized.scheme .. "://" .. localized.host
	or match == localized.scheme .. "://" .. localized.host .. "$"
	or match == "^" .. localized.scheme .. "://" .. localized.host .. "$"
	or match == "^" .. localized.scheme .. "://" .. localized.host
	or match == localized.scheme .. "://" .. localized.host .. "/"
	or match == localized.scheme .. "://" .. localized.host .. "/$"
	or match == "^" .. localized.scheme .. "://" .. localized.host .. "/$"
	or match == "^" .. localized.scheme .. "://" .. localized.host .. "/"
	or match == localized.scheme .. "://" .. localized.host .. localized.request_uri
	or match == localized.scheme .. "://" .. localized.host .. localized.request_uri .."$"
	or match == "^" .. localized.scheme .. "://" .. localized.host .. localized.request_uri .. "$"
	or match == "^" .. localized.scheme .. "://" .. localized.host .. localized.request_uri
	]]
	or match == nil then
		return true
	else
		return false
	end
end
--Example both do the same thing just mine is faster
--localized.var = "hello world"
--for i=1, 1e8 do if localized.string_match(localized.var, ".*") then end end--slow
--for i=1, 1e8 do if faster_than_match(localized.var) then end end--fast

localized.get_resp_content_type_counter = 0
local function get_resp_content_type(forced) --incase content-type header not yet exists grab it
	local resp_content_type = nil
	if forced == nil then
		localized.get_resp_content_type_counter = localized.get_resp_content_type_counter+1
		if localized.ngx_header["content-type"] then
			--localized.ngx_log(localized.ngx_LOG_TYPE, " localized.ngx_header['content-type'] " .. localized.ngx_header["content-type"] )
			resp_content_type = localized.ngx_header["content-type"]
			return resp_content_type
		end
	end
	--made it this far still no content-type ?
	if localized.get_resp_content_type_counter > 1 then --so we dont run location capture multiple times on the first run it will either be content-type or nil
		return resp_content_type
	end
	--localized.ngx_log(localized.ngx_LOG_TYPE, " count is " .. localized.get_resp_content_type_counter )
	--local req_headers = localized.ngx_req_get_headers()
	local map = {
		GET = localized.ngx_HTTP_GET,
		HEAD = localized.ngx_HTTP_HEAD,
		PUT = localized.ngx_HTTP_PUT,
		POST = localized.ngx_HTTP_POST,
		DELETE = localized.ngx_HTTP_DELETE,
		OPTIONS = localized.ngx_HTTP_OPTIONS,
		MKCOL = localized.ngx_HTTP_MKCOL,
		COPY = localized.ngx_HTTP_COPY,
		MOVE = localized.ngx_HTTP_MOVE,
		PROPFIND = localized.ngx_HTTP_PROPFIND,
		PROPPATCH = localized.ngx_HTTP_PROPPATCH,
		LOCK = localized.ngx_HTTP_LOCK,
		UNLOCK = localized.ngx_HTTP_UNLOCK,
		PATCH = localized.ngx_HTTP_PATCH,
		TRACE = localized.ngx_HTTP_TRACE,
		CONNECT = localized.ngx_HTTP_CONNECT, --does not exist but put here never know in the future
	}
	local res = localized.ngx.location.capture(localized.request_uri, {
	--method = map[localized.ngx_var.request_method],
	method = map[HEAD],
	--headers = req_headers,
	})
	if res then
		if res.header ~= nil and localized.type(res.header) == "table" then
			for headerName, header in localized.next, res.header do
				--localized.ngx_log(localized.ngx_LOG_TYPE, " header name" .. headerName .. " value " .. header )
				if localized.string_lower(localized.tostring(headerName)) == "content-type" then
					--localized.ngx_log(localized.ngx_LOG_TYPE, " localized.ngx.location.capture " .. header )
					resp_content_type = header
				end
			end
		end
	end
	localized.ngx_header["content-type"] = resp_content_type --set header as content-type be either nil or the content-type
	localized.get_resp_content_type_counter = localized.get_resp_content_type_counter+2 --make sure we dont run again
	return resp_content_type

end
--localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Content-Type header is. " .. get_resp_content_type() )
--get_resp_content_type()

--[[
Start IP range function
]]
local function ip_address_in_range(input_ip, client_connecting_ip)
	if localized.string_find(input_ip, "/") then --input ip is a subnet
		--do nothing
	else
		return
	end

	local ip_type = nil
	if localized.string_find(input_ip, "%:") and localized.string_find(client_connecting_ip, "%:") then --if both input and connecting ip are ipv6 addresses
		--ipv6
		ip_type = 1
	elseif localized.string_find(input_ip, "%.") and localized.string_find(client_connecting_ip, "%.") then --if both input and connecting ip are ipv4 addresses
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
			for st, sp in function() return localized.string_find(string, divide, pos, true) end do
				arr[arr_table_length] = localized.string_sub(string, pos, st - 1 ) --attach chars left of current divider
				arr_table_length=arr_table_length+1
				pos = sp + 1 --jump past current divider
			end
				arr[arr_table_length] = localized.string_sub(string, pos) -- Attach chars right of last divider
				arr_table_length=arr_table_length+1
			return arr
		end

		--[[
		Input IP
		]]
		--validate actual ip
		local a, b, ip, mask = localized.string_find(input_ip, '([%w:]+)/(%d+)')

		--get ip bits
		local ipbits = explode(ip, ':')

		--now to build an expanded ip
		local zeroblock
		--local ipbits_length = #ipbits
		for i=1,#ipbits do
			local k = i
			local v = ipbits[i]
			--length 0? we're at the :: bit
			if localized.string_len(v) == 0 then
				zeroblock = k

				--length not 0 but not 4, prepend 0's
			elseif localized.string_len(v) < 4 then
				--local padding = 4 - localized.string_len(v)
				for i = 1, 4 - localized.string_len(v) do
					ipbits[k] = 0 .. ipbits[k]
				end
			end
		end
		if zeroblock and #ipbits < 8 then
			--remove zeroblock
			ipbits[zeroblock] = '0000'
			--local padding = 8 - #ipbits

			for i = 1, 8 - #ipbits do
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
		local a, b, clientip, mask_client = localized.string_find(client_connecting_ip, '([%w:]+)')

		--get ip bits
		local ipbits_client = explode(clientip, ':')

		--now to build an expanded ip
		local zeroblock_client
		--local ipbits_client_length = #ipbits_client
		for i=1,#ipbits_client do
			local k = i
			local v = ipbits_client[i]
			--length 0? we're at the :: bit
			if localized.string_len(v) == 0 then
				zeroblock_client = k

				--length not 0 but not 4, prepend 0's
			elseif localized.string_len(v) < 4 then
				--local padding = 4 - localized.string_len(v)
				for i = 1, 4 - localized.string_len(v) do
					ipbits_client[k] = 0 .. ipbits_client[k]
				end
			end
		end
		if zeroblock_client and #ipbits_client < 8 then
			--remove zeroblock
			ipbits_client[zeroblock_client] = '0000'
			--local padding = 8 - #ipbits_client

			for i = 1, 8 - #ipbits_client do
				ipbits_client[zeroblock_client] = '0000'
				--ipbits_client_length=ipbits_client_length+1
			end
		end
		--[[
		End Client IP
		]]

		local expanded_ip_count = (ipbits[1] or "0000") .. ':' .. (ipbits[2] or "0000") .. ':' .. (ipbits[3] or "0000") .. ':' .. (ipbits[4] or "0000") .. ':' .. (ipbits[5] or "0000") .. ':' .. (ipbits[6] or "0000") .. ':' .. (ipbits[7] or "0000") .. ':' .. (ipbits[8] or "0000")
		expanded_ip_count = localized.string_gsub(expanded_ip_count, ":", "")

		local client_connecting_ip_count = (ipbits_client[1] or "0000") .. ':' .. (ipbits_client[2] or "0000") .. ':' .. (ipbits_client[3] or "0000") .. ':' .. (ipbits_client[4] or "0000") .. ':' .. (ipbits_client[5] or "0000") .. ':' .. (ipbits_client[6] or "0000") .. ':' .. (ipbits_client[7] or "0000") .. ':' .. (ipbits_client[8] or "0000")
		client_connecting_ip_count = localized.string_gsub(client_connecting_ip_count, ":", "")

		--generate wildcard from mask
		local indent = mask / 4

		expanded_ip_count = localized.string_sub(expanded_ip_count, 0, indent)
		client_connecting_ip_count = localized.string_sub(client_connecting_ip_count, 0, indent)

		local client_connecting_ip_expanded = localized.string_gsub(client_connecting_ip_count, "....", "%1:")
		client_connecting_ip_expanded = localized.string_gsub(client_connecting_ip_count, ":$", "")
		local expanded_ip = localized.string_gsub(expanded_ip_count, "....", "%1:")
		expanded_ip = localized.string_gsub(expanded_ip_count, ":$", "")

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
		--local wildcardbits_length = #wildcardbits
		for i=1,#wildcardbits do
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
			--local ipbits_length = #ipbits
			for i=1,#ipbits do
				local k = i
				local v = ipbits[i]
				local topbit = ''
				local bottombit = ''
				for i = 1, 4 do
					local wild = localized.string_sub(wildcard[k], i, i)
					local norm = localized.string_sub(v, i, i)
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
		local ipcount = localized.math_pow(2, 128 - mask)

		if expanded_ip == client_connecting_ip_expanded then
			--localized.ngx_log(localized.ngx_LOG_TYPE,"ipv6 is in range")
			return true
		end

		--output
		--[[
		localized.ngx_log(localized.ngx_LOG_TYPE,'indent' .. indent)
		localized.ngx_log(localized.ngx_LOG_TYPE,'client_ip numeric : ' .. client_connecting_ip_count )
		localized.ngx_log(localized.ngx_LOG_TYPE,'input ip numeric : ' .. expanded_ip_count )
		localized.ngx_log(localized.ngx_LOG_TYPE,'client_ip : ' .. client_connecting_ip_expanded )
		localized.ngx_log(localized.ngx_LOG_TYPE,'input ip : ' .. expanded_ip )
		localized.ngx_log(localized.ngx_LOG_TYPE, '###### INFO ######' )
		localized.ngx_log(localized.ngx_LOG_TYPE, 'IP in: ' .. ip )
		localized.ngx_log(localized.ngx_LOG_TYPE, '=> Expanded IP: ' .. (ipbits[1] or "0000") .. ':' .. (ipbits[2] or "0000") .. ':' .. (ipbits[3] or "0000") .. ':' .. (ipbits[4] or "0000") .. ':' .. (ipbits[5] or "0000") .. ':' .. (ipbits[6] or "0000") .. ':' .. (ipbits[7] or "0000") .. ':' .. (ipbits[8] or "0000") )
		localized.ngx_log(localized.ngx_LOG_TYPE, 'Mask in: /' .. mask )
		localized.ngx_log(localized.ngx_LOG_TYPE, '=> Mask Wildcard: ' .. (wildcard[1] or "0000") .. ':' .. (wildcard[2] or "0000") .. ':' .. (wildcard[3] or "0000") .. ':' .. (wildcard[4] or "0000") .. ':' .. (wildcard[5] or "0000") .. ':' .. (wildcard[6] or "0000") .. ':' .. (wildcard[7] or "0000") .. ':' .. (wildcard[8] or "0000") )
		localized.ngx_log(localized.ngx_LOG_TYPE, '\n###### BLOCK ######' )
		localized.ngx_log(localized.ngx_LOG_TYPE, '#IP\'s: ' .. ipcount )
		localized.ngx_log(localized.ngx_LOG_TYPE, 'Range Start: ' .. (topip[1] or "0000") .. ':' .. (topip[2] or "0000") .. ':' .. (topip[3] or "0000") .. ':' .. (topip[4] or "0000") .. ':' .. (topip[5] or "0000") .. ':' .. (topip[6] or "0000") .. ':' .. (topip[7] or "0000") .. ':' .. (topip[8] or "0000") )
		localized.ngx_log(localized.ngx_LOG_TYPE, 'Range End: ' .. (bottomip[1] or "ffff") .. ':' .. (bottomip[2] or "ffff") .. ':' .. (bottomip[3] or "ffff") .. ':' .. (bottomip[4] or "ffff") .. ':' .. (bottomip[5] or "ffff") .. ':' .. (bottomip[6] or "ffff") .. ':' .. (bottomip[7] or "ffff") .. ':' .. (bottomip[8] or "ffff") )
		]]

	end

	if ip_type == 2 then --ipv4

		local a, b, ip1, ip2, ip3, ip4, mask = localized.string_find(input_ip, '(%d+).(%d+).(%d+).(%d+)/(%d+)')
		local ip = { localized.tonumber( ip1 ), localized.tonumber( ip2 ), localized.tonumber( ip3 ), localized.tonumber( ip4 ) }
		local a, b, client_ip1, client_ip2, client_ip3, client_ip4 = localized.string_find(client_connecting_ip, '(%d+).(%d+).(%d+).(%d+)')
		local client_ip = { localized.tonumber( client_ip1 ), localized.tonumber( client_ip2 ), localized.tonumber( client_ip3 ), localized.tonumber( client_ip4 ) }

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
		local wildcard = masks[localized.tonumber( mask )]

		--number of ips in mask
		local ipcount = localized.math_pow(2, ( 32 - mask ))

		--network IP (route/bottom IP)
		local bottomip = {}
		--local ip_length = #ip
		for i=1,#ip do
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
		--local bottomip_length = #bottomip
		for i=1,#bottomip do
			local k = i
			local v = bottomip[i]
			topip[k] = v + wildcard[k]
		end

		--is input ip = network ip?
		local isnetworkip = ( ip[1] == bottomip[1] and ip[2] == bottomip[2] and ip[3] == bottomip[3] and ip[4] == bottomip[4] )
		local isbroadcastip = ( ip[1] == topip[1] and ip[2] == topip[2] and ip[3] == topip[3] and ip[4] == topip[4] )

		local ip1 = localized.tonumber(ip1)
		local ip2 = localized.tonumber(ip2)
		local ip3 = localized.tonumber(ip3)
		local ip4 = localized.tonumber(ip4)
		local client_ip1 = localized.tonumber(client_ip1)
		local client_ip2 = localized.tonumber(client_ip2)
		local client_ip3 = localized.tonumber(client_ip3)
		local client_ip4 = localized.tonumber(client_ip4)
		local in_range_low_end1 = localized.tonumber(bottomip[1])
		local in_range_low_end2 = localized.tonumber(bottomip[2])
		local in_range_low_end3 = localized.tonumber(bottomip[3])
		local in_range_low_end4 = localized.tonumber(bottomip[4])
		local in_range_top_end1 = localized.tonumber(topip[1])
		local in_range_top_end2 = localized.tonumber(topip[2])
		local in_range_top_end3 = localized.tonumber(topip[3])
		local in_range_top_end4 = localized.tonumber(topip[4])

		if localized.tonumber(mask) == 1 then --127, 255, 255, 255
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
		if localized.tonumber(mask) == 2 then --63, 255, 255, 255
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
		if localized.tonumber(mask) == 3 then --31, 255, 255, 255
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
		if localized.tonumber(mask) == 4 then --15, 255, 255, 255
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
		if localized.tonumber(mask) == 5 then --7, 255, 255, 255
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
		if localized.tonumber(mask) == 6 then --3, 255, 255, 255
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
		if localized.tonumber(mask) == 7 then --1, 255, 255, 255
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
		if localized.tonumber(mask) == 8 then --0, 255, 255, 255
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
		if localized.tonumber(mask) == 9 then --0, 127, 255, 255
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
		if localized.tonumber(mask) == 10 then --0, 63, 255, 255
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
		if localized.tonumber(mask) == 11 then --0, 31, 255, 255
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
		if localized.tonumber(mask) == 12 then --0, 15, 255, 255
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
		if localized.tonumber(mask) == 13 then --0, 7, 255, 255
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
		if localized.tonumber(mask) == 14 then --0, 3, 255, 255
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
		if localized.tonumber(mask) == 15 then --0, 1, 255, 255
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
		if localized.tonumber(mask) == 16 then --0, 0, 255, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if localized.tonumber(mask) == 17 then --0, 0, 127, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if localized.tonumber(mask) == 18 then --0, 0, 63, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if localized.tonumber(mask) == 19 then --0, 0, 31, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if localized.tonumber(mask) == 20 then --0, 0, 15, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if localized.tonumber(mask) == 21 then --0, 0, 7, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if localized.tonumber(mask) == 22 then --0, 0, 3, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if localized.tonumber(mask) == 23 then --0, 0, 1, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and client_ip3 >= in_range_low_end3 --in range low end
			and client_ip3 <= in_range_top_end3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if localized.tonumber(mask) == 24 then --0, 0, 0, 255
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and ip3 == client_ip3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if localized.tonumber(mask) == 25 then --0, 0, 0, 127
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and ip3 == client_ip3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if localized.tonumber(mask) == 26 then --0, 0, 0, 63
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and ip3 == client_ip3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if localized.tonumber(mask) == 27 then --0, 0, 0, 31
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and ip3 == client_ip3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if localized.tonumber(mask) == 28 then --0, 0, 0, 15
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and ip3 == client_ip3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if localized.tonumber(mask) == 29 then --0, 0, 0, 7
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and ip3 == client_ip3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if localized.tonumber(mask) == 30 then --0, 0, 0, 3
			if ip1 == client_ip1 
			and ip2 == client_ip2 
			and ip3 == client_ip3 
			and client_ip4 >= in_range_low_end4 --in range low end
			and client_ip4 <= in_range_top_end4 then --in range top end
				return true
			end
		end
		if localized.tonumber(mask) == 31 then --0, 0, 0, 1
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
		localized.ngx_log(localized.ngx_LOG_TYPE, '###### INFO ######' )
		localized.ngx_log(localized.ngx_LOG_TYPE, 'IP in: ' .. ip[1] .. '.' .. ip[2] .. '.' .. ip[3] .. '.' .. ip[4]  )
		localized.ngx_log(localized.ngx_LOG_TYPE, 'Mask in: /' .. mask )
		localized.ngx_log(localized.ngx_LOG_TYPE, '=> Mask Wildcard: ' .. wildcard[1] .. '.' .. wildcard[2] .. '.' .. wildcard[3] .. '.' .. wildcard[4]  )
		localized.ngx_log(localized.ngx_LOG_TYPE, '=> in IP is network-ip: ' .. localized.tostring( isnetworkip ) )
		localized.ngx_log(localized.ngx_LOG_TYPE, '=> in IP is broadcast-ip: ' .. localized.tostring( isbroadcastip ) )
		localized.ngx_log(localized.ngx_LOG_TYPE, '\n###### BLOCK ######' )
		localized.ngx_log(localized.ngx_LOG_TYPE, '#IP\'s: ' .. ipcount )
		localized.ngx_log(localized.ngx_LOG_TYPE, 'Bottom/Network: ' .. bottomip[1] .. '.' .. bottomip[2] .. '.' .. bottomip[3] .. '.' .. bottomip[4] .. '/' .. mask )
		localized.ngx_log(localized.ngx_LOG_TYPE, 'Top/Broadcast: ' .. topip[1] .. '.' .. topip[2] .. '.' .. topip[3] .. '.' .. topip[4] )
		localized.ngx_log(localized.ngx_LOG_TYPE, 'Subnet Range: ' .. bottomip[1] .. '.' .. bottomip[2] .. '.' .. bottomip[3] .. '.' .. bottomip[4] .. ' - ' .. topip[1] .. '.' .. topip[2] .. '.' .. topip[3] .. '.' .. topip[4] )
		localized.ngx_log(localized.ngx_LOG_TYPE, 'Host Range: ' .. bottomip[1] .. '.' .. bottomip[2] .. '.' .. bottomip[3] .. '.' .. bottomip[4] + 1 .. ' - ' .. topip[1] .. '.' .. topip[2] .. '.' .. topip[3] .. '.' .. topip[4] - 1 )
		]]

	end

end
--[[
usage
if localized.ngx_var_http_internal == nil then --1st layer
	if ip_address_in_range("127.0.0.0/16", "127.0.0.1") == true then --ipv4
		localized.ngx_log(localized.ngx_LOG_TYPE,"IPv4 in range")
	end
	if ip_address_in_range("2620:0:860:2::/64", "2620:0:860:2:FFFF:FFFF:FFFF:FFFF") == true then --ipv6
		localized.ngx_log(localized.ngx_LOG_TYPE,"IPv6 in range")
	end
end
]]
--[[
End IP range function
]]

--if a table has a value inside of it
local function has_value(table_, val)
	--for i=1,#table_ do
		--if table_[i] == val then
	for key, value in localized.next, table_ do
		if value == val then
			return true
		end
	end
	return false
end

local function TableConcat(t1,t2)
	for i=1,#t2 do
		if has_value(t1,t2[i]) == false then
			t1[#t1+1] = t2[i]
		end
	end
	return t1
end

localized.proxy_header_ip_check_count = 0
local function proxy_header_ip_check(ip_table)
	if localized.proxy_header_ip_check_count >= 1 then --so we dont run multiple times we serve the cached output instead
		return localized.proxy_header_ip_check_cached
	end
	if ip_table ~= nil and #ip_table > 0 then
		localized.proxy_header_ip_check_count = localized.proxy_header_ip_check_count+2 --make sure we dont run again
		for i=1,#ip_table do
			local value = ip_table[i]
			if value == localized.ngx_var_remote_addr then --if our ip address matches with one in the whitelist
				localized.proxy_header_ip_check_cached = true
				return true
			elseif ip_address_in_range(value, localized.ngx_var_remote_addr) == true then
				localized.proxy_header_ip_check_cached = true
				return true
			end
		end
	else
		localized.proxy_header_ip_check_count = localized.proxy_header_ip_check_count+2 --make sure we dont run again
		localized.proxy_header_ip_check_cached = true
		return true
	end
	localized.proxy_header_ip_check_count = localized.proxy_header_ip_check_count+2 --make sure we dont run again
	localized.proxy_header_ip_check_cached = false
	return false
end

local function internal_header_setup()
	if localized.anti_ddos_table ~= nil and #localized.anti_ddos_table > 0 then --do ip block checks before we bother generating headers
		for i=1,#localized.anti_ddos_table do --for each host/path in our table
			local v = localized.anti_ddos_table[i]
			if faster_than_match(v[1]) or localized.string_find(localized.URL, v[1]) then --if our host matches one in the table
				--if localized.request_limit == nil then
					--localized.request_limit = v[19] or nil --What ever memory space your server has set / defined for this to use
				--end
				if localized.blocked_addr == nil then
					localized.blocked_addr = v[20] or nil
				end
				if localized.ddos_counter == nil then
					localized.ddos_counter = v[21] or nil
				end
				if localized.blocked_addr ~= nil and localized.ddos_counter ~= nil then
					local block_duration = v[10]
					local rate_limit_exit_status = v[11]

					local total_requests = localized.ddos_counter:get("blocked_ip") or 0
					if v[33] == 1 then
						if total_requests > v[24] then --Automatically enable I am Under Attack Mode so disable logging
							v[7] = 0 --disable logging to prevent denil of service from excessive log file writes using up disk I/O
						end
					end

					--start real ip block
					local ip = localized.ngx_var_remote_addr
					local blocked_time = localized.blocked_addr:get(ip) --if for some reason their real ip is in the block list block them else fall back to other checks
					if blocked_time then
						if v[7] == 1 then
							if v[23] == 1 then
								if total_requests < v[24] then --Less than required amount to trigger Automatically enable I am Under Attack Mode so enable logging
									--localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) Blocked IP attempt: " .. ip .. " - URL : " .. localized.URL )
									localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) Blocked IP attempt: " .. ip .. " - URL : " .. localized.URL .. " - Ban extended/ends on : " .. localized.ngx_cookie_time(blocked_time+block_duration) ) --ngx_cookie_time can be slow dont use this under attack
								end
							end
						end
						localized.blocked_addr:set(ip, localized.currenttime, block_duration) --update with current time to extend ban duration
						if rate_limit_exit_status ~= 444 and rate_limit_exit_status ~= 204 then --no point with gzip on these
							localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip --this can slow down nginx tested via 100,000,000 requests nulled out on the block pages
						end
						return localized.ngx_exit(rate_limit_exit_status)
					end
					--end real ip
					--concatenate tables make sure both these tables are the same
					if localized.ip_whitelist ~= nil and localized.proxy_header_table ~= nil then
						localized.merge_table = TableConcat(localized.ip_whitelist, localized.proxy_header_table)
						localized.merge_table[#localized.merge_table+1] = localized.ngx_var.server_addr --make sure our own server address is whitelisted just incase
						localized.ip_whitelist = localized.merge_table
						localized.proxy_header_table = localized.merge_table
					end
					local ip = v[22]
					if ip == "auto" then
						if localized.ngx_var_http_cf_connecting_ip ~= nil then
							if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
								ip = localized.ngx_var_http_cf_connecting_ip
							else --you are not really cloudflare dont pretend you are to bypass flood protection
								ip = localized.ngx_var_remote_addr
							end
						elseif localized.ngx_var_http_x_forwarded_for ~= nil then
							if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
								ip = localized.ngx_var_http_x_forwarded_for
							else
								ip = localized.ngx_var_remote_addr
							end
						else
							ip = localized.ngx_var_remote_addr
						end
					end
					local blocked_time = localized.blocked_addr:get(ip)
					if blocked_time then
						if v[7] == 1 then
							if v[23] == 1 then
								if total_requests < v[24] then --Less than required amount to trigger Automatically enable I am Under Attack Mode so enable logging
									--localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) Blocked IP attempt: " .. ip .. " - URL : " .. localized.URL )
									localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) Blocked IP attempt: " .. ip .. " - URL : " .. localized.URL .. " - Ban extended/ends on : " .. localized.ngx_cookie_time(blocked_time+block_duration) ) --ngx_cookie_time can be slow dont use this under attack
								end
							end
						end
						localized.blocked_addr:set(ip, localized.currenttime, block_duration) --update with current time to extend ban duration
						if rate_limit_exit_status ~= 444 and rate_limit_exit_status ~= 204 then --no point with gzip on these
							localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip --this can slow down nginx tested via 100,000,000 requests nulled out on the block pages
						end
						return localized.ngx_exit(rate_limit_exit_status)
					end
				end
				break
			end
		end
	end
	if localized.secret == " enigma" then --if its still default and unchanged by user
		localized.secret = localized.secret .. localized.os_date("%W",localized.os_time_saved) --make more dynamic than default hopefully nobody does try to use default in production
		--you dont want this to change to frequently every time you change your secret key you will see users on a javascript puzzle page will need to pass auth again
	end
	--openresty have a simple version of this https://github.com/openresty/lua-nginx-module?tab=readme-ov-file#ngxreqis_internal but for old versions of nginx with lua i created this so backwards compatibility
	if localized.proxy_header_table ~= nil and #localized.proxy_header_table > 0 then --only set internal headers when proxy header checks are in use
		--internal header protection if the script needs to make a internal call like with the header_append_ip() / localized.send_ip_to_backend_custom_headers function we can track it.
		localized.ngx_var_http_internal_string = "1337"--internal bypass header value
		localized.ngx_var_http_internal_header_name = "internal" --internal bypass header name
		localized.ngx_var_http_internal_header_name = localized.ngx_hmac_sha1(localized.secret .. localized.os_date("%W",localized.os_time_saved), localized.ngx_var_http_internal_header_name) --encrypt this header so nobody can guess it or use it other than internal work calls
		localized.ngx_var_http_internal_header_name = localized.ngx_encode_base64(localized.ngx_var_http_internal_header_name) --wrap encrypted header in base64
		localized.ngx_var_http_internal_header_name = localized.string_gsub(localized.ngx_var_http_internal_header_name, "[+/=]", "") --Remove +/=
		localized.ngx_var_http_internal = localized.ngx_var["http_"..localized.ngx_var_http_internal_header_name] or nil
		localized.ngx_var_http_internal_log = 0

		if localized.ngx_var_http_internal_log == 1 then --log the internal request headers
			localized.ngx_log(localized.ngx_LOG_TYPE, " internal header is - " .. localized.ngx_var_http_internal_header_name )
			if localized.ngx_var_http_internal ~= nil then --2nd layer
				for headerName, header in localized.next, localized.ngx_req_get_headers() do
					localized.ngx_log(localized.ngx_LOG_TYPE, " 2nd layer " .. headerName .. " - " .. header )
				end
			else --1st layer
				for headerName, header in localized.next, localized.ngx_req_get_headers() do
					localized.ngx_log(localized.ngx_LOG_TYPE, " 1st layer " .. headerName .. " - " .. header )
				end
			end
		end
	end
end
internal_header_setup()

localized.check_tor_onion_cached = nil
local function check_tor_onion()
	if localized.check_tor_onion_cached == nil then
		if localized.string_find(localized.string_lower(localized.host), ".onion") then
			localized.check_tor_onion_cached = true
		else
			localized.check_tor_onion_cached = false
		end
		return localized.check_tor_onion_cached
	else
		return localized.check_tor_onion_cached
	end
end
--check_tor_onion() --true or false
if check_tor_onion() then
	localized.ip_whitelist = nil
	localized.proxy_header_table = nil
end

localized.ip_whitelist_flood_checks_count = 0
local function ip_whitelist_flood_checks(ip_table)
	if localized.ip_whitelist_flood_checks_count >= 1 then --so we dont run multiple times we serve the cached output instead
		return localized.ip_whitelist_output_cached
	end
	if localized.ip_whitelist_bypass_flood_protection == 1 and ip_table ~= nil and #ip_table > 0 then
		if localized.ip_whitelist_remote_addr == "auto" then
			if localized.ngx_var_http_cf_connecting_ip ~= nil then
				if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
					localized.ip_whitelist_remote_addr = localized.ngx_var_http_cf_connecting_ip
				else --you are not really cloudflare dont pretend you are to bypass flood protection
					localized.ip_whitelist_remote_addr = localized.ngx_var_remote_addr
				end
			elseif localized.ngx_var_http_x_forwarded_for ~= nil then
				if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
					localized.ip_whitelist_remote_addr = localized.ngx_var_http_x_forwarded_for
				else
					localized.ip_whitelist_remote_addr = localized.ngx_var_remote_addr
				end
			else
				localized.ip_whitelist_remote_addr = localized.ngx_var_remote_addr
			end
		end
		localized.ip_whitelist_flood_checks_count = localized.ip_whitelist_flood_checks_count+2 --make sure we dont run again
		for i=1,#ip_table do
			local value = ip_table[i]
			if value == localized.ip_whitelist_remote_addr then --if our ip address matches with one in the whitelist
				localized.ip_whitelist_output_cached = false
				return false
			elseif ip_address_in_range(value, localized.ip_whitelist_remote_addr) == true then
				localized.ip_whitelist_output_cached = false
				return false
			end
		end
	else
		localized.ip_whitelist_flood_checks_count = localized.ip_whitelist_flood_checks_count+2 --make sure we dont run again
		--if localized.ip_whitelist_bypass_flood_protection == 1 then
			--if returns true then ips will be blocked so we return false
			--localized.ip_whitelist_output_cached = false
			--return false
		--end
	end
	localized.ip_whitelist_output_cached = true
	return true
end

local function check_system(number,command,logging,ip)
	if localized.package == nil then
		localized.package = package
	end
	if localized.os_exe == nil then
		localized.os_execute = os.execute --might be better way with io.popen
	end
	if localized.system_os == nil then
		localized.system_os = localized.string_match(localized.package.cpath, "%p[".. localized.string_sub(localized.package.config, 1, 1 ) .."]?%p(%a+)")
	end
	if localized.system_os == "dll" and number == 1 then
		if logging == 1 then
			--localized.ngx_log(localized.ngx_LOG_TYPE, "binformat: "..localized.system_os .. " - number: " .. number .. " - command: " .. command)
			localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Running custom command on banned IP address : " .. ip .. " - " .. command)
		end
		--Windows
		localized.os_execute(command)
	elseif localized.system_os == "so" and number == 2 then
		if logging == 1 then
			--localized.ngx_log(localized.ngx_LOG_TYPE, "binformat: "..localized.system_os .. " - number: " .. number .. " - command: " .. command)
			localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Running custom command on banned IP address : " .. ip .. " - " .. command)
		end
		--Linux
		localized.os_execute(command)
	elseif localized.system_os == "dylib" and number == 3 then
		if logging == 1 then
			--localized.ngx_log(localized.ngx_LOG_TYPE, "binformat: "..localized.system_os .. " - number: " .. number .. " - command: " .. command)
			localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Running custom command on banned IP address : " .. ip .. " - " .. command)
		end
		--MacOS
		localized.os_execute(command)
	end
end

localized.blocked_address_check_count = 0
local function blocked_address_check(log_message, jsval)
	if localized.blocked_address_check_count > 1 then --so we dont run multiple times
		return
	end
	if localized.anti_ddos_table ~= nil and #localized.anti_ddos_table > 0 then
		for i=1,#localized.anti_ddos_table do
			if faster_than_match(localized.anti_ddos_table[i][1]) or localized.string_find(localized.URL, localized.anti_ddos_table[i][1]) then --if our host matches one in the table
				local rate_limit_window = localized.anti_ddos_table[i][8]
				local block_duration = localized.anti_ddos_table[i][10]
				if localized.request_limit == nil then
					localized.request_limit = localized.anti_ddos_table[i][19] or nil --What ever memory space your server has set / defined for this to use
				end
				if localized.blocked_addr == nil then
					localized.blocked_addr = localized.anti_ddos_table[i][20] or nil
				end
				if localized.ddos_counter == nil then
					localized.ddos_counter = localized.anti_ddos_table[i][21] or nil
				end
				local ip = localized.anti_ddos_table[i][22]
				if ip == "auto" then
					if localized.ngx_var_http_cf_connecting_ip ~= nil then
						if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
							ip = localized.ngx_var_http_cf_connecting_ip
						else --you are not really cloudflare dont pretend you are to bypass flood protection
							ip = localized.ngx_var_remote_addr
						end
					elseif localized.ngx_var_http_x_forwarded_for ~= nil then
						if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
							ip = localized.ngx_var_http_x_forwarded_for
						else
							ip = localized.ngx_var_remote_addr
						end
					else
						ip = localized.ngx_var_remote_addr
					end
				end
				if check_tor_onion() then
					ip = localized.tor_remote_addr --set ip as what the user wants the tor IP to be
					if localized.tor_remote_addr == "auto" then
						ip = localized.ngx_var_remote_addr
					end
				end
				if localized.request_limit ~= nil and localized.blocked_addr ~= nil and localized.ddos_counter ~= nil then --we can do so much more than the basic anti-ddos above
					if jsval ~= nil then
						if localized.jspuzzle_memory_zone == nil then
							localized.jspuzzle_memory_zone = localized.anti_ddos_table[i][29]
						end
						local jspuzzle_rate_limit_window = localized.anti_ddos_table[i][30]
						local jspuzzle_request_limit = localized.anti_ddos_table[i][31]
						if localized.jspuzzle_memory_zone ~= nil then
							local key = "r" .. ip --set identifyer as r and ip for to not use up to much memory
							local count = "" --create locals to use

							count = localized.jspuzzle_memory_zone:get(key) or nil
							if count == nil then
								localized.jspuzzle_memory_zone:set(key, 1, jspuzzle_rate_limit_window)
							else
								count = localized.jspuzzle_memory_zone:get(key)
								localized.jspuzzle_memory_zone:set(key, count+1, jspuzzle_rate_limit_window)
								count = localized.jspuzzle_memory_zone:get(key)
							end
							--Rate limit check
							if count ~= nil then
								if count > jspuzzle_request_limit then
									if ip_whitelist_flood_checks(localized.ip_whitelist) and check_tor_onion() == false then --if true then block ip
										--Block IP
										localized.blocked_addr:set(ip, localized.currenttime, block_duration)
										if localized.anti_ddos_table[i][32] ~= nil and localized.anti_ddos_table[i][32] ~= "" then
											if #localized.anti_ddos_table[i][32] > 0 then
												for o=1,#localized.anti_ddos_table[i][32] do
													check_system(o, localized.anti_ddos_table[i][32][o], localized.anti_ddos_table[i][7], ip)
												end
											end
										end
										localized.blocked_address_check_count = localized.blocked_address_check_count+2
									end
									local incr = localized.ddos_counter:get("blocked_ip") or nil
									if incr == nil then
										localized.ddos_counter:set("blocked_ip", 1, block_duration)
									else
										local incr = localized.ddos_counter:get("blocked_ip")
										localized.ddos_counter:set("blocked_ip", incr+1, block_duration)
									end
									if localized.anti_ddos_table[i][7] == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, log_message .. count .. " - " .. ip)
									end
								end
							end
						end
					else
						if ip_whitelist_flood_checks(localized.ip_whitelist) and check_tor_onion() == false then --if true then block ip
							--Block IP
							localized.blocked_addr:set(ip, localized.currenttime, block_duration)
							if localized.anti_ddos_table[i][32] ~= nil and localized.anti_ddos_table[i][32] ~= "" then
								if #localized.anti_ddos_table[i][32] > 0 then
									for o=1,#localized.anti_ddos_table[i][32] do
										check_system(o, localized.anti_ddos_table[i][32][o], localized.anti_ddos_table[i][7], ip)
									end
								end
							end
							localized.blocked_address_check_count = localized.blocked_address_check_count+2
						end
						local incr = localized.ddos_counter:get("blocked_ip") or nil
						if incr == nil then
							localized.ddos_counter:set("blocked_ip", 1, block_duration)
						else
							local incr = localized.ddos_counter:get("blocked_ip")
							localized.ddos_counter:set("blocked_ip", incr+1, block_duration)
						end
						if localized.anti_ddos_table[i][7] == 1 then
							localized.ngx_log(localized.ngx_LOG_TYPE, log_message .. ip)
						end
					end
				end
				break
			end
		end
	end
	localized.blocked_address_check_count = localized.blocked_address_check_count+2
end

--Anti DDoS function
local function anti_ddos()
	--local pcall = pcall
	--local require = require
	--local shdict = pcall(require, "resty.core.shdict") --check if resty core shdict function exists will be true or false

	--Slowhttp / Slowloris attack detection
	local function check_slowhttp(content_limit, timeout, connection_header_timeout, connection_header_max_conns, range_whitelist_blacklist, range_table, logging_value)
		local req_headers = localized.ngx_req_get_headers()

		--Expect: 100-continue Content-Length
		local expect = req_headers["expect"]
		if expect then
			if localized.type(expect) ~= "table" then
				if expect and localized.string_lower(expect) == "100-continue" then
					local content_length = req_headers["content-length"]
					if content_length then
						if localized.type(content_length) ~= "table" then
							local c_l = localized.tonumber(content_length or "0")
							if c_l > 0 and c_l < content_limit then
								if logging_value == 1 then
									localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Content-Length smaller than Limit.")
								end
								return true
							end
						else
							for i=1, #content_length do
								local c_l = localized.tonumber(content_length[i] or "0")
								if c_l > 0 and c_l < content_limit then
									if logging_value == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Content-Length smaller than Limit.")
									end
									return true
								end
							end
						end
					end
				end
			else
				for i=1, #expect do
					if expect[i] and localized.string_lower(expect[i]) == "100-continue" then
						local content_length = req_headers["content-length"]
						if content_length then
							if localized.type(content_length) ~= "table" then
								local c_l = localized.tonumber(content_length or "0")
								if c_l > 0 and c_l < content_limit then
									if logging_value == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Content-Length smaller than Limit.")
									end
									return true
								end
							else
								for i=1, #content_length do
									local c_l = localized.tonumber(content_length[i] or "0")
									if c_l > 0 and c_l < content_limit then
										if logging_value == 1 then
											localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Content-Length smaller than Limit.")
										end
										return true
									end
								end
							end
						end
					end
				end
			end
		end

		--Detect slow request time
		local request_time = localized.ngx_var.request_time
		if request_time and localized.tonumber(request_time) > timeout then
			if logging_value == 1 then
				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Slow request time exceeded timeout.")
			end
			return true
		end

		--Detect Connection header manipulation
		local connection = req_headers["connection"]
		if connection then
			if localized.type(connection) ~= "table" then
				if connection and localized.string_lower(connection) == "keep-alive" then
					local keep_alive = req_headers["keep-alive"]
					if keep_alive then
						if localized.type(keep_alive) ~= "table" then
							if keep_alive and localized.string_find(keep_alive, "timeout%s*=%s*(%-?%d+)") then
								local timeout = localized.tonumber(localized.string_match(keep_alive, "timeout%s*=%s*(%-?%d+)"))
								if timeout and timeout > connection_header_timeout then --if they send header to try to keep connection alive for more than set time
									if logging_value == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Keep-Alive Timeout header exceeded limit.")
									end
									return true
								end
							end
							if keep_alive and localized.string_find(keep_alive, "max%s*=%s*(%-?%d+)") then
								local max_keepalive = localized.tonumber(localized.string_match(keep_alive, "max%s*=%s*(%-?%d+)"))
								if max_keepalive and max_keepalive > connection_header_max_conns then --if they send header to set max connections to a ridiculous number
									if logging_value == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Keep-Alive Max connections header exceeded limit.")
									end
									return true
								end
							end
						else
							for i=1, #keep_alive do
								if keep_alive[i] and localized.string_find(keep_alive[i], "timeout%s*=%s*(%-?%d+)") then
									local timeout = localized.tonumber(localized.string_match(keep_alive[i], "timeout%s*=%s*(%-?%d+)"))
									if timeout and timeout > connection_header_timeout then --if they send header to try to keep connection alive for more than set time
										if logging_value == 1 then
											localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Keep-Alive Timeout header exceeded limit.")
										end
										return true
									end
								end
								if keep_alive[i] and localized.string_find(keep_alive[i], "max%s*=%s*(%-?%d+)") then
									local max_keepalive = localized.tonumber(localized.string_match(keep_alive[i], "max%s*=%s*(%-?%d+)"))
									if max_keepalive and max_keepalive > connection_header_max_conns then --if they send header to set max connections to a ridiculous number
										if logging_value == 1 then
											localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Keep-Alive Max connections header exceeded limit.")
										end
										return true
									end
								end
							end
						end
					end
				end
			else
				for i=1, #connection do
					if connection[i] and localized.string_lower(connection[i]) == "keep-alive" then
						local keep_alive = req_headers["keep-alive"]
						if keep_alive then
							if localized.type(keep_alive) ~= "table" then
								if keep_alive and localized.string_find(keep_alive, "timeout%s*=%s*(%-?%d+)") then
									local timeout = localized.tonumber(localized.string_match(keep_alive, "timeout%s*=%s*(%-?%d+)"))
									if timeout and timeout > connection_header_timeout then --if they send header to try to keep connection alive for more than set time
										if logging_value == 1 then
											localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Keep-Alive Timeout header exceeded limit.")
										end
										return true
									end
								end
								if keep_alive and localized.string_find(keep_alive, "max%s*=%s*(%-?%d+)") then
									local max_keepalive = localized.tonumber(localized.string_match(keep_alive, "max%s*=%s*(%-?%d+)"))
									if max_keepalive and max_keepalive > connection_header_max_conns then --if they send header to set max connections to a ridiculous number
										if logging_value == 1 then
											localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Keep-Alive Max connections header exceeded limit.")
										end
										return true
									end
								end
							else
								for i=1, #keep_alive do
									if keep_alive[i] and localized.string_find(keep_alive[i], "timeout%s*=%s*(%-?%d+)") then
										local timeout = localized.tonumber(localized.string_match(keep_alive[i], "timeout%s*=%s*(%-?%d+)"))
										if timeout and timeout > connection_header_timeout then --if they send header to try to keep connection alive for more than set time
											if logging_value == 1 then
												localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Keep-Alive Timeout header exceeded limit.")
											end
											return true
										end
									end
									if keep_alive[i] and localized.string_find(keep_alive[i], "max%s*=%s*(%-?%d+)") then
										local max_keepalive = localized.tonumber(localized.string_match(keep_alive[i], "max%s*=%s*(%-?%d+)"))
										if max_keepalive and max_keepalive > connection_header_max_conns then --if they send header to set max connections to a ridiculous number
											if logging_value == 1 then
												localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Keep-Alive Max connections header exceeded limit.")
											end
											return true
										end
									end
								end
							end
						end
					end
				end
			end
		end

		--Detect Range header manipulation slowhttp / slowloris range attack
		--curl -H "Range: bytes=5-1,5-2,5-3,5-4,5-5,5-6,5-7,5-8,5-9,5-10,5-11,5-12" http://localhost/video.mp4 --output "C:\Videos" -H "User-Agent: testagent"
		local range = req_headers["range"]
		if range then
			if localized.type(range) ~= "table" then
				--Filter by what we expect a range header to be provided with
				if localized.content_type_fix then
					get_resp_content_type() --grab content-type incase does not exist
				end
				if localized.content_type_fix == false or localized.ngx_header["content-type"] then --the content type that the user is requesting to use a range header on
					if #range_table > 0 then
						local whitelist_set = 0
						local regex_g = "%s*(%-?%d+)%s*-%s*(%-?%d+)%s*[^,]+" --multi segment regex
						local regex_m = "%s*(%-?%d+)%s*-%s*(%-?%d+)%s*" --single segment regex
						local regex_s = "%s*(%-?%d+)%s*" --single start segment
						local regex_c = "%s*(%-?%d+)%s*[^,]+" --single start segment comma seperated
						local _, count = localized.string_gsub(range, ","," , ") --fix commas
						local _ = localized.string_gsub(_, "%s+", "") --remove white space
						if not localized.string_find(_, ",$") then --if does not end in comma
							_ = _ .. "," --insert comma
						end
						local _, count = localized.string_gsub(_, ","," , ") --recount now that range is fixed
						for i=1,#range_table do
							if #range_table[i] > 0 then
								for x=1,#range_table[i] do
									if x == 1 and localized.content_type_fix then
										if range_table[i][x] ~= "" then
											if localized.string_find(localized.ngx_header["content-type"], range_table[i][x]) then
												if range_whitelist_blacklist == 0 then --0 blacklist 1 whitelist
													if logging_value == 1 then
														localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Blacklist match " .. range_table[i][x] )
													end
													--range header prohibited block request
													return true
												else --whitelist mode
													--range header provided only allowed on this resource
													whitelist_set = 1
												end
											end
										end
									end
									if x == 2 then --bytes= segment limiter to a max number
										if range_table[i][x] ~= "" then
											if count and localized.tonumber(count) > 1 then
												if localized.tonumber(count) > range_table[i][x] then
													if logging_value == 1 then
														localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Max MultiPart range Occurances exceeded: " .. count )
													end
													return true
												end
											end
										end
									end
									if x == 4 then
										if range_table[i][x] ~= "" then
											if count and localized.tonumber(count) > 1 then
												--for each segment
												local rcount = 0
												for start_byte, end_byte in localized.string_gmatch(_, regex_g) do
													rcount = rcount+1
													if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][3]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][4]) then
														if logging_value == 1 then
															localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte .. " occurance: " .. rcount)
														end
														return true
													end
													if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][3]) and localized.tonumber(end_byte) < localized.tonumber(range_table[i][4]) then
														if logging_value == 1 then
															localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value end = " .. end_byte .. " occurance: " .. rcount)
														end
														return true
													end
												end
												if rcount == 0 then
													for start_byte in localized.string_gmatch(_, regex_c) do
														if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][3]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][4]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte .. " occurance: " .. rcount)
															end
															return true
														end
													end
												end
											else
												local start_byte, end_byte = localized.string_match(_, regex_m)
												if start_byte or end_byte then
													if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][3]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][4]) then
														if logging_value == 1 then
															localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte )
														end
														return true
													end
													if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][3]) and localized.tonumber(end_byte) < localized.tonumber(range_table[i][4]) then
														if logging_value == 1 then
															localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value end = " .. end_byte )
														end
														return true
													end
												else
													local start_byte = localized.string_match(_, regex_s)
													if start_byte then
														if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][3]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][4]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte )
															end
															return true
														end
													end
												end
											end
										end
									end
									if x == 5 then
										if range_table[i][x] ~= "" then
											if not localized.string_find(_, range_table[i][x]) then --string match specified unit or block
												if logging_value == 1 then
													localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Not using acceptable Unit type " .. range_table[i][x])
												end
												--not using bytes block request not following standards https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Range
												--curl -H "Range: bits=0-199, 120-200" http://localhost/video.mp4 --output "C:\Videos" -H "User-Agent: testagent"
												return true
											end
										end
									end
									if x == 6 then --illegal chars
										if range_table[i][x] ~= "" then
											if localized.string_gsub(_, range_table[i][x], "") ~= "" then
												if logging_value == 1 then
													localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range header contains illegal chars " .. _ )
												end
												return true
											end
										end
									end
									if x == 7 then
										if range_table[i][x] ~= "" then
											if count and localized.tonumber(count) > 1 then
												--for each segment
												local rcount = 0
												for start_byte, end_byte in localized.string_gmatch(_, regex_g) do
													rcount = rcount+1
													if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x]) then
														if logging_value == 1 then
															localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte .. " occurance: " .. rcount)
														end
														return true
													end
													if end_byte and localized.tonumber(end_byte) < localized.tonumber(range_table[i][x]) then
														if logging_value == 1 then
															localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value end = " .. end_byte .. " occurance: " .. rcount)
														end
														return true
													end
												end
												if rcount == 0 then
													for start_byte in localized.string_gmatch(_, regex_c) do
														if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte .. " occurance: " .. rcount)
															end
															return true
														end
													end
												end
											else
												local start_byte, end_byte = localized.string_match(_, regex_m)
												if start_byte or end_byte then
													if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x]) then
														if logging_value == 1 then
															localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte )
														end
														return true
													end
													if end_byte and localized.tonumber(end_byte) < localized.tonumber(range_table[i][x]) then
														if logging_value == 1 then
															localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value end = " .. end_byte )
														end
														return true
													end
												else
													local start_byte = localized.string_match(_, regex_s)
													if start_byte then
														if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte )
															end
															return true
														end
													end
												end
											end
										end
									end --end 7
									if x == 8 then
										if range_table[i][x] ~= "" then
											if count and localized.tonumber(count) > 1 then
												--for each segment
												local rcount = 0
												for start_byte, end_byte in localized.string_gmatch(_, regex_g) do
													rcount = rcount+1
													if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x]) then
														if logging_value == 1 then
															localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte .. " occurance: " .. rcount)
														end
														return true
													end
													if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][x]) then
														if logging_value == 1 then
															localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value end = " .. end_byte .. " occurance: " .. rcount)
														end
														return true
													end
												end
												if rcount == 0 then
													for start_byte in localized.string_gmatch(_, regex_c) do
														if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte .. " occurance: " .. rcount)
															end
															return true
														end
													end
												end
											else
												local start_byte, end_byte = localized.string_match(_, regex_m)
												if start_byte or end_byte then
													if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x]) then
														if logging_value == 1 then
															localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte )
														end
														return true
													end
													if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][x]) then
														if logging_value == 1 then
															localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value end = " .. end_byte )
														end
														return true
													end
												else
													local start_byte = localized.string_match(_, regex_s)
													if start_byte then
														if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte )
															end
															return true
														end
													end
												end
											end
										end
									end --end 8
									if x == 9 then --table for specific occurance of multi byte range
										if range_table[i][x] ~= "" then
											if #range_table[i][x] > 0 then
												if count and localized.tonumber(count) > 1 then
													--for each segment
													local rcount = 0
													for start_byte, end_byte in localized.string_gmatch(_, regex_g) do
														rcount = rcount+1
														for z=1, #range_table[i][x] do
															if z == rcount then
																if range_table[i][x][z] ~= "" then
																	if range_table[i][x][z][1] and range_table[i][x][z][2] ~= "" then
																		if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][1]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][2]) then
																			if logging_value == 1 then
																				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte .. " occurance: " .. rcount)
																			end
																			return true
																		end
																		if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][x][z][1]) and localized.tonumber(end_byte) < localized.tonumber(range_table[i][x][z][2]) then
																			if logging_value == 1 then
																				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value end = " .. end_byte .. " occurance: " .. rcount)
																			end
																			return true
																		end
																	end
																	if range_table[i][x][z][3] and range_table[i][x][z][3] ~= "" then
																		if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][3]) then
																			if logging_value == 1 then
																				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte .. " occurance: " .. rcount)
																			end
																			return true
																		end
																		if end_byte and localized.tonumber(end_byte) < localized.tonumber(range_table[i][x][z][3]) then
																			if logging_value == 1 then
																				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value end = " .. end_byte .. " occurance: " .. rcount)
																			end
																			return true
																		end
																	end
																	if range_table[i][x][z][4] and range_table[i][x][z][4] ~= "" then
																		if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][4]) then
																			if logging_value == 1 then
																				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte .. " occurance: " .. rcount)
																			end
																			return true
																		end
																		if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][x][z][4]) then
																			if logging_value == 1 then
																				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value end = " .. end_byte .. " occurance: " .. rcount)
																			end
																			return true
																		end
																	end
																end
															end
														end
													end
													if rcount == 0 then
														local rcount = 0
														for start_byte in localized.string_gmatch(_, regex_c) do
															rcount = rcount+1
															for z=1, #range_table[i][x] do
																if z == rcount then
																	if range_table[i][x][z] ~= "" then
																		if range_table[i][x][z][1] and range_table[i][x][z][2] ~= "" then
																			if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][1]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][2]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte .. " occurance: " .. rcount)
																				end
																				return true
																			end
																		end
																		if range_table[i][x][z][3] and range_table[i][x][z][3] ~= "" then
																			if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][3]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte .. " occurance: " .. rcount)
																				end
																				return true
																			end
																		end
																		if range_table[i][x][z][4] and range_table[i][x][z][4] ~= "" then
																			if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][4]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte .. " occurance: " .. rcount)
																				end
																				return true
																			end
																		end
																	end
																end
															end
														end
													end
												else
													local start_byte, end_byte = localized.string_match(_, regex_m)
													if start_byte or end_byte then
														for z=1, #range_table[i][x] do
															if z == 1 then
																if range_table[i][x][z] ~= "" then
																	if range_table[i][x][z][1] and range_table[i][x][z][2] ~= "" then
																		if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][1]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][2]) then
																			if logging_value == 1 then
																				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte )
																			end
																			return true
																		end
																		if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][x][z][1]) and localized.tonumber(end_byte) < localized.tonumber(range_table[i][x][z][2]) then
																			if logging_value == 1 then
																				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value end = " .. end_byte )
																			end
																			return true
																		end
																	end
																	if range_table[i][x][z][3] and range_table[i][x][z][3] ~= "" then
																		if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][3]) then
																			if logging_value == 1 then
																				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte .. " occurance: " .. z)
																			end
																			return true
																		end
																		if end_byte and localized.tonumber(end_byte) < localized.tonumber(range_table[i][x][z][3]) then
																			if logging_value == 1 then
																				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value end = " .. end_byte .. " occurance: " .. z)
																			end
																			return true
																		end
																	end
																	if range_table[i][x][z][4] and range_table[i][x][z][4] ~= "" then
																		if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][4]) then
																			if logging_value == 1 then
																				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte .. " occurance: " .. z)
																			end
																			return true
																		end
																		if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][x][z][4]) then
																			if logging_value == 1 then
																				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value end = " .. end_byte .. " occurance: " .. z)
																			end
																			return true
																		end
																	end
																end
																break
															end
														end
													else
														local start_byte = localized.string_match(_, regex_s)
														for z=1, #range_table[i][x] do
															if z == 1 then
																if range_table[i][x][z] ~= "" then
																	if range_table[i][x][z][1] and range_table[i][x][z][2] ~= "" then
																		if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][1]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][2]) then
																			if logging_value == 1 then
																				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte )
																			end
																			return true
																		end
																	end
																	if range_table[i][x][z][3] and range_table[i][x][z][3] ~= "" then
																		if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][3]) then
																			if logging_value == 1 then
																				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte .. " occurance: " .. z)
																			end
																			return true
																		end
																	end
																	if range_table[i][x][z][4] and range_table[i][x][z][4] ~= "" then
																		if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][4]) then
																			if logging_value == 1 then
																				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte .. " occurance: " .. z)
																			end
																			return true
																		end
																	end
																end
																break
															end
														end
													end
												end
											end
										end
									end --end 7
								end
							end
						end
						if range_whitelist_blacklist == 1 then
							if whitelist_set == 1 then --no range provied found in whitelist block ?
								--localized.ngx_log(localized.ngx_LOG_TYPE, " Whitelist Match " .. range_whitelist_blacklist )
							else
								if logging_value == 1 then
									localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range provided not in Whitelist " .. range_whitelist_blacklist )
								end
								return true
							end
						end
					end
				end
			else
				for i=1, #range do
					--Filter by what we expect a range header to be provided with
					if localized.content_type_fix then
						get_resp_content_type() --grab content-type incase does not exist
					end
					if localized.content_type_fix == false or localized.ngx_header["content-type"] then --the content type that the user is requesting to use a range header on
						if #range_table > 0 then
							local whitelist_set = 0
							local regex_g = "%s*(%-?%d+)%s*-%s*(%-?%d+)%s*[^,]+" --multi segment regex
							local regex_m = "%s*(%-?%d+)%s*-%s*(%-?%d+)%s*" --single segment regex
							local regex_s = "%s*(%-?%d+)%s*" --single start segment
							local regex_c = "%s*(%-?%d+)%s*[^,]+" --single start segment comma seperated
							local _, count = localized.string_gsub(range[i], ","," , ") --fix commas
							local _ = localized.string_gsub(_, "%s+", "") --remove white space
							if not localized.string_find(_, ",$") then --if does not end in comma
								_ = _ .. "," --insert comma
							end
							local _, count = localized.string_gsub(_, ","," , ") --recount now that range is fixed
							for i=1,#range_table do
								if #range_table[i] > 0 then
									for x=1,#range_table[i] do
										if x == 1 and localized.content_type_fix then
											if range_table[i][x] ~= "" then
												if localized.string_find(localized.ngx_header["content-type"], range_table[i][x]) then
													if range_whitelist_blacklist == 0 then --0 blacklist 1 whitelist
														if logging_value == 1 then
															localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Blacklist match " .. range_table[i][x] )
														end
														--range header prohibited block request
														return true
													else --whitelist mode
														--range header provided only allowed on this resource
														whitelist_set = 1
													end
												end
											end
										end
										if x == 2 then --bytes= segment limiter to a max number
											if range_table[i][x] ~= "" then
												if count and localized.tonumber(count) > 1 then
													if localized.tonumber(count) > range_table[i][x] then
														if logging_value == 1 then
															localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Max MultiPart range Occurances exceeded: " .. count )
														end
														return true
													end
												end
											end
										end
										if x == 4 then
											if range_table[i][x] ~= "" then
												if count and localized.tonumber(count) > 1 then
													--for each segment
													local rcount = 0
													for start_byte, end_byte in localized.string_gmatch(_, regex_g) do
														rcount = rcount+1
														if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][3]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][4]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte .. " occurance: " .. rcount)
															end
															return true
														end
														if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][3]) and localized.tonumber(end_byte) < localized.tonumber(range_table[i][4]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value end = " .. end_byte .. " occurance: " .. rcount)
															end
															return true
														end
													end
													if rcount == 0 then
														for start_byte in localized.string_gmatch(_, regex_c) do
															if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][3]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][4]) then
																if logging_value == 1 then
																	localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte .. " occurance: " .. rcount)
																end
																return true
															end
														end
													end
												else
													local start_byte, end_byte = localized.string_match(_, regex_m)
													if start_byte or end_byte then
														if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][3]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][4]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte )
															end
															return true
														end
														if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][3]) and localized.tonumber(end_byte) < localized.tonumber(range_table[i][4]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value end = " .. end_byte )
															end
															return true
														end
													else
														local start_byte = localized.string_match(_, regex_s)
														if start_byte then
															if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][3]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][4]) then
																if logging_value == 1 then
																	localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte )
																end
																return true
															end
														end
													end
												end
											end
										end --end 4
										if x == 5 then
											if range_table[i][x] ~= "" then
												if not localized.string_find(_, range_table[i][x]) then --string match specified unit or block
													if logging_value == 1 then
														localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Not using acceptable Unit type " .. range_table[i][x])
													end
													--not using bytes block request not following standards https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Range
													--curl -H "Range: bits=0-199, 120-200" http://localhost/video.mp4 --output "C:\Videos" -H "User-Agent: testagent"
													return true
												end
											end
										end
										if x == 6 then --illegal chars
											if range_table[i][x] ~= "" then
												if localized.string_gsub(_, range_table[i][x], "") ~= "" then
													if logging_value == 1 then
														localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range header contains illegal chars " .. _ )
													end
													return true
												end
											end
										end
										if x == 7 then
											if range_table[i][x] ~= "" then
												if count and localized.tonumber(count) > 1 then
													--for each segment
													local rcount = 0
													for start_byte, end_byte in localized.string_gmatch(_, regex_g) do
														rcount = rcount+1
														if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte .. " occurance: " .. rcount)
															end
															return true
														end
														if end_byte and localized.tonumber(end_byte) < localized.tonumber(range_table[i][x]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value end = " .. end_byte .. " occurance: " .. rcount)
															end
															return true
														end
													end
													if rcount == 0 then
														for start_byte in localized.string_gmatch(_, regex_c) do
															if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x]) then
																if logging_value == 1 then
																	localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte .. " occurance: " .. rcount)
																end
																return true
															end
														end
													end
												else
													local start_byte, end_byte = localized.string_match(_, regex_m)
													if start_byte or end_byte then
														if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte )
															end
															return true
														end
														if end_byte and localized.tonumber(end_byte) < localized.tonumber(range_table[i][x]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value end = " .. end_byte )
															end
															return true
														end
													else
														local start_byte = localized.string_match(_, regex_s)
														if start_byte then
															if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x]) then
																if logging_value == 1 then
																	localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte )
																end
																return true
															end
														end
													end
												end
											end
										end --end 7
										if x == 8 then
											if range_table[i][x] ~= "" then
												if count and localized.tonumber(count) > 1 then
													--for each segment
													local rcount = 0
													for start_byte, end_byte in localized.string_gmatch(_, regex_g) do
														rcount = rcount+1
														if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte .. " occurance: " .. rcount)
															end
															return true
														end
														if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][x]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value end = " .. end_byte .. " occurance: " .. rcount)
															end
															return true
														end
													end
													if rcount == 0 then
														for start_byte in localized.string_gmatch(_, regex_c) do
															if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x]) then
																if logging_value == 1 then
																	localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte .. " occurance: " .. rcount)
																end
																return true
															end
														end
													end
												else
													local start_byte, end_byte = localized.string_match(_, regex_m)
													if start_byte or end_byte then
														if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte )
															end
															return true
														end
														if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][x]) then
															if logging_value == 1 then
																localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value end = " .. end_byte )
															end
															return true
														end
													else
														local start_byte = localized.string_match(_, regex_s)
														if start_byte then
															if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x]) then
																if logging_value == 1 then
																	localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte )
																end
																return true
															end
														end
													end
												end
											end
										end --end 8
										if x == 9 then --table for specific occurance of multi byte range
											if range_table[i][x] ~= "" then
												if #range_table[i][x] > 0 then
													if count and localized.tonumber(count) > 1 then
														--for each segment
														local rcount = 0
														for start_byte, end_byte in localized.string_gmatch(_, regex_g) do
															rcount = rcount+1
															for z=1, #range_table[i][x] do
																if z == rcount then
																	if range_table[i][x][z] ~= "" then
																		if range_table[i][x][z][1] and range_table[i][x][z][2] ~= "" then
																			if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][1]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][2]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte .. " occurance: " .. rcount)
																				end
																				return true
																			end
																			if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][x][z][1]) and localized.tonumber(end_byte) < localized.tonumber(range_table[i][x][z][2]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value end = " .. end_byte .. " occurance: " .. rcount)
																				end
																				return true
																			end
																		end
																		if range_table[i][x][z][3] and range_table[i][x][z][3] ~= "" then
																			if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][3]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte .. " occurance: " .. rcount)
																				end
																				return true
																			end
																			if end_byte and localized.tonumber(end_byte) < localized.tonumber(range_table[i][x][z][3]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value end = " .. end_byte .. " occurance: " .. rcount)
																				end
																				return true
																			end
																		end
																		if range_table[i][x][z][4] and range_table[i][x][z][4] ~= "" then
																			if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][4]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte .. " occurance: " .. rcount)
																				end
																				return true
																			end
																			if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][x][z][4]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value end = " .. end_byte .. " occurance: " .. rcount)
																				end
																				return true
																			end
																		end
																	end
																end
															end
														end
														if rcount == 0 then
															local rcount = 0
															for start_byte in localized.string_gmatch(_, regex_c) do
																rcount = rcount+1
																for z=1, #range_table[i][x] do
																	if z == rcount then
																		if range_table[i][x][z] ~= "" then
																			if range_table[i][x][z][1] and range_table[i][x][z][2] ~= "" then
																				if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][1]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][2]) then
																					if logging_value == 1 then
																						localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte .. " occurance: " .. rcount)
																					end
																					return true
																				end
																			end
																			if range_table[i][x][z][3] and range_table[i][x][z][3] ~= "" then
																				if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][3]) then
																					if logging_value == 1 then
																						localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte .. " occurance: " .. rcount)
																					end
																					return true
																				end
																			end
																			if range_table[i][x][z][4] and range_table[i][x][z][4] ~= "" then
																				if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][4]) then
																					if logging_value == 1 then
																						localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte .. " occurance: " .. rcount)
																					end
																					return true
																				end
																			end
																		end
																	end
																end
															end
														end
													else
														local start_byte, end_byte = localized.string_match(_, regex_m)
														if start_byte or end_byte then
															for z=1, #range_table[i][x] do
																if z == 1 then
																	if range_table[i][x][z] ~= "" then
																		if range_table[i][x][z][1] and range_table[i][x][z][2] ~= "" then
																			if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][1]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][2]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte )
																				end
																				return true
																			end
																			if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][x][z][1]) and localized.tonumber(end_byte) < localized.tonumber(range_table[i][x][z][2]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value end = " .. end_byte )
																				end
																				return true
																			end
																		end
																		if range_table[i][x][z][3] and range_table[i][x][z][3] ~= "" then
																			if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][3]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte .. " occurance: " .. z)
																				end
																				return true
																			end
																			if end_byte and localized.tonumber(end_byte) < localized.tonumber(range_table[i][x][z][3]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value end = " .. end_byte .. " occurance: " .. z)
																				end
																				return true
																			end
																		end
																		if range_table[i][x][z][4] and range_table[i][x][z][4] ~= "" then
																			if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][4]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte .. " occurance: " .. z)
																				end
																				return true
																			end
																			if end_byte and localized.tonumber(end_byte) > localized.tonumber(range_table[i][x][z][4]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value end = " .. end_byte .. " occurance: " .. z)
																				end
																				return true
																			end
																		end
																	end
																	break
																end
															end
														else
															local start_byte = localized.string_match(_, regex_s)
															for z=1, #range_table[i][x] do
																if z == 1 then
																	if range_table[i][x][z] ~= "" then
																		if range_table[i][x][z][1] and range_table[i][x][z][2] ~= "" then
																			if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][1]) and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][2]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range within min and max value start = " .. start_byte )
																				end
																				return true
																			end
																		end
																		if range_table[i][x][z][3] and range_table[i][x][z][3] ~= "" then
																			if start_byte and localized.tonumber(start_byte) < localized.tonumber(range_table[i][x][z][3]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range Less Than value start = " .. start_byte .. " occurance: " .. z)
																				end
																				return true
																			end
																		end
																		if range_table[i][x][z][4] and range_table[i][x][z][4] ~= "" then
																			if start_byte and localized.tonumber(start_byte) > localized.tonumber(range_table[i][x][z][4]) then
																				if logging_value == 1 then
																					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range More Than value start = " .. start_byte .. " occurance: " .. z)
																				end
																				return true
																			end
																		end
																	end
																	break
																end
															end
														end
													end
												end
											end
										end --end 7
									end
								end
							end
							if range_whitelist_blacklist == 1 then
								if whitelist_set == 1 then --no range provied found in whitelist block ?
									--localized.ngx_log(localized.ngx_LOG_TYPE, " Whitelist Match " .. range_whitelist_blacklist )
								else
									if logging_value == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Range Header] Range provided not in Whitelist " .. range_whitelist_blacklist )
									end
									return true
								end
							end
						end
					end
				end
			end
		end

		return false
	end

	--Rate limit per user
	local function check_rate_limit(ip, rate_limit_window, rate_limit_requests, block_duration, request_limit, ddos_counter, logging)
		local key = "r" .. ip --set identifyer as r and ip for to not use up to much memory
		local count, err = "" --create locals to use

		--if shdict then --backwards compatibility for lua
			--count, err = localized.request_limit:incr(key, 1, 0, rate_limit_window)
			--if not count then
				--if logging == 1 then
					--localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Rate limit error: " .. err)
				--end
				--return false
			--end
		--else --older lua version

			count = localized.request_limit:get(key) or nil
			if count == nil then
				localized.request_limit:set(key, 1, rate_limit_window)
				return false
			else
				count = localized.request_limit:get(key)
				localized.request_limit:set(key, count+1, rate_limit_window)
				count = localized.request_limit:get(key)
			end
		--end

		--Rate limit check
		if count > rate_limit_requests then
			if logging == 1 then
				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Rate limit exceeded by IP: " .. ip .. " (Max requests = " .. rate_limit_requests.. " client has made (" .. count .. " requests)")
			end

			--if shdict then --backwards compatibility for lua
				--local incr, err = localized.ddos_counter:incr("blocked_ip", 1, 0, block_duration)
				--if not incr then
					--if logging == 1 then
						--localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] TOTAL IN SHARED error: " .. err)
					--end
				--end
			--else --older lua version
			
				local incr = localized.ddos_counter:get("blocked_ip") or nil
				if incr == nil then
					localized.ddos_counter:set("blocked_ip", 1, block_duration)
				else
					local incr = localized.ddos_counter:get("blocked_ip")
					localized.ddos_counter:set("blocked_ip", incr+1, block_duration)
				end
			--end

			return true
		end

		return false
	end

	if localized.anti_ddos_table ~= nil and #localized.anti_ddos_table > 0 then
		for i=1,#localized.anti_ddos_table do --for each host/path in our table
			local v = localized.anti_ddos_table[i]
			if faster_than_match(v[1]) or localized.string_find(localized.URL, v[1]) then --if our host matches one in the table
				if localized.request_limit == nil then
					localized.request_limit = v[19] or nil --What ever memory space your server has set / defined for this to use
				end
				if localized.blocked_addr == nil then
					localized.blocked_addr = v[20] or nil
				end
				if localized.ddos_counter == nil then
					localized.ddos_counter = v[21] or nil
				end

				if localized.request_limit ~= nil and localized.blocked_addr ~= nil and localized.ddos_counter ~= nil then --we can do so much more than the basic anti-ddos above
					local rate_limit_window = v[8]
					local rate_limit_requests = v[9]
					local block_duration = v[10]
					local rate_limit_exit_status = v[11]
					local content_limit = v[12]
					local timeout = v[13]
					local connection_header_timeout = v[14]
					local connection_header_max_conns = v[15]
					local slow_limit_exit_status = v[16]
					local range_whitelist_blacklist = v[17]
					local range_table = v[18]
					local ip = v[22]

					local total_requests = localized.ddos_counter:get("blocked_ip") or 0
					if v[33] == 1 then
						if total_requests > v[24] then --Automatically enable I am Under Attack Mode so disable logging
							v[7] = 0 --disable logging to prevent denil of service from excessive log file writes using up disk I/O
						end
					end

					if v[2] >= 1 then --limit keep alive ip
						if localized.tonumber(localized.ngx_var_connection_requests) >= v[2] then
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE,"[Anti-DDoS] Exceeded Number of keepalive conns from IP " .. localized.ngx_var_connection_requests )
							end
							localized.ngx_exit(v[3])
						end
					end
					if v[4] >= 1 then --limit request size smaller than
						if localized.tonumber(localized.ngx_var_request_length) <= v[4] then --1000 bytes = 1kb
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE,"[Anti-DDoS] Request Smaller than allowed LENGTH in bytes " .. localized.ngx_var_request_length )
							end
							localized.ngx_exit(v[6])
						end
					end
					if v[5] >= 1 then --limit request size greater than
						if localized.tonumber(localized.ngx_var_request_length) >= v[5] then --1000 bytes = 1kb
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE,"[Anti-DDoS] Request Larger than allowed LENGTH in bytes " .. localized.ngx_var_request_length )
							end
							localized.ngx_exit(v[6])
						end
					end

					if ip == "auto" then
						--localized.ngx_log(localized.ngx_LOG_TYPE, "Proxy IP found in whitelist - " .. localized.tostring(proxy_header_ip_check(localized.proxy_header_table)) .. " http_internal = " .. localized.tostring(localized.ngx_var_http_internal)  )
						if localized.ngx_var_http_cf_connecting_ip ~= nil then
							if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
								ip = localized.ngx_var_http_cf_connecting_ip
							else --you are not really cloudflare dont pretend you are to bypass flood protection
								if localized.ngx_var_http_internal_log == 1 then --log the internal request headers
									localized.ngx_log(localized.ngx_LOG_TYPE, " we expect these to match - " .. localized.tostring(localized.ngx_var_http_internal) .. " and " .. localized.tostring(localized.ngx_var_http_internal_string) )
								end
								if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then --1st run this nil 2nd run not nil
									if localized.ngx_var_http_internal_log == 1 then --log the internal request headers
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) here 1 : ")
									end
									if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
										blocked_address_check("[Anti-DDoS] (1) Blocked IP for attempting to impersonate cloudflare via header CF-Connecting-IP : ")
									end
								else
									if localized.ngx_var_http_internal_log == 1 then --log the internal request headers
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) here 2 : ")
									end
									if localized.ngx_var_http_internal_log == 1 and localized.ngx_var_http_internal == nil then --2nd layer
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) internal call to bypass IP Block : " .. localized.ngx_var_remote_addr)
									end
								end
								ip = localized.ngx_var_remote_addr
							end
						elseif localized.ngx_var_http_x_forwarded_for ~= nil then
							if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
								ip = localized.ngx_var_http_x_forwarded_for
							else
								if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
									if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
										blocked_address_check("[Anti-DDoS] (1) Blocked IP for attempting to impersonate proxy via header X-Forwarded-For : ")
									end
								else
									if localized.ngx_var_http_internal_log == 1 and localized.ngx_var_http_internal ~= nil then --2nd layer
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) internal call to bypass IP Block : " .. localized.ngx_var_remote_addr)
									end
								end
								ip = localized.ngx_var_remote_addr
							end
						else
							ip = localized.ngx_var_remote_addr
						end
					end
					if check_tor_onion() then
						v[23] = 0 --enable or disable automatic under attack
						--v[24] = 0 --number of ips to enable automatic under attack
						ip = localized.tor_remote_addr --set ip as what the user wants the tor IP to be
						if localized.tor_remote_addr == "auto" then
							ip = localized.ngx_var_remote_addr
						end
					end

					--[[ --dev test to show to log file each users request count
					local incr = localized.ddos_counter:get("blocked_ip") or 0
					if incr ~= nil then
						local incr = localized.ddos_counter:get("blocked_ip")
						localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Total number of IP's in block list : " .. incr)
					end
					]]

					if localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
						local blocked_time = localized.blocked_addr:get(ip)
						if blocked_time then
							if v[7] == 1 then
								if v[23] == 1 then
									if total_requests < v[24] then --Less than required amount to trigger Automatically enable I am Under Attack Mode so enable logging
										--localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (2) Blocked IP attempt: " .. ip .. " - URL : " .. localized.URL )
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (2) Blocked IP attempt: " .. ip .. " - URL : " .. localized.URL .. " - Ban extended/ends on : " .. localized.ngx_cookie_time(blocked_time+block_duration) ) --ngx_cookie_time can be slow dont use this under attack
									end
								end
							end
							localized.blocked_addr:set(ip, localized.currenttime, block_duration) --update with current time to extend ban duration
							if rate_limit_exit_status ~= 444 and rate_limit_exit_status ~= 204 then --no point with gzip on these
								localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip --this can slow down nginx tested via 100,000,000 requests nulled out on the block pages
							end
							if v[32] ~= nil and v[32] ~= "" then
								if #v[32] > 0 then
									for o=1,#v[32] do
										check_system(o, v[32][o], v[7], ip)
									end
								end
							end

							return localized.ngx_exit(rate_limit_exit_status)
						end

						if ip_whitelist_flood_checks(localized.ip_whitelist) and check_tor_onion() == false then --if true then block ip
							if check_rate_limit(ip, rate_limit_window, rate_limit_requests, block_duration, request_limit, ddos_counter, v[7]) then
								--Block IP
								localized.blocked_addr:set(ip, localized.currenttime, block_duration)
								if v[32] ~= nil and v[32] ~= "" then
									if #v[32] > 0 then
										for o=1,#v[32] do
											check_system(o, v[32][o], v[7], ip)
										end
									end
								end
								if rate_limit_exit_status ~= 444 and rate_limit_exit_status ~= 204 then --no point with gzip on these
									localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
								end
								return localized.ngx_exit(rate_limit_exit_status)
							end
						end

						if ip_whitelist_flood_checks(localized.ip_whitelist) and check_tor_onion() == false then --if true then block ip
							if check_slowhttp(content_limit, timeout, connection_header_timeout, connection_header_max_conns, range_whitelist_blacklist, range_table, v[7]) then
								--Block IP
								localized.blocked_addr:set(ip, localized.currenttime, block_duration)
								if v[32] ~= nil and v[32] ~= "" then
									if #v[32] > 0 then
										for o=1,#v[32] do
											check_system(o, v[32][o], v[7], ip)
										end
									end
								end
								if v[7] == 1 then
									localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] SlowHTTP / Slowloris attack detected from: " .. ip)
								end
								if slow_limit_exit_status ~= 444 and slow_limit_exit_status ~= 204 then --no point with gzip on these
									localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
								end

								return localized.ngx_exit(slow_limit_exit_status)
							end
						end
						if localized.ngx_var_http_internal_log == 1 then --log the internal request headers
							localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] attempting 1st ")
						end
					else
						if localized.ngx_var_http_internal_log == 1 then --log the internal request headers
							localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] attempting 2nd ")
						end
					end

					if v[23] == 1 then
						if total_requests >= v[24] then --Automatically enable I am Under Attack Mode
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (I am Under Attack Mode is ON) Total number of IP's in block list : " .. total_requests)
							end
							--Automatic Detection of DDoS
							--Disable GZIP to prevent GZIP memory bomb and CPU consumption attacks.
							localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
							--MASTER SWITCH ENGAGED
							localized.master_switch = 1 --enabled for all sites
						else
							localized.master_switch = 2 --disabled
						end
					end

					if #v[25] > 0 then --make sure the 24th var is a lua table and has values
						for i=1,#v[25] do --for each in our table
							if #v[25][i] > 0 then --if subtable has values
								local table_head_val = v[25][i][1] or nil
								local req_headers = localized.ngx_req_get_headers()
								local header_value = req_headers[localized.tostring(table_head_val)] or ""
								if header_value then
									if localized.type(header_value) ~= "table" then
										if localized.string_find(localized.string_lower(header_value), localized.string_lower(v[25][i][2])) then
											if v[25][i][4] > 0 then --add to ban list
												if ip_whitelist_flood_checks(localized.ip_whitelist) and check_tor_onion() == false then --if true then block ip
													if v[7] == 1 then
														localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Blocked sending prohibited header : " .. localized.string_lower(header_value) .. " - " .. ip)
													end
													--Block IP
													localized.blocked_addr:set(ip, localized.currenttime, block_duration)
												end
											end
											if v[25][i][3] ~= 444 and v[25][i][3] ~= 204 then --no point with gzip on these
												localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
											end
											localized.ngx_exit(v[25][i][3])
										end
									else
										for i=1, #header_value do
											if localized.string_find(localized.string_lower(header_value[i]), localized.string_lower(v[25][i][2])) then
												if v[25][i][4] > 0 then --add to ban list
													if ip_whitelist_flood_checks(localized.ip_whitelist) and check_tor_onion() == false then --if true then block ip
														if v[7] == 1 then
															localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Blocked sending prohibited header : " .. localized.string_lower(header_value[i]) .. " - " .. ip)
														end
														--Block IP
														localized.blocked_addr:set(ip, localized.currenttime, block_duration)
													end
												end
												if v[25][i][3] ~= 444 and v[25][i][3] ~= 204 then --no point with gzip on these
													localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
												end
												localized.ngx_exit(v[25][i][3])
											end
										end
									end
								end
							end
						end
					end

					if #v[26] > 0 then
						for i=1,#v[26] do
							if localized.string_lower(localized.ngx_var.request_method) == localized.string_lower(v[26][i][1]) then
								if v[26][i][3] > 0 then
									if ip_whitelist_flood_checks(localized.ip_whitelist) and check_tor_onion() == false then --if true then block ip
										if v[7] == 1 then
											localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Blocked using prohibited Request Method : " .. localized.ngx_var.request_method .. " - " .. ip)
										end
										--Block IP
										localized.blocked_addr:set(ip, localized.currenttime, block_duration)
									end
								end
								if v[26][i][2] ~= 444 and v[26][i][2] ~= 204 then --no point with gzip on these
									localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
								end
								localized.ngx_exit(v[26][i][2])
							end
						end
					end

					if v[27] < 1 then --disable gzip option
						localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
					end

					if v[28] > 0 then --dsiable compression when banlist has more than certain number of ips automated protection
						if total_requests >= v[24] then --Automatically enable I am Under Attack Mode
							localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
						end
					end

				else
					local content_limit = v[12]
					local timeout = v[13]
					local connection_header_timeout = v[14]
					local connection_header_max_conns = v[15]
					local slow_limit_exit_status = v[16]
					local range_whitelist_blacklist = v[17]
					local range_table = v[18]
					local ip = v[22]

					if v[2] >= 1 then --limit keep alive ip
						if localized.tonumber(localized.ngx_var_connection_requests) >= v[2] then
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE,"[Anti-DDoS] Exceeded Number of keepalive conns from IP " .. localized.ngx_var_connection_requests )
							end
							localized.ngx_exit(v[3])
						end
					end
					if v[4] >= 1 then --limit request size smaller than
						if localized.tonumber(localized.ngx_var_request_length) <= v[4] then --1000 bytes = 1kb
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE,"[Anti-DDoS] Request Smaller than allowed LENGTH in bytes " .. localized.ngx_var_request_length )
							end
							localized.ngx_exit(v[6])
						end
					end
					if v[5] >= 1 then --limit request size greater than
						if localized.tonumber(localized.ngx_var_request_length) >= v[5] then --1000 bytes = 1kb
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE,"[Anti-DDoS] Request Larger than allowed LENGTH in bytes " .. localized.ngx_var_request_length )
							end
							localized.ngx_exit(v[6])
						end
					end

					if ip == "auto" then
						--localized.ngx_log(localized.ngx_LOG_TYPE, "Proxy IP found in whitelist - " .. localized.tostring(proxy_header_ip_check(localized.proxy_header_table)) .. " http_internal = " .. localized.tostring(localized.ngx_var_http_internal)  )
						if localized.ngx_var_http_cf_connecting_ip ~= nil then
							if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
								ip = localized.ngx_var_http_cf_connecting_ip
							else --you are not really cloudflare dont pretend you are to bypass flood protection
								ip = localized.ngx_var_remote_addr
							end
						elseif localized.ngx_var_http_x_forwarded_for ~= nil then
							if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
								ip = localized.ngx_var_http_x_forwarded_for
							else
								ip = localized.ngx_var_remote_addr
							end
						else
							ip = localized.ngx_var_remote_addr
						end
					end
					if check_tor_onion() then
						v[23] = 0
						v[24] = 0
						ip = localized.tor_remote_addr --set ip as what the user wants the tor IP to be
						if localized.tor_remote_addr == "auto" then
							ip = localized.ngx_var_remote_addr
						end
					end

					--no shared memory set but we can still check and block slowhttp cons without shared memory
					if localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
						if check_slowhttp(content_limit, timeout, connection_header_timeout, connection_header_max_conns, range_whitelist_blacklist, range_table) then
							if slow_limit_exit_status ~= 444 and slow_limit_exit_status ~= 204 then --no point with gzip on these
								localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
							end
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] SlowHTTP / Slowloris attack detected from: " .. ip)
							end
							return localized.ngx_exit(slow_limit_exit_status)
						end
					end

					if #v[25] > 0 then --make sure the 24th var is a lua table and has values
						for i=1,#v[25] do --for each in our table
							local t = v[25][i]
							if #t > 0 then --if subtable has values
								local table_head_val = t[1] or nil
								local req_headers = localized.ngx_req_get_headers()
								local header_value = req_headers[localized.tostring(table_head_val)] or ""
								if header_value then
									if localized.type(header_value) ~= "table" then
										if localized.string_find(localized.string_lower(header_value), localized.string_lower(t[2])) then
											if v[7] == 1 then
												localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Blocked sending prohibited header : " .. localized.string_lower(header_value) .. " - " .. ip)
											end
											if t[3] ~= 444 and t[3] ~= 204 then --no point with gzip on these
												localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
											end
											localized.ngx_exit(t[3])
										end
									else
										for i=1, #header_value do
											if localized.string_find(localized.string_lower(header_value[i]), localized.string_lower(t[2])) then
												if v[7] == 1 then
													localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Blocked sending prohibited header : " .. localized.string_lower(header_value[i]) .. " - " .. ip)
												end
												if t[3] ~= 444 and t[3] ~= 204 then --no point with gzip on these
													localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
												end
												localized.ngx_exit(t[3])
											end
										end
									end
								end
							end
						end
					end

					if #v[26] > 0 then
						for i=1,#v[26] do
							if localized.string_lower(localized.ngx_var.request_method) == localized.string_lower(v[26][i][1]) then
								if v[7] == 1 then
									localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Blocked using prohibited Request Method : " .. localized.ngx_var.request_method .. " - " .. ip)
								end
								if v[26][i][2] ~= 444 and v[26][i][2] ~= 204 then --no point with gzip on these
									localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
								end
								localized.ngx_exit(v[26][i][2])
							end
						end
					end

					if v[27] < 1 then --disable gzip option
						localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
					end

				end
				break --break out of the for each loop pointless to keep searching the rest since we matched our host
			end
		end
	end
end
--if localized.ngx_var_http_internal == nil then --1st layer
anti_ddos()
--end

-- Random seed generator
local function getRandomSeed()
	local collectgarbage = collectgarbage
	local a = collectgarbage("count")
	local b = localized.currenttime
	local c = localized.tostring(a) .. localized.tostring(b)
	local d = (localized.math_pi * b + localized.math_sqrt(a + 1)) % 4294967296
	c = c .. localized.tostring(d)
	local e = 0
	for i=1,#c do
		local f = localized.string_byte(c, i)
		e = (e * 33 + f) % 4294967296
	end
	return localized.math_floor(e)
end

local function run_checks() --nested function

	local master_exit_var = 0
	local function master_exit()
		master_exit_var = 1
		--return localized.ngx_exit(localized.ngx_OK) --Go to content
		return ""
	end
	--master_exit()
	--[[
	if master_exit_var == 1 then
		return
	end
	]]

--[[
Header Modifications
]]
local function header_modification()
	if localized.custom_headers ~= nil and #localized.custom_headers > 0 then
		for i=1,#localized.custom_headers do --for each host in our table
			local v = localized.custom_headers[i]
			if faster_than_match(v[1]) or localized.string_find(localized.URL, v[1]) then --if our host matches one in the table
				for first=1,#v[2] do --for each arg in our table
					local value1 = v[2][first][1]
					local value2 = v[2][first][2]
					if value1 ~= nil and value2 ~= nil then
						localized.ngx_header[value1] = value2
					end
					if value2 == nil then
						localized.ngx_header[value1] = nil --remove the header
					end
				end
			end
		end
	end
end
--if localized.ngx_var_http_internal == nil then --1st layer
header_modification()
--end
--[[
End Header Modifications
]]

--automatically figure out the IP address of the connecting Client
if localized.remote_addr == "auto" then
if localized.ngx_var_http_cf_connecting_ip ~= nil then
		if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
			localized.remote_addr = localized.ngx_var_http_cf_connecting_ip
		else --you are not really cloudflare dont pretend you are to bypass flood protection
			if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
				if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
					blocked_address_check("[Anti-DDoS] (2) Blocked IP for attempting to impersonate cloudflare via header CF-Connecting-IP : ")
				end
			end
			localized.remote_addr = localized.ngx_var_remote_addr
		end
	elseif localized.ngx_var_http_x_forwarded_for ~= nil then
		if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
			localized.remote_addr = localized.ngx_var_http_x_forwarded_for
		else
			if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
				if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
					blocked_address_check("[Anti-DDoS] (2) Blocked IP for attempting to impersonate proxy via header X-Forwarded-For : ")
				end
			end
			localized.remote_addr = localized.ngx_var_remote_addr
		end
	else
		localized.remote_addr = localized.ngx_var_remote_addr
	end
end
if localized.ip_whitelist_remote_addr == "auto" then
	if localized.ngx_var_http_cf_connecting_ip ~= nil then
		if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
			localized.ip_whitelist_remote_addr = localized.ngx_var_http_cf_connecting_ip
		else --you are not really cloudflare dont pretend you are to bypass flood protection
			if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
				if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
					blocked_address_check("[Anti-DDoS] (3) Blocked IP for attempting to impersonate cloudflare via header CF-Connecting-IP : ")
				end
			end
			localized.ip_whitelist_remote_addr = localized.ngx_var_remote_addr
		end
	elseif localized.ngx_var_http_x_forwarded_for ~= nil then
		if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
			localized.ip_whitelist_remote_addr = localized.ngx_var_http_x_forwarded_for
		else
			if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
				if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
					blocked_address_check("[Anti-DDoS] (3) Blocked IP for attempting to impersonate proxy via header X-Forwarded-For : ")
				end
			end
			localized.ip_whitelist_remote_addr = localized.ngx_var_remote_addr
		end
	else
		localized.ip_whitelist_remote_addr = localized.ngx_var_remote_addr
	end
end
if localized.ip_blacklist_remote_addr == "auto" then
	if localized.ngx_var_http_cf_connecting_ip ~= nil then
		if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
			localized.ip_blacklist_remote_addr = localized.ngx_var_http_cf_connecting_ip
		else --you are not really cloudflare dont pretend you are to bypass flood protection
			if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
				if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
					blocked_address_check("[Anti-DDoS] (4) Blocked IP for attempting to impersonate cloudflare via header CF-Connecting-IP : ")
				end
			end
			localized.ip_blacklist_remote_addr = localized.ngx_var_remote_addr
		end
	elseif localized.ngx_var_http_x_forwarded_for ~= nil then
		if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
			localized.ip_blacklist_remote_addr = localized.ngx_var_http_x_forwarded_for
		else
			if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
				if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
					blocked_address_check("[Anti-DDoS] (4) Blocked IP for attempting to impersonate proxy via header X-Forwarded-For : ")
				end
			end
			localized.ip_blacklist_remote_addr = localized.ngx_var_remote_addr
		end
	else
		localized.ip_blacklist_remote_addr = localized.ngx_var_remote_addr
	end
end

--[[
headers to restore original visitor IP addresses at your origin web server order last
]]
if localized.ngx_var_http_internal_header_name ~= nil then
localized.ngx_req_set_header(localized.ngx_var_http_internal_header_name, nil) --remove internal header
end
local function header_append_ip()
	if localized.send_ip_to_backend_custom_headers ~= nil and #localized.send_ip_to_backend_custom_headers > 0 then
		for i=1,#localized.send_ip_to_backend_custom_headers do --for each host in our table
			--local v = custom_headers[i]
			local v = localized.send_ip_to_backend_custom_headers[i]
			if faster_than_match(v[1]) or localized.string_find(localized.URL, v[1]) then --if our host matches one in the table
				for first=1,#v[2] do --for each arg in our table
					local value1 = v[2][first][1]
					if localized.ngx_var_http_internal ~= "1" and value1 ~= nil then
						localized.ngx_req_set_header(value1, localized.remote_addr)
					end
					if localized.ngx_var_http_internal_header_name ~= nil and localized.string_lower(value1) == "cf-connecting-ip" or localized.string_lower(value1) == "x-forwarded-for" then
						localized.ngx_req_set_header(localized.ngx_var_http_internal_header_name, localized.ngx_var_http_internal_string) --mark a way so we know this is a internal run
					end
				end
				break --break out of the for each loop pointless to keep searching the rest since we matched our host
			end
		end
	end
end
if localized.ngx_var_http_internal == nil then --1st layer
header_append_ip()
end
if localized.ngx_var_http_internal ~= nil then --2nd layer
	if localized.ngx_var_http_internal_log == 1 then
		localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (2) Internal call back again  : ")
	end
	if localized.ngx_var_http_internal_header_name ~= nil then
		localized.ngx_req_set_header(localized.ngx_var_http_internal_header_name, nil) --remove internal header
	end
end
--[[
End headers to restore original visitor IP addresses at your origin web server
]]

--if host of site is a tor website connecting clients will be tor network clients
if localized.remote_addr == "tor" then
	localized.remote_addr = localized.tor_remote_addr
	if localized.tor_remote_addr == "auto" then
		localized.remote_addr = localized.ngx_var_remote_addr
		localized.tor_remote_addr = localized.ngx_var_remote_addr
	end
end
if check_tor_onion() then
	localized.remote_addr = localized.tor_remote_addr --set ip as what the user wants the tor IP to be
	if localized.tor_remote_addr == "auto" then
		localized.remote_addr = localized.ngx_var_remote_addr
		localized.tor_remote_addr = localized.ngx_var_remote_addr
	end
end
if localized.tor_remote_addr == "auto" then
	localized.tor_remote_addr = localized.ngx_var_remote_addr
end

--[[
Query String Remove arguments
]]
local function query_string_remove_args()
	if localized.query_string_remove_args_table ~= nil and #localized.query_string_remove_args_table > 0 then
		local args = localized.ngx_req_get_uri_args() --grab our query string args and put them into a table
		local modified = nil

		for i=1,#localized.query_string_remove_args_table do --for each host in our table
			local v = localized.query_string_remove_args_table[i]
			if faster_than_match(v[1]) or localized.string_find(localized.URL, v[1]) then --if our host matches one in the table
				for i=1,#v[2] do --for each arg in our table
					local value = v[2][i]
					args[value] = nil --remove the arguement from the args table
					modified = 1 --set args as modified
				end
				break --break out of the for each loop pointless to keep searching the rest since we matched our host
			end
		end
		if modified == 1 then --need to set our args as our new modified one
			localized.ngx_req_set_uri_args(args) --set the args on the server as our new ordered args check localized.ngx_var.args
		else
			return --carry on script functions
		end
	end
end
query_string_remove_args()
--[[
Query String Remove arguments
]]

--[[
Query String Expected arguments Whitelist only
]]
local function query_string_expected_args_only()
	if localized.query_string_expected_args_only_table ~= nil and #localized.query_string_expected_args_only_table > 0 then
		local args = localized.ngx_req_get_uri_args() --grab our query string args and put them into a table
		local modified = nil

		for i=1,#localized.query_string_expected_args_only_table do --for each host in our table
			local v = localized.query_string_expected_args_only_table[i]
			if faster_than_match(v[1]) or localized.string_find(localized.URL, v[1]) then --if our host matches one in the table
				for key, value in localized.next, args do
					if has_value(v[2], localized.tostring(key)) == false then
						args[key] = nil --remove the arguement from the args table
						modified = 1 --set args as modified
					end
				end
				break --break out of the for each loop pointless to keep searching the rest since we matched our host
			end
		end
		if modified == 1 then --need to set our args as our new modified one
			localized.ngx_req_set_uri_args(args) --set the args on the server as our new ordered args check localized.ngx_var.args
		else
			return --carry on script functions
		end
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
	if localized.query_string_sort_table ~= nil and #localized.query_string_sort_table > 0 then
		local allow_site = nil

		for i=1,#localized.query_string_sort_table do --for each host in our table
			local v = localized.query_string_sort_table[i]
			if faster_than_match(v[1]) or localized.string_find(localized.URL, v[1]) then --if our host matches one in the table
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
			local args = localized.ngx_req_get_uri_args() --grab our query string args and put them into a table
			localized.table_sort(args) --sort our query string args table into order
			localized.ngx_req_set_uri_args(args) --set the args on the server as our new ordered args check localized.ngx_var.args
		else --allow_site was 1
			return --carry on script functions
		end
	end
end
query_string_sort()
--[[
End Query String Sort
]]

local function WAF_Checks()
--[[WAF Web Application Firewall POST Request arguments filter]]
local function WAF_Post_Requests()
	--if localized.next(localized.WAF_POST_Request_table) ~= nil then --Check Post filter table has rules inside it
	if localized.WAF_POST_Request_table ~= nil and #localized.WAF_POST_Request_table > 0 then --Check Post filter table has rules inside it

		localized.ngx_req_read_body() --Grab the request Body
		local read_request_body_args = (localized.ngx_req_get_body_data() or "") --Put the request body arguments into a variable
		local args = (localized.ngx_decode_args(read_request_body_args) or "") --Put the Post args in to a table

		if localized.next(args) ~= nil then --Check Post args table has contents
		--if #args > 0 then --Check Post args table has contents	

			local arguement1 = nil --create empty variable
			local arguement2 = nil --create empty variable

			for key, value in localized.next, args do

				for i=1,#localized.WAF_POST_Request_table do
					arguement1 = nil --reset to nil each loop
					arguement2 = nil --reset to nil each loop
					local value = localized.WAF_POST_Request_table[i] --put table value into variable
					local argument_name = value[1] or "" --get the WAF TABLE argument name or empty
					local argument_value = value[2] or "" --get the WAF TABLE arguement value or empty
					local args_name = localized.tostring(key) or "" --variable to store POST data argument name
					local args_value = localized.tostring(value) or "" --variable to store POST data argument value
					if localized.string_find(args_name, argument_name) then --if the argument name in my table matches the one in the POST request
						arguement1 = 1
					end
					if localized.string_find(args_value, argument_value) then --if the argument value in my table matches the one the POST request
						arguement2 = 1
					end
					if arguement1 and arguement2 then --if what would of been our empty vars have been changed to not empty meaning a WAF match then block the request
						localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked Request POST args prohibited : arg_name = " .. argument_name .. " - arg_value = " .. argument_value .. " - IP : " .. localized.remote_addr)
						return localized.ngx_exit(localized.ngx_HTTP_FORBIDDEN) --deny user access
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
	--if localized.next(localized.WAF_Header_Request_table) ~= nil then --Check Header filter table has rules inside it
	if localized.WAF_Header_Request_table ~= nil and #localized.WAF_Header_Request_table > 0 then --Check Header filter table has rules inside it

		local argument_request_headers = localized.ngx_req_get_headers() --get our client request headers and put them into a table

		if localized.next(argument_request_headers) ~= nil then --Check Header args table has contents
		--if #argument_request_headers > 0 then --Check Header args table has contents

			local arguement1 = nil --create empty variable
			local arguement2 = nil --create empty variable

			for key, value in localized.next, argument_request_headers do

				for i=1,#localized.WAF_Header_Request_table do
					arguement1 = nil --reset to nil each loop
					arguement2 = nil --reset to nil each loop
					local value = localized.WAF_Header_Request_table[i] --put table value into variable
					local argument_name = value[1] or "" --get the WAF TABLE argument name or empty
					local argument_value = value[2] or "" --get the WAF TABLE arguement value or empty
					local args_name = localized.tostring(key) or "" --variable to store Header data argument name
					local args_value = localized.tostring(localized.ngx_req_get_headers()[args_name]) or ""
					if localized.string_find(args_name, argument_name) then --if the argument name in my table matches the one in the request
						arguement1 = 1
					end
					if localized.string_find(args_value, argument_value) then --if the argument value in my table matches the one the request
						arguement2 = 1
					end
					if arguement1 and arguement2 then --if what would of been our empty vars have been changed to not empty meaning a WAF match then block the request
						localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked Request Header prohibited : arg_name = " .. argument_name .. " - arg_value = " .. argument_value .. " - IP : " .. localized.remote_addr)
						return localized.ngx_exit(localized.ngx_HTTP_FORBIDDEN) --deny user access
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
	--if localized.next(localized.WAF_query_string_Request_table) ~= nil then --Check query string filter table has rules inside it
	if localized.WAF_query_string_Request_table ~= nil and #localized.WAF_query_string_Request_table > 0 then --Check query string filter table has rules inside it

		local args = localized.ngx_req_get_uri_args() --grab our query string args and put them into a table

		if localized.next(args) ~= nil then --Check query string args table has contents
		--if #args > 0 then --Check query string args table has contents

			local arguement1 = nil --create empty variable
			local arguement2 = nil --create empty variable

			for key, value in localized.next, args do

				for i=1,#localized.WAF_query_string_Request_table do
					arguement1 = nil --reset to nil each loop
					arguement2 = nil --reset to nil each loop
					local value = localized.WAF_query_string_Request_table[i] --put table value into variable
					local argument_name = value[1] or "" --get the WAF TABLE argument name or empty
					local argument_value = value[2] or "" --get the WAF TABLE arguement value or empty
					local args_name = localized.tostring(key) or "" --variable to store query string data argument name
					local args_value = localized.tostring(localized.ngx_req_get_uri_args()[args_name]) or "" --variable to store query string data argument value
					if localized.string_find(args_name, argument_name) then --if the argument name in my table matches the one in the request
						arguement1 = 1
					end
					if localized.string_find(args_value, argument_value) then --if the argument value in my table matches the one the request
						arguement2 = 1
					end
					if arguement1 and arguement2 then --if what would of been our empty vars have been changed to not empty meaning a WAF match then block the request
						localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked Request Query String prohibited : arg_name = " .. argument_name .. " - arg_value = " .. argument_value .. " - IP : " .. localized.remote_addr)
						return localized.ngx_exit(localized.ngx_HTTP_FORBIDDEN) --deny user access
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
	--if localized.next(localized.WAF_URI_Request_table) ~= nil then --Check Post filter table has rules inside it
	if localized.WAF_URI_Request_table ~= nil and #localized.WAF_URI_Request_table > 0 then --Check Post filter table has rules inside it

		--[[
		Because localized.ngx_var.uri is a bit stupid I strip the query string of the request uri.
		The reason for this it is subject to normalisation
		Consecutive / characters are replace by a single / 
		and URL encoded characters are decoded 
		but then your back end webserver / application recieve the encoded uri!?
		So to keep the security strong I match the same version your web application would need protecting from (Yes the encoded copy that could contain malicious / exploitable contents)
		]]
		local args = localized.string_gsub(localized.request_uri, "?.*", "") --remove the query string from the uri

		for i=1,#localized.WAF_URI_Request_table do --for each host in our table
			local v = localized.WAF_URI_Request_table[i]
			if faster_than_match(v[1]) or localized.string_find(localized.URL, v[1]) then --if our host matches one in the table
				if localized.string_find(args, v[2]) then
					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked Request URI prohibited : " .. localized.URL .. " - IP : " .. localized.remote_addr)
					return localized.ngx_exit(localized.ngx_HTTP_FORBIDDEN) --deny user access
				end
			end
		end
	end
end
WAF_URI_Request()
--[[End WAF Web Application Firewall URI Request arguments filter]]
end
WAF_Checks()

local function check_ips()
	--function to check if ip address is whitelisted to bypass our auth
	local function check_ip_whitelist(ip_table)
		if ip_table ~= nil and #ip_table > 0 then
			for i=1,#ip_table do
				local value = ip_table[i]
				if value == localized.ip_whitelist_remote_addr then --if our ip address matches with one in the whitelist
					return master_exit() --Go to content
				elseif ip_address_in_range(value, localized.ip_whitelist_remote_addr) == true then
					return master_exit() --Go to content
				end
			end
			if localized.ip_whitelist_block_mode == 1 then --ip address not matched the above
				blocked_address_check("[Anti-DDoS] Blocked IP attempt for not being in whitelist : ")
				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked IP not in whitelist IP : " .. localized.ip_whitelist_remote_addr)
				return localized.ngx_exit(localized.ngx_HTTP_CLOSE) --deny user access
			end
		end

		return --no ip was in the whitelist
	end
	check_ip_whitelist(localized.ip_whitelist) --run whitelist check function

	if master_exit_var == 1 then
		return --exit from check_ips() function
	end

	local function check_ip_blacklist(ip_table)
		if ip_table ~= nil and #ip_table > 0 then
			for i=1,#ip_table do
				local value = ip_table[i]
				if value == localized.ip_blacklist_remote_addr then
					blocked_address_check("[Anti-DDoS] Blocked IP attempt for being in blacklist : ")
					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked IP in blacklist - " .. value .. " -" .. " IP : " .. localized.ip_blacklist_remote_addr)
					return localized.ngx_exit(localized.ngx_HTTP_CLOSE) --deny user access
				elseif ip_address_in_range(value, localized.ip_blacklist_remote_addr) == true then
					blocked_address_check("[Anti-DDoS] Blocked IP attempt for being in blacklist : ")
					localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked IP in blacklist - " .. value .. " -" .. " IP : " .. localized.ip_blacklist_remote_addr)
					return localized.ngx_exit(localized.ngx_HTTP_CLOSE) --deny user access
				end
			end
		end

		return --no ip was in blacklist
	end
	check_ip_blacklist(localized.ip_blacklist) --run blacklist check function
end
check_ips()

if master_exit_var == 1 then
return --exit from run_checks() function
end

local function check_user_agents()
	local function check_user_agent_blacklist(user_agent_table)
		if user_agent_table ~= nil and #user_agent_table > 0 then
			local req_headers = localized.ngx_req_get_headers()
			local user_agent_blacklist_var = req_headers["user-agent"] or ""
			if user_agent_blacklist_var then
				if localized.type(user_agent_blacklist_var) ~= "table" then
					for i=1,#user_agent_table do
						local value = user_agent_table[i]
						if value[2] == 1 then --case insensative
							user_agent_blacklist_var = localized.string_lower(user_agent_blacklist_var)
							value[1] = localized.string_lower(value[1])
						end
						if value[2] == 2 then --case sensative
						end
						if value[2] == 3 then --regex case sensative
						end
						if value[2] == 4 then --regex lower case insensative
							user_agent_blacklist_var = localized.string_lower(user_agent_blacklist_var)
						end
						if faster_than_match(value[1]) or localized.string_find(user_agent_blacklist_var, value[1])then
							localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] User-Agent Blocked - " .. user_agent_blacklist_var .. " -" .. " IP : " .. localized.remote_addr)
							return localized.ngx_exit(localized.ngx_HTTP_FORBIDDEN) --deny user access
						end
					end
				else
					for x=1, #user_agent_blacklist_var do
						for i=1,#user_agent_table do
							local value = user_agent_table[i]
							if value[2] == 1 then --case insensative
								user_agent_blacklist_var[x] = localized.string_lower(user_agent_blacklist_var[x])
								value[1] = localized.string_lower(value[1])
							end
							if value[2] == 2 then --case sensative
							end
							if value[2] == 3 then --regex case sensative
							end
							if value[2] == 4 then --regex lower case insensative
								user_agent_blacklist_var[x] = localized.string_lower(user_agent_blacklist_var[x])
							end
							if faster_than_match(value[1]) or localized.string_find(user_agent_blacklist_var[x], value[1])then
								localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] User-Agent Blocked - " .. user_agent_blacklist_var[x] .. " -" .. " IP : " .. localized.remote_addr)
								return localized.ngx_exit(localized.ngx_HTTP_FORBIDDEN) --deny user access
							end
						end
					end
				end
			end
		end

		return --no user agent was in blacklist
	end
	check_user_agent_blacklist(localized.user_agent_blacklist_table) --run user agent blacklist check function

	local function check_user_agent_whitelist(user_agent_table)
		if user_agent_table ~= nil and #user_agent_table > 0 then
			local req_headers = localized.ngx_req_get_headers()
			local user_agent_whitelist_var = req_headers["user-agent"] or ""
			if user_agent_whitelist_var then
				if localized.type(user_agent_whitelist_var) ~= "table" then
					for i=1,#user_agent_table do
						local value = user_agent_table[i]
						if value[2] == 1 then --case insensative
							user_agent_whitelist_var = localized.string_lower(user_agent_whitelist_var)
							value[1] = localized.string_lower(value[1])
						end
						if value[2] == 2 then --case sensative
						end
						if value[2] == 3 then --regex case sensative
						end
						if value[2] == 4 then --regex lower case insensative
							user_agent_whitelist_var = localized.string_lower(user_agent_whitelist_var)
						end
						if faster_than_match(value[1]) or localized.string_find(user_agent_whitelist_var, value[1])then
							return master_exit() --Go to content
						end
					end
				else
					for x=1, #user_agent_whitelist_var do
						for i=1,#user_agent_table do
							local value = user_agent_table[i]
							if value[2] == 1 then --case insensative
								user_agent_whitelist_var[x] = localized.string_lower(user_agent_whitelist_var[x])
								value[1] = localized.string_lower(value[1])
							end
							if value[2] == 2 then --case sensative
							end
							if value[2] == 3 then --regex case sensative
							end
							if value[2] == 4 then --regex lower case insensative
								user_agent_whitelist_var[x] = localized.string_lower(user_agent_whitelist_var[x])
							end
							if faster_than_match(value[1]) or localized.string_find(user_agent_whitelist_var[x], value[1])then
								return master_exit() --Go to content
							end
						end
					end
				end
			end
		end

		return --no user agent was in whitelist
	end
	check_user_agent_whitelist(localized.user_agent_whitelist_table) --run user agent whitelist check function
	if master_exit_var == 1 then
		return --exit from check_user_agents() function
	end
end
check_user_agents()
if master_exit_var == 1 then
return --exit from run_checks() function
end

-- Seed the randomness with our custom seed
localized.math_randomseed(getRandomSeed())

--[[
String XOR helper function
]]
local function xorChar(c, key)
    return localized.string_char(localized.bit_bxor(localized.string_byte(c), key))
end
--[[
End String XOR helper function
]]
--[[
Char Shift helper function
]]
local function shiftChar(c, amount)
    return localized.string_char((localized.string_byte(c) + amount) % 256)
end
--[[
End Char Shift helper function
]]
--[[
Calculate answer Function
]]--
local function calculateAnswer(client_signature) 
    local seed = localized.math_floor(localized.math_sin(localized.tonumber(localized.os_date("%Y%m%d", localized.os_time_saved))) * 1000)
    local key = seed % 256
    local shiftAmount = localized.math_floor((seed * localized.math_sin(seed)) % 10) + 1

    local result = ""
    for i = 1, #client_signature do
        result = result .. shiftChar(xorChar(localized.string_sub(client_signature, i, i), (key + i - 1) % 256), shiftAmount)
    end
    return localized.ngx_encode_base64(result)
end
--[[
End Calculate answer Function
]]--

--function to encrypt strings with our secret key / password provided
local function calculate_signature(str)
	local output = localized.ngx_encode_base64(localized.ngx_hmac_sha1(localized.secret, str))
	output = localized.string_gsub(output, "[+/=]", "") --Remove +/=
	return output
end
--calculate_signature(str)

--generate random strings on the fly
--qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890
local charset = {}
for i = 48,  57 do
charset[#charset+1] = localized.string_char(i)
end --0-9 numeric
--[[
for i = 65,  90 do
charset[#charset+1] = localized.string_char(i)
end --A-Z uppercase
]]
--[[
for i = 97, 122 do
charset[#charset+1] = localized.string_char(i)
end --a-z lowercase
]]
charset[#charset+1] = localized.string_char(95) --insert number 95 underscore
local stringrandom_table = {} --create table to store our generated vars to avoid duplicates
local function stringrandom(length)
	if length > 0 then
		local output = stringrandom(length - 1) .. charset[localized.math_random(1, #charset)]
		local duplicate_found = 0 --mark if we find a duplicate or not
		for i=1,#stringrandom_table do --for each value in our generated var table
			if stringrandom_table[i] == output then --if a value in our table matches our generated var
				duplicate_found = 1 --mark as duplicate var
				output = "_" .. output --append an underscore to the duplicate var
				stringrandom_table[#stringrandom_table+1] = output --insert to the table
				break --break out of for each loop since we found a duplicate
			end
		end
		if duplicate_found == 0 then --if no duplicate found
			stringrandom_table[#stringrandom_table+1] = output --insert the output to our table
		end
		return output
	else
		return ""
	end
end
--stringrandom(10)

local stringrandom_length = "" --create our random length variable
if localized.dynamic_javascript_vars_length == 1 then --if our javascript random var length is to be static
	stringrandom_length = localized.dynamic_javascript_vars_length_static --set our length as our static value
else --it is to be dynamic
	stringrandom_length = localized.math_random(localized.dynamic_javascript_vars_length_start, localized.dynamic_javascript_vars_length_end) --set our length to be our dynamic min and max value
end

--shuffle table function
local function shuffle(tbl)
	for i = #tbl, 2, -1 do
		local j = localized.math_random(i)
		tbl[i], tbl[j] = tbl[j], tbl[i]
	end
	return tbl
end

--for my javascript Hex output
local function sep(str, patt, re)
	local rstr = localized.string_gsub(str, patt, "%1%" .. re)
	return localized.string_sub(rstr, 1, #rstr - #re)
end

local function stringtohex(str)
	return localized.string_gsub(str, '.', function (c)
		return localized.string_format('%02X', localized.string_byte(c))
	end)
end

--encrypt_javascript function
local function encrypt_javascript(string1, type, defer_async, num_encrypt, encrypt_type, methods) --Function to generate encrypted/obfuscated output
	local output = "" --Empty var

	if type == 0 then
		type = localized.math_random(3, 5) --Random encryption
	end

	if type == 1 or type == nil then --No encryption
		if defer_async == "0" or defer_async == nil then --Browser default loading / execution order
			output = "<script type=\"text/javascript\" charset=\"" .. localized.default_charset .. "\" data-cfasync=\"false\">" .. string1 .. "</script>"
		end
		if defer_async == "1" then --Defer
			output = "<script type=\"text/javascript\" defer=\"defer\" charset=\"" .. localized.default_charset .. "\" data-cfasync=\"false\">" .. string1 .. "</script>"
		end
		if defer_async == "2" then --Async
			output = "<script type=\"text/javascript\" async=\"async\" charset=\"" .. localized.default_charset .. "\" data-cfasync=\"false\">" .. string1 .. "</script>"
		end
	end

	--https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs
	--pass other encrypted outputs through this too ?
	if type == 2 then --Base64 Data URI
		local base64_data_uri = string1

		if localized.tonumber(num_encrypt) ~= nil then --If number of times extra to rencrypt is set
			for i=1, localized.tonumber(num_encrypt) do --for each number
				string1 = localized.ngx_encode_base64(base64_data_uri)
			end
		end

		if defer_async == "0" or defer_async == nil then --Browser default loading / execution order
			output = "<script type=\"text/javascript\" src=\"data:text/javascript;base64," .. localized.ngx_encode_base64(string1) .. "\" charset=\"" .. localized.default_charset .. "\" data-cfasync=\"false\"></script>"
		end
		if defer_async == "1" then --Defer
			output = "<script type=\"text/javascript\" src=\"data:text/javascript;base64," .. localized.ngx_encode_base64(string1) .. "\" defer=\"defer\" charset=\"" .. localized.default_charset .. "\" data-cfasync=\"false\"></script>"
		end
		if defer_async == "2" then --Async
			output = "<script type=\"text/javascript\" src=\"data:text/javascript;base64," .. localized.ngx_encode_base64(string1) .. "\" async=\"async\" charset=\"" .. localized.default_charset .. "\" data-cfasync=\"false\"></script>"
		end
	end

	if type == 3 then --Hex
		local hex_output = stringtohex(string1) --ndk.set_var.set_encode_hex(string1) --Encode string in hex
		local hexadecimal_x = "" --Create var
		local encrypt_type_origin = encrypt_type --Store var passed to function in local var

		if localized.tonumber(encrypt_type) == nil or localized.tonumber(encrypt_type) <= 0 then
			encrypt_type = localized.math_random(2, 2) --Random encryption
		end
		--I was inspired by http://www.hightools.net/javascript-encrypter.php so i built it myself
		if localized.tonumber(encrypt_type) == 1 then
			hexadecimal_x = "%" .. sep(hex_output, "%x%x", "%") --hex output insert a char every 2 chars %x%x
		end
		if localized.tonumber(encrypt_type) == 2 then
			hexadecimal_x = localized.string_char(92) .. "x" .. sep(hex_output, "%x%x", localized.string_char(92) .. "x") --hex output insert a char every 2 chars %x%x
		end

		--TODO: Fix this.
		--num_encrypt = "3" --test var
		if localized.tonumber(num_encrypt) ~= nil then --If number of times extra to rencrypt is set
			for i=1, localized.tonumber(num_encrypt) do --for each number
				if localized.tonumber(encrypt_type) ~= nil then
					encrypt_type = localized.math_random(1, 2) --Random encryption
					if localized.tonumber(encrypt_type) == 1 then
						--hexadecimal_x = "%" .. sep(ndk.set_var.set_encode_hex("eval(decodeURIComponent('" .. hexadecimal_x .. "'))"), "%x%x", "%") --hex output insert a char every 2 chars %x%x
					end
					if localized.tonumber(encrypt_type) == 2 then
						--hexadecimal_x = "\\x" .. sep(ndk.set_var.set_encode_hex("eval(decodeURIComponent('" .. hexadecimal_x .. "'))"), "%x%x", "\\x") --hex output insert a char every 2 chars %x%x
					end
				end
			end
		end

		if defer_async == "0" or defer_async == nil then --Browser default loading / execution order
			--https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/decodeURIComponent
			output = "<script type=\"text/javascript\" charset=\"" .. localized.default_charset .. "\" data-cfasync=\"false\">eval(decodeURIComponent(escape('" .. hexadecimal_x .. "')));</script>"
		end
		if defer_async == "1" then --Defer
			output = "<script type=\"text/javascript\" defer=\"defer\" charset=\"" .. localized.default_charset .. "\" data-cfasync=\"false\">eval(decodeURIComponent(escape('" .. hexadecimal_x .. "')));</script>"
		end
		if defer_async == "2" then --Defer
			output = "<script type=\"text/javascript\" async=\"async\" charset=\"" .. localized.default_charset .. "\" data-cfasync=\"false\">eval(decodeURIComponent(escape('" .. hexadecimal_x .. "')));</script>"
		end
	end

	if type == 4 then --Base64 javascript decode
		local base64_javascript = "eval(decodeURIComponent(escape(window.atob('" .. localized.ngx_encode_base64(string1) .. "'))))"

		if localized.tonumber(num_encrypt) ~= nil then --If number of times extra to rencrypt is set
			for i=1, localized.tonumber(num_encrypt) do --for each number
				base64_javascript = "eval(decodeURIComponent(escape(window.atob('" .. localized.ngx_encode_base64(base64_javascript) .. "'))))"
			end
		end

		if defer_async == "0" or defer_async == nil then --Browser default loading / execution order
			output = "<script type=\"text/javascript\" charset=\"" .. localized.default_charset .. "\" data-cfasync=\"false\">" .. base64_javascript .. "</script>"
		end
		if defer_async == "1" then --Defer
			output = "<script type=\"text/javascript\" defer=\"defer\" charset=\"" .. localized.default_charset .. "\" data-cfasync=\"false\">" .. base64_javascript .. "</script>"
		end
		if defer_async == "2" then --Defer
			output = "<script type=\"text/javascript\" async=\"async\" charset=\"" .. localized.default_charset .. "\" data-cfasync=\"false\">" .. base64_javascript .. "</script>"
		end
	end

	if type == 5 then --Conor Mcknight's Javascript Scrambler (Obfuscate Javascript by putting it into vars and shuffling them like a deck of cards)
		local base64_javascript = localized.ngx_encode_base64(string1) --base64 encode our script

		local counter = 0 --keep track of how many times we pass through
		local r = localized.math_random(1, #base64_javascript) --randomize where to split string
		local chunks = {} --create our chunks table for string storage
		local chunks_order = {} --create our chunks table for string storage that stores the value only
		local random_var = nil --create our random string variable to use

		for i=1, #base64_javascript do
			if counter <= #base64_javascript then
				random_var = stringrandom(stringrandom_length) --create a random variable name to use
				chunks_order[#chunks_order+1] = "_" .. random_var .. "" --insert the value into our ordered table
				chunks[#chunks+1] = 'var _' .. random_var .. '="' .. localized.string_sub(base64_javascript,counter,counter+r).. '";' --insert our value into our table we will scramble
				counter = counter+r+1
			else
				break
			end
		end

		shuffle(chunks) --scramble our table

		output = localized.table_concat(chunks, "") --put our scrambled table into string
		output = output .. "eval(decodeURIComponent(escape(window.atob(" .. localized.table_concat(chunks_order, " + " ) .. "))));" --put our scrambled table and ordered table into a string
		
		if defer_async == "0" or defer_async == nil then --Browser default loading / execution order
			output = "<script type=\"text/javascript\" charset=\"" .. localized.default_charset .. "\" data-cfasync=\"false\">" .. output .. "</script>"
		end
		if defer_async == "1" then --Defer
			output = "<script type=\"text/javascript\" defer=\"defer\" charset=\"" .. localized.default_charset .. "\" data-cfasync=\"false\">" .. output .. "</script>"
		end
		if defer_async == "2" then --Defer
			output = "<script type=\"text/javascript\" async=\"async\" charset=\"" .. localized.default_charset .. "\" data-cfasync=\"false\">" .. output .. "</script>"
		end
	end

	return output
end
--end encrypt_javascript function

localized.currentdate = "" --make current date a empty var

--Make sure our current date is in align with expires_time variable so that the auth page only shows when the cookie expires
if localized.expire_time <= 60 then --less than equal to one minute
	localized.currentdate = localized.os_date("%M",localized.os_time_saved) --Current minute
end
if localized.expire_time > 60 then --greater than one minute
	localized.currentdate = localized.os_date("%H",localized.os_time_saved) --Current hour
end
if localized.expire_time > 3600 then --greater than one hour
	localized.currentdate = localized.os_date("%d",localized.os_time_saved) --Current day of the year
end
if localized.expire_time > 86400 then --greater than one day
	localized.currentdate = localized.os_date("%W",localized.os_time_saved) --Current week
end
if localized.expire_time > 6048000 then --greater than one week
	localized.currentdate = localized.os_date("%m",localized.os_time_saved) --Current month
end
if localized.expire_time > 2628000 then --greater than one month
	localized.currentdate = localized.os_date("%Y",localized.os_time_saved) --Current year
end
if localized.expire_time > 31536000 then --greater than one year
	localized.currentdate = localized.os_date("%z",localized.os_time_saved) --Current time zone
end

--Auth puzzle status code responses
local expected_header_status = localized.ngx_HTTP_NO_CONTENT --(204)
local authentication_page_status_output = localized.ngx_HTTP_OK --(200)
if localized.ngx_var_http_cf_connecting_ip ~= nil then
	authentication_page_status_output = localized.ngx_HTTP_OK --(200) cloudflare may not like a 503 status code response so send them a 200 instead
elseif localized.ngx_var_http_x_forwarded_for ~= nil then
	authentication_page_status_output = localized.ngx_HTTP_OK --(200) proxy servers may not like a 503 status code response so send them a 200 instead
end

--Put our vars into storage for use later on
local challenge_original = localized.challenge
local cookie_name_start_date_original = localized.cookie_name_start_date
local cookie_name_end_date_original = localized.cookie_name_end_date
local cookie_name_encrypted_start_and_end_date_original = localized.cookie_name_encrypted_start_and_end_date

--[[
Start Tor detection
]]
if localized.x_tor_header == 2 then --if x-tor-header is dynamic
	localized.x_tor_header_name = calculate_signature(localized.tor_remote_addr .. localized.x_tor_header_name .. localized.currentdate) --make the header unique to the client and for todays date encrypted so every 24 hours this will change and can't be guessed by bots gsub because header bug with underscores so underscore needs to be removed
	localized.x_tor_header_name = localized.string_gsub(localized.x_tor_header_name, "_", "") --replace underscore with nothing
	localized.x_tor_header_name_allowed = calculate_signature(localized.tor_remote_addr .. localized.x_tor_header_name_allowed .. localized.currentdate) --make the header unique to the client and for todays date encrypted so every 24 hours this will change and can't be guessed by bots gsub because header bug with underscores so underscore needs to be removed
	localized.x_tor_header_name_allowed = localized.string_gsub(localized.x_tor_header_name_allowed, "_", "") --replace underscore with nothing
	localized.x_tor_header_name_blocked = calculate_signature(localized.tor_remote_addr .. localized.x_tor_header_name_blocked .. localized.currentdate) --make the header unique to the client and for todays date encrypted so every 24 hours this will change and can't be guessed by bots gsub because header bug with underscores so underscore needs to be removed
	localized.x_tor_header_name_blocked = localized.string_gsub(localized.x_tor_header_name_blocked, "_", "") --replace underscore with nothing
end

if localized.encrypt_anti_ddos_cookies == 2 then --if Anti-DDoS Cookies are to be encrypted
	localized.cookie_tor = calculate_signature(localized.tor_remote_addr .. localized.cookie_tor .. localized.currentdate) --encrypt our tor cookie name
	localized.cookie_tor_value_allow = calculate_signature(localized.tor_remote_addr .. localized.cookie_tor_value_allow .. localized.currentdate) --encrypt our tor cookie value for allow
	localized.cookie_tor_value_block = calculate_signature(localized.tor_remote_addr .. localized.cookie_tor_value_block .. localized.currentdate) --encrypt our tor cookie value for block
end

--block tor function to block traffic from tor users
local function blocktor()
	return localized.ngx_exit(localized.ngx_HTTP_FORBIDDEN) --deny user access
end

--check the connecting client to see if they have our required matching tor cookie name in their request
local tor_cookie_name = "cookie_" .. localized.cookie_tor
local tor_cookie_value = localized.ngx_var[tor_cookie_name] or ""

if tor_cookie_value == localized.cookie_tor_value_allow then --if their cookie value matches the value we expect
	if localized.tor == 2 then --perform check if tor users should be allowed or blocked if tor users already browsing your site have been granted access and you change this setting you want them to be blocked now so this makes sure they are denied any further access before their cookie expires
		blocktor()
	end
	localized.remote_addr = localized.tor_remote_addr --set the localized.remote_addr as the localized.tor_remote_addr value
end

if tor_cookie_value == localized.cookie_tor_value_block then --if the provided cookie value matches our block cookie value
	blocktor()
end

local cookie_tor_value = "" --create variable to store if tor should be allowed or disallowed
local x_tor_header_name_value = "" --create variable to store our expected header value

if localized.tor == 1 then --if tor users should be allowed
	cookie_tor_value = localized.cookie_tor_value_allow --set our value as our expected allow value
	x_tor_header_name_value = localized.x_tor_header_name_allowed --set our value as our expected allow value
else --tor users should be blocked
	cookie_tor_value = localized.cookie_tor_value_block --set our value as our expected block value
	x_tor_header_name_value = localized.x_tor_header_name_blocked --set our value as our expected block value
end
--[[
End Tor detection
]]

--[[
Authorization / Restricted Access Area Box
]]
if localized.encrypt_anti_ddos_cookies == 2 then --if Anti-DDoS Cookies are to be encrypted
	localized.authorization_cookie = calculate_signature(localized.remote_addr .. localized.authorization_cookie .. localized.currentdate) --encrypt our auth box session cookie name
end

localized.set_cookies = nil
localized.set_cookie1 = nil
localized.set_cookie2 = nil
localized.set_cookie3 = nil
localized.set_cookie4 = nil
localized.set_cookie5 = nil

local function check_authorization(authorization, authorization_dynamic)
	if localized.authorization == 0 or nil then --auth box disabled
		return
	end

	if localized.authorization ~= 0 and check_tor_onion() then
		localized.authorization = 2
		localized.remote_addr = localized.tor_remote_addr --set for compatibility with Tor Clients
	end

	local expected_cookie_value = nil
	if localized.authorization == 2 then --Cookie sessions
		local cookie_name = "cookie_" .. localized.authorization_cookie
		local cookie_value = localized.ngx_var[cookie_name] or ""
		expected_cookie_value = calculate_signature(localized.remote_addr .. "authenticate" .. localized.currentdate) --encrypt our expected cookie value
		if cookie_value == expected_cookie_value then --cookie value client gave us matches what we expect it to be
			master_exit() --Go to content
		end
	end

	local allow_site = nil
	local authorization_display_user_details = nil
	if localized.authorization_paths ~= nil and #localized.authorization_paths > 0 then
		for i=1,#localized.authorization_paths do --for each host in our table
			local v = localized.authorization_paths[i]
			if faster_than_match(v[2]) or localized.string_find(localized.URL, v[2]) then --if our host matches one in the table
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
	end
	if allow_site == 1 then --checks passed site allowed grant direct access
		--showbox
	else --allow_site was 2
		return --carry on script functions to display auth page
	end

	local allow_access = nil
	local authorization_username = nil
	local authorization_password = nil

	local req_headers = localized.ngx_req_get_headers() --get all request headers

	if authorization_dynamic == 0 then --static
		if localized.authorization_logins ~= nil and #localized.authorization_logins > 0 then
			for i=1,#localized.authorization_logins do --for each login
				local value = localized.authorization_logins[i]
				authorization_username = value[1] --username
				authorization_password = value[2] --password
				local base64_expected = authorization_username .. ":" .. authorization_password --convert to browser format
				base64_expected = localized.ngx_encode_base64(base64_expected) --base64 encode like browser format
				local authroization_user_pass = "Basic " .. base64_expected --append Basic to start like browser header does
				if req_headers["Authorization"] == authroization_user_pass then --if the details match what we expect
					if localized.authorization == 2 then --Cookie sessions
						localized.set_cookie1 = localized.authorization_cookie.."="..expected_cookie_value.."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";"
						localized.set_cookies = {localized.set_cookie1}
						localized.ngx_header["Set-Cookie"] = localized.set_cookies --send client a cookie for their session to be valid
					end
					allow_access = 1 --grant access
					break --break out foreach loop since our user and pass was correct
				end
			end
		end
	end
	if authorization_dynamic == 1 then --dynamic
		authorization_username = calculate_signature(localized.remote_addr .. "username" .. localized.currentdate) --encrypt username
		authorization_password = calculate_signature(localized.remote_addr .. "password" .. localized.currentdate) --encrypt password
		authorization_username = localized.string_sub(authorization_username, 1, localized.authorization_dynamic_length) --change username to set length
		authorization_password = localized.string_sub(authorization_password, 1, localized.authorization_dynamic_length) --change password to set length

		local base64_expected = authorization_username .. ":" .. authorization_password --convert to browser format
		base64_expected = localized.ngx_encode_base64(base64_expected) --base64 encode like browser format
		local authroization_user_pass = "Basic " .. base64_expected --append Basic to start like browser header does
		if req_headers["Authorization"] == authroization_user_pass then --if the details match what we expect
			if localized.authorization == 2 then --Cookie sessions
				localized.set_cookie1 = localized.authorization_cookie.."="..expected_cookie_value.."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";"
				localized.set_cookies = {localized.set_cookie1}
				localized.ngx_header["Set-Cookie"] = localized.set_cookies --send client a cookie for their session to be valid
			end
			allow_access = 1 --grant access
		end
	end

	if allow_access == 1 then
		master_exit() --Go to content
	else
		localized.ngx_status = localized.ngx_HTTP_UNAUTHORIZED --send client unathorized header
		if authorization_display_user_details == 0 then
			localized.ngx_header['WWW-Authenticate'] = 'Basic realm="' .. localized.authorization_message .. '", charset="' .. localized.default_charset .. '"' --send client a box to input required username and password fields
		else
			localized.ngx_header['WWW-Authenticate'] = 'Basic realm="' .. localized.authorization_message .. ' ' .. localized.authorization_username_message .. ' ' .. authorization_username .. ' ' .. localized.authorization_password_message .. ' ' .. authorization_password .. '", charset="' .. localized.default_charset .. '"' --send client a box to input required username and password fields
		end
		localized.ngx_exit(localized.ngx_HTTP_UNAUTHORIZED) --deny access any further
	end
end
check_authorization(authorization, localized.authorization_dynamic)
--[[
Authorization / Restricted Access Area Box
]]
if master_exit_var == 1 then
return --exit from run_checks() function
end

--[[
master switch
]]
--master switch check
local function check_master_switch()
	if localized.master_switch == 2 then --script disabled
		return master_exit() --Go to content
	end
	if localized.master_switch == 3 then --custom host selection
		local allow_site = nil
		if localized.master_switch_custom_hosts ~= nil and #localized.master_switch_custom_hosts > 0 then
			for i=1,#localized.master_switch_custom_hosts do --for each host in our table
				local v = localized.master_switch_custom_hosts[i]
				if faster_than_match(v[2]) or localized.string_find(localized.URL, v[2]) then --if our host matches one in the table
					if v[1] == 1 then --run auth
						allow_site = 2 --run auth checks
					end
					if v[1] == 2 then --bypass
						allow_site = 1 --bypass auth achecks
					end
					break --break out of the for each loop pointless to keep searching the rest since we matched our host
				end
			end
		end
		if allow_site == 1 then --checks passed site allowed grant direct access
			return master_exit() --Go to content
		else --allow_site was 2 to disallow direct access we matched a host to protect
			return --carry on script functions to display auth page
		end
	end
end
check_master_switch()
--[[
master switch
]]
if master_exit_var == 1 then
return --exit from run_checks() function
end

local answer = calculate_signature(localized.remote_addr) --create our encrypted unique identification for the user visiting the website.
local JsPuzzleAnswer = calculateAnswer(answer) -- Localize the answer to be used further

if localized.x_auth_header == 2 then --if x-auth-header is dynamic
	localized.x_auth_header_name = calculate_signature(localized.remote_addr .. localized.x_auth_header_name .. localized.currentdate) --make the header unique to the client and for todays date encrypted so every 24 hours this will change and can't be guessed by bots gsub because header bug with underscores so underscore needs to be removed
	localized.x_auth_header_name = localized.string_gsub(localized.x_auth_header_name, "_", "") --replace underscore with nothing
end

if localized.encrypt_anti_ddos_cookies == 2 then --if Anti-DDoS Cookies are to be encrypted
	--make the cookies unique to the client and for todays date encrypted so every 24 hours this will change and can't be guessed by bots
	localized.challenge = calculate_signature(localized.remote_addr .. localized.challenge .. localized.currentdate)
	localized.cookie_name_start_date = calculate_signature(localized.remote_addr .. localized.cookie_name_start_date .. localized.currentdate)
	localized.cookie_name_end_date = calculate_signature(localized.remote_addr .. localized.cookie_name_end_date .. localized.currentdate)
	localized.cookie_name_encrypted_start_and_end_date = calculate_signature(localized.remote_addr .. localized.cookie_name_encrypted_start_and_end_date .. localized.currentdate)
end

--[[
Grant access function to either grant or deny user access to our website
]]
local function grant_access()
	--our uid cookie
	local cookie_name = "cookie_" .. localized.challenge
	local cookie_value = localized.ngx_var[cookie_name] or ""
	--our start date cookie
	local cookie_name_start_date_name = "cookie_" .. localized.cookie_name_start_date
	local cookie_name_start_date_value = localized.ngx_var[cookie_name_start_date_name] or "0" --Added a 0, since a missing 'cookie_name_start_date_name' value in ngx_var resulted in 502
	local cookie_name_start_date_value_unix = localized.tonumber(cookie_name_start_date_value) or 0
	--our end date cookie
	local cookie_name_end_date_name = "cookie_" .. localized.cookie_name_end_date
	local cookie_name_end_date_value = localized.ngx_var[cookie_name_end_date_name] or "0" --Just to make sure it doesnt fail somewhere
	--our start date and end date combined to a unique id
	local cookie_name_encrypted_start_and_end_date_name = "cookie_" .. localized.cookie_name_encrypted_start_and_end_date
	local cookie_name_encrypted_start_and_end_date_value = localized.ngx_var[cookie_name_encrypted_start_and_end_date_name] or ""

	if cookie_value ~= answer then --if cookie value not equal to or matching our expected cookie they should be giving us
		return --return to refresh the page so it tries again
	end

	--if x-auth-answer is correct to the user unique id time stamps etc meaning browser figured it out then set a new cookie that grants access without needed these checks
	local req_headers = localized.ngx_req_get_headers() --get all request headers
	if req_headers["x-requested-with"] == "XMLHttpRequest" then --if request header matches request type of XMLHttpRequest
		if req_headers[localized.x_tor_header_name] == x_tor_header_name_value and req_headers[localized.x_auth_header_name] == JsPuzzleAnswer then --if the header and value are what we expect then the client is legitimate
			localized.remote_addr = localized.tor_remote_addr --set as our defined static tor variable to use
			
			localized.challenge = calculate_signature(localized.remote_addr .. challenge_original .. localized.currentdate) --create our encrypted unique identification for the user visiting the website again. (Stops a double page refresh loop)
			answer = calculate_signature(localized.remote_addr) --create our answer again under the new localized.remote_addr (Stops a double page refresh loop)
			localized.cookie_name_start_date = calculate_signature(localized.remote_addr .. cookie_name_start_date_original .. localized.currentdate) --create our localized.cookie_name_start_date again under the new localized.remote_addr (Stops a double page refresh loop)
			localized.cookie_name_end_date = calculate_signature(localized.remote_addr .. cookie_name_end_date_original .. localized.currentdate) --create our localized.cookie_name_end_date again under the new localized.remote_addr (Stops a double page refresh loop)
			localized.cookie_name_encrypted_start_and_end_date = calculate_signature(localized.remote_addr .. cookie_name_encrypted_start_and_end_date_original .. localized.currentdate) --create our localized.cookie_name_encrypted_start_and_end_date again under the new localized.remote_addr (Stops a double page refresh loop)

			localized.set_cookie1 = localized.challenge.."="..answer.."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --apply our uid cookie incase javascript setting this cookies time stamp correctly has issues
			localized.set_cookie2 = localized.cookie_name_start_date.."="..localized.currenttime.."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --start date cookie
			localized.set_cookie3 = localized.cookie_name_end_date.."="..(localized.currenttime+localized.expire_time).."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --end date cookie
			localized.set_cookie4 = localized.cookie_name_encrypted_start_and_end_date.."="..calculate_signature(localized.remote_addr .. localized.currenttime .. (localized.currenttime+localized.expire_time) ).."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --start and end date combined to unique id
			localized.set_cookie5 = localized.cookie_tor.."="..cookie_tor_value.."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --create our tor cookie to identify the client as a tor user

			localized.set_cookies = {localized.set_cookie1 , localized.set_cookie2 , localized.set_cookie3 , localized.set_cookie4, localized.set_cookie5}
			localized.ngx_header["Set-Cookie"] = localized.set_cookies
			localized.ngx_header["X-Content-Type-Options"] = "nosniff"
			localized.ngx_header["X-Frame-Options"] = "SAMEORIGIN"
			localized.ngx_header["X-XSS-Protection"] = "1; mode=block"
			localized.ngx_header["Cache-Control"] = "public, max-age=0 no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
			localized.ngx_header["Pragma"] = "no-cache"
			localized.ngx_header["Expires"] = "0"
			localized.ngx_header.content_type = "text/html; charset=" .. localized.default_charset
			localized.ngx_status = expected_header_status
			localized.ngx_exit(expected_header_status)
		end
		if req_headers[localized.x_auth_header_name] == JsPuzzleAnswer then --if the answer header provided by the browser Javascript matches what our Javascript puzzle answer should be
			localized.set_cookie1 = localized.challenge.."="..cookie_value.."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --apply our uid cookie incase javascript setting this cookies time stamp correctly has issues
			localized.set_cookie2 = localized.cookie_name_start_date.."="..localized.currenttime.."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --start date cookie
			localized.set_cookie3 = localized.cookie_name_end_date.."="..(localized.currenttime+localized.expire_time).."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --end date cookie
			localized.set_cookie4 = localized.cookie_name_encrypted_start_and_end_date.."="..calculate_signature(localized.remote_addr .. localized.currenttime .. (localized.currenttime+localized.expire_time) ).."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --start and end date combined to unique id

			localized.set_cookies = {localized.set_cookie1 , localized.set_cookie2 , localized.set_cookie3 , localized.set_cookie4}
			localized.ngx_header["Set-Cookie"] = localized.set_cookies
			localized.ngx_header["X-Content-Type-Options"] = "nosniff"
			localized.ngx_header["X-Frame-Options"] = "SAMEORIGIN"
			localized.ngx_header["X-XSS-Protection"] = "1; mode=block"
			localized.ngx_header["Cache-Control"] = "public, max-age=0 no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
			localized.ngx_header["Pragma"] = "no-cache"
			localized.ngx_header["Expires"] = "0"
			localized.ngx_header.content_type = "text/html; charset=" .. localized.default_charset
			localized.ngx_status = expected_header_status
			localized.ngx_exit(expected_header_status)
		end
	end

	if cookie_name_start_date_value ~= nil and cookie_name_end_date_value ~= nil and cookie_name_encrypted_start_and_end_date_value ~= nil then --if all our cookies exist
		local cookie_name_end_date_value_unix = localized.tonumber(cookie_name_end_date_value) or nil --convert our cookie end date provided by the user into a unix time stamp
		if cookie_name_end_date_value_unix == nil or cookie_name_end_date_value_unix == "" then --if our cookie end date date in unix does not exist
			return --return to refresh the page so it tries again
		end
		if cookie_name_end_date_value_unix <= localized.currenttime then --if our cookie end date is less than or equal to the current date meaning the users authentication time expired
			return --return to refresh the page so it tries again
		end
		if cookie_name_encrypted_start_and_end_date_value ~= calculate_signature(localized.remote_addr .. cookie_name_start_date_value_unix .. cookie_name_end_date_value_unix) then --if users authentication encrypted cookie not equal to or matching our expected cookie they should be giving us
			return --return to refresh the page so it tries again
		end
	end
	--else all checks passed bypass our firewall and show page content

	if localized.log_users_granted_access == 1 then
		localized.ngx_log(localized.ngx_LOG_TYPE,  localized.log_on_granted_text_start .. localized.remote_addr .. localized.log_on_granted_text_end)
	end
	if localized.os_clock ~= nil then
		localized.ngx_log(localized.ngx_LOG_TYPE,  " Grant Elapsed time is: " .. os.clock()-localized.os_clock)
	end
	return master_exit() --Go to content
end
--grant_access()

--[[
End Required Functions
]]

grant_access() --perform checks to see if user can access the site or if they will see our denial of service status below

if master_exit_var == 1 then
return --exit from run_checks() function
end

if localized.log_users_on_puzzle == 1 then
	localized.ngx_log(localized.ngx_LOG_TYPE,  localized.log_on_puzzle_text_start .. localized.remote_addr .. localized.log_on_puzzle_text_end)
end

--Fix localized.remote_addr output as what ever IP address the Client is using
if localized.ngx_var_http_cf_connecting_ip ~= nil then
	if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
		localized.remote_addr = localized.ngx_var_http_cf_connecting_ip
	else --you are not really cloudflare dont pretend you are to bypass flood protection
		if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
			if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
				blocked_address_check("[Anti-DDoS] (5) Blocked IP for attempting to impersonate cloudflare via header CF-Connecting-IP : ")
			end
		end
		localized.remote_addr = localized.ngx_var_remote_addr
	end
elseif localized.ngx_var_http_x_forwarded_for ~= nil then
	if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
		localized.remote_addr = localized.ngx_var_http_x_forwarded_for
	else
		if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
			if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
				blocked_address_check("[Anti-DDoS] (5) Blocked IP for attempting to impersonate proxy via header X-Forwarded-For : ")
			end
		end
		localized.remote_addr = localized.ngx_var_remote_addr
	end
else
	localized.remote_addr = localized.ngx_var_remote_addr
end

if check_tor_onion() == false then
blocked_address_check("[Anti-DDoS] Blocked IP for exceeding puzzle fail attempt : ", 1)
end

--[[
Build HTML Template
]]

localized.title = localized.host .. [[ | Anti-DDoS Flood Protection and Firewall]]

--[[
Javascript after setting cookie run xmlhttp GET request
if cookie did exist in GET request then respond with valid cookie to grant access
also
if GET request contains specific required headers provide a SETCOOKIE
then if GET request response had specific passed security check response header
run window.location.reload(); Javascript
]]
if localized.javascript_REQUEST_TYPE == 3 then --Dynamic Random request
	localized.javascript_REQUEST_TYPE = localized.math_random (1, 2) --Randomize between 1 and 2
end
if localized.javascript_REQUEST_TYPE == 1 then --GET request
	localized.javascript_REQUEST_TYPE = "GET"
end
if localized.javascript_REQUEST_TYPE == 2 then --POST request
	localized.javascript_REQUEST_TYPE = "POST"
end

local javascript_POST_headers = "" --Create empty var
local javascript_POST_data = "" --Create empty var

if localized.javascript_REQUEST_TYPE == "POST" then
	-- https://www.w3schools.com/xml/tryit.asp?filename=tryajax_post2
	javascript_POST_headers = [[xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
]]

	javascript_POST_data = [["name1=Henry&name2=Ford"]]

end

local JavascriptPuzzleVariable_name = "_" .. stringrandom(stringrandom_length)

--Variable names for JS puzzle
local JsPuzzleVar1 = "_" .. stringrandom(stringrandom_length)
local JsPuzzleVar2 = "_" .. stringrandom(stringrandom_length)
local JsPuzzleVar3 = "_" .. stringrandom(stringrandom_length)
local JsPuzzleVar4 = "_" .. stringrandom(stringrandom_length)
local JsPuzzleVar5 = "_" .. stringrandom(stringrandom_length)

--[[
Begin Tor Browser Checks
Because Tor blocks browser fingerprinting / tracking it actually makes it easy to detect by comparing screen window sizes if they do not match we know it is Tor
]]
localized.javascript_detect_tor = [[
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
	xhttp.setRequestHeader(']] .. localized.x_tor_header_name .. [[', ']] .. x_tor_header_name_value .. [[');
}
]]
--[[
End Tor Browser Checks
]]

localized.javascript_REQUEST_headers = [[
xhttp.setRequestHeader(']] .. localized.x_auth_header_name .. [[', ]] .. JavascriptPuzzleVariable_name .. [[); //make the answer what ever the browser figures it out to be
			xhttp.setRequestHeader('X-Requested-with', 'XMLHttpRequest');
			xhttp.setRequestHeader('X-Requested-TimeStamp', '');
			xhttp.setRequestHeader('X-Requested-TimeStamp-Expire', '');
			xhttp.setRequestHeader('X-Requested-TimeStamp-Combination', '');
			xhttp.setRequestHeader('X-Requested-Type', 'GET');
			xhttp.setRequestHeader('X-Requested-Type-Combination', 'GET'); //Encrypted for todays date
			xhttp.withCredentials = true;
]] .. localized.javascript_detect_tor

--[[
Javascript Puzzle for web browser to solve do not touch this unless you understand Javascript, HTML and Lua
]]
--Simple static Javascript puzzle where every request all year round the question and answer would be the same pretty predictable for bots.
--localized.JavascriptPuzzleVars = [[22 + 22]] --44
--local JavascriptPuzzleVars_answer = "44" --if this does not equal the equation above you will find access to your site will be blocked make sure you can do maths!?

--Improved the script
--Moved the script to be able to use answer (ip+signature string)
localized.JavascriptPuzzleVars = [[
	(function(){var ]]..JsPuzzleVar1..[[=Math.floor(1E3*Math.sin(']]..localized.os_date("%Y%m%d", localized.os_time_saved)..[[')),]]..JsPuzzleVar2..[[=]]..JsPuzzleVar5..[[(]]..JsPuzzleVar1..[[,256),]]..JsPuzzleVar3..[[=Math.floor(]]..JsPuzzleVar5..[[(]]..JsPuzzleVar1..[[*Math.sin(]]..JsPuzzleVar1..[[),10))+1;]]..JsPuzzleVar1..[[=']]..answer..[['.split("").map(function(]]..JsPuzzleVar1..[[,]]..JsPuzzleVar4..[[){return String.fromCharCode(]]..JsPuzzleVar5..[[((String.fromCharCode(]]..JsPuzzleVar5..[[(]]..JsPuzzleVar1..[[.charCodeAt(0)^(]]..JsPuzzleVar2..[[+]]..JsPuzzleVar4..[[),256)).charCodeAt(0)+]]..JsPuzzleVar3..[[),256))}).join("");return btoa(]]..JsPuzzleVar1..[[)})();
]] --JavaScript code to produce a unique string by using client's signature and yesterday's date and XORing them
   --Made it more secure by using random variable names on each run.
   --Could be obfuscated as well in the future

localized.JavascriptPuzzleHelperFunctions = [[
	function ]]..JsPuzzleVar5..[[(_,__){return ((_ % __) + __) % __;}
]]
   

localized.JavascriptPuzzleVariable = [[
var ]] .. JavascriptPuzzleVariable_name .. [[=]] .. localized.JavascriptPuzzleVars ..[[;
]]

-- https://www.w3schools.com/xml/tryit.asp?filename=try_dom_xmlhttprequest
localized.javascript_anti_ddos = [[
(function(){
	var a = function() {try{return !!window.addEventListener} catch(e) {return !1} },
	b = function(b, c) {a() ? document.addEventListener("DOMContentLoaded", b, c) : document.attachEvent("onreadystatechange", b)};
	b(function(){
		var timeleft = ]] .. localized.refresh_auth .. [[;
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
			document.cookie = ']] .. localized.challenge .. [[=]] .. answer .. [[' + '; expires=' + ']] .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. [[' + '; path=/';
			//javascript puzzle for browser to figure out to get answer
			]] .. localized.JavascriptVars_opening .. [[
			]] .. localized.JavascriptPuzzleHelperFunctions .. [[
			]] .. localized.JavascriptPuzzleVariable .. [[
			]] .. localized.JavascriptVars_closing .. [[
			//end javascript puzzle
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function() {
				if (xhttp.readyState === 4) {
					document.getElementById("status").innerHTML = "Refresh your page.";
					location.reload(true);
				}
			};
			xhttp.open("]] .. localized.javascript_REQUEST_TYPE .. [[", "]] .. localized.request_uri .. [[", true);
			]] .. localized.javascript_REQUEST_headers .. [[
			]] .. javascript_POST_headers .. [[
			xhttp.send(]] .. javascript_POST_data .. [[);
		}, ]] .. localized.refresh_auth+1 .. [[000); /*if correct data has been sent then the auth response will allow access*/
	}, false);
})();
]]

--TODO: include Captcha like Google ReCaptcha

--[[
encrypt/obfuscate the javascript output
]]
if localized.encrypt_javascript_output == 1 then --No encryption/Obfuscation of Javascript so show Javascript in plain text
localized.javascript_anti_ddos = [[<script type="text/javascript" charset="]] .. localized.default_charset .. [[" data-cfasync="false">
]] .. localized.javascript_anti_ddos .. [[
</script>]]
else --some form of obfuscation has been specified so obfuscate the javascript output
localized.javascript_anti_ddos = encrypt_javascript(localized.javascript_anti_ddos, localized.encrypt_javascript_output) --run my function to encrypt/obfuscate javascript output
end


--Adverts positions
localized.head_ad_slot = [[
<!-- Start: Ad code and script tags for header of page -->
<!-- End: Ad code and script tags for header of page -->
]]
localized.top_body_ad_slot = [[
<!-- Start: Ad code and script tags for top of page -->
<!-- End: Ad code and script tags for top of page -->
]]
localized.left_body_ad_slot = [[
<!-- Start: Ad code and script tags for left of page -->
<!-- End: Ad code and script tags for left of page -->
]]
localized.right_body_ad_slot = [[
<!-- Start: Ad code and script tags for right of page -->
<!-- End: Ad code and script tags for right of page -->
]]
localized.footer_body_ad_slot = [[
<!-- Start: Ad code and script tags for bottom of page -->
<!-- End: Ad code and script tags for bottom of page -->
]]
--End advert positions

localized.ddos_credits = [[
<div class="credits" style="text-align:center;font-size:100%;">
<a href="//facebook.com/C0nw0nk" target="_blank">DDoS protection by &copy; Conor McKnight</a>
</div>
]]

if localized.credits == 2 then
localized.ddos_credits = "" --make empty string
end

localized.request_details = [[
<br>
<div id="status" style="color:#bd2426;font-size:200%;">
<noscript>Please turn JavaScript on and reload the page.<br></noscript>
This process is automatic. Your browser will redirect to your requested content shortly.
<br>
Please allow up to <span id="countdowntimer">]] .. localized.refresh_auth .. [[</span> seconds&hellip;
</div>
<br>
<br>
<h3 style="color:#bd2426;">Request Details :</h3>
IP address : ]] .. localized.remote_addr .. [[
<br>
Request URL : ]] .. localized.URL .. [[
<br>
User-Agent : ]] .. localized.user_agent .. [[
<br>
]]

localized.style_sheet = [[
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

localized.anti_ddos_html_output = [[
<!DOCTYPE html>
<html>
<head>
<meta charset="]] .. localized.default_charset .. [[" />
<meta http-equiv="Content-Type" content="text/html; charset=]] .. localized.default_charset .. [[" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge,chrome=1" />
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
<meta name="robots" content="noindex, nofollow" />
<title>]] .. localized.title .. [[</title>
<style type="text/css">
]] .. localized.style_sheet .. [[
</style>
]] .. localized.head_ad_slot .. [[
]] .. localized.javascript_anti_ddos .. [[
</head>
<body style="background-color:#EEEEEE;color:#000000;font-family:Arial,Helvetica,sans-serif;font-size:100%;">
<div style="width:auto;margin:16px auto;border:1px solid #CCCCCC;background-color:#FFFFFF;border-radius:3px 3px 3px 3px;padding:10px;">
<div style="float:right;margin-top:10px;">
<br>
<h1>Checking your browser</h1>
</div>
<br>
<h1>]] .. localized.title .. [[</h1>
<p>
<b>Please wait a moment while we verify your request</b>
<br>
<br>
<br>
]] .. localized.top_body_ad_slot .. [[
<br>
<br>
<center>
<h2>Information :</h2>
]] .. localized.request_details .. [[
</center>
]] .. localized.footer_body_ad_slot .. [[
</div>
]] .. localized.ddos_credits .. [[
</body>
</html>
]]

--All previous checks failed and no access_granted permited so display authentication check page.
--Output Anti-DDoS Authentication Page
if localized.set_cookies == nil then
localized.set_cookies = localized.challenge.."="..answer.."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --apply our uid cookie in header here incase browsers javascript can't set cookies due to permissions.
end
localized.ngx_header["Set-Cookie"] = localized.set_cookies
localized.ngx_header["X-Content-Type-Options"] = "nosniff"
localized.ngx_header["X-Frame-Options"] = "SAMEORIGIN"
localized.ngx_header["X-XSS-Protection"] = "1; mode=block"
localized.ngx_header["Cache-Control"] = "public, max-age=0 no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
localized.ngx_header["Pragma"] = "no-cache"
localized.ngx_header["Expires"] = "0"
if localized.credits == 1 then
localized.ngx_header["X-Anti-DDoS"] = "Conor McKnight | facebook.com/C0nw0nk"
end
localized.ngx_header.content_type = "text/html; charset=" .. localized.default_charset
localized.ngx_status = authentication_page_status_output
localized.ngx_say(localized.anti_ddos_html_output)
if localized.os_clock ~= nil then
localized.ngx_log(localized.ngx_LOG_TYPE,  " Puzzle Elapsed time is: " .. os.clock()-localized.os_clock)
end
localized.ngx_exit(authentication_page_status_output)

end
run_checks() --nest function to prevent function at line 1 has more than 200 local variables and function at line X has more than X upvalues just my way of putting locals inside functions to get around the 200 limit

if localized.content_cache == nil or #localized.content_cache == 0 then
	--localized.ngx_log(localized.ngx_LOG_TYPE,  " resp_content_type before " .. get_resp_content_type() )
	if localized.content_type_fix then
		get_resp_content_type(1) --fix for random bug where content-type output is application/octet-stream on text/html seems to only happen on a / directory not a /index.html
	end
	--localized.ngx_log(localized.ngx_LOG_TYPE,  " resp_content_type after " .. get_resp_content_type() )
	if localized.exit_status then
		localized.ngx_exit(localized.ngx_OK) --Go to content
	end
end

if localized.content_cache ~= nil and #localized.content_cache > 0 then

local function minification(content_type_list)

	local function grab_cookies(cookie_name, cookie_value, guest_value)
		local cookie_match = 0
		local guest_or_logged_in = 0
		local req_headers = localized.ngx_req_get_headers() --get all request headers
		local cookies = req_headers["cookie"] or "" --for dynamic pages
		-- strip all Set-Cookie attributes, e.g. "Name=value; Path=/; Max-Age=2592000" => "Name=value"
		local function strip_attributes(cookie)
			return localized.string_match(cookie, "[^;]+")
		end
		--iterator for use in "for in" loop, works both with strings and tables
		local function iterate_cookies(cookies)
			local i = 0
			return function()
				i = i+1
				if localized.type(cookies) == "string" then
					if i == 1 then return strip_attributes(cookies) end
					elseif localized.type(cookies) == "table" then
					if cookies[i] then return strip_attributes(cookies[i]) end
				end
			end
		end
		--at the first loop iteration separator should be an empty string if client browser send no cookies or "; " otherwise
		local separator = cookies and "; " or ""
		for cookie in iterate_cookies(cookies) do
			cookies = cookies .. separator .. cookie
			--next separator definitely should be a "; "
			separator = "; "
		end
		local regex_1 = "[^;]+"
		local regex_2 = "%s*(.*)%s*=%s*(.*)%s*"
		local _ = localized.string_gsub(cookies, ";"," ; ") --fix semicolons
		local _ = localized.string_gsub(_, "%s+", "") --remove white space
		if not localized.string_find(_, ";$") then --if does not end in semicolon
			_ = _ .. ";" --insert semicolon
		end
		for each_cookie in localized.string_gmatch(_, regex_1) do
			if each_cookie ~= nil then
				for cookiename, cookievalue in localized.string_gmatch(each_cookie, regex_2) do
					if cookiename ~= nil and cookievalue ~= nil then
						if localized.string_find(cookiename, cookie_name ) and localized.string_find(cookievalue, cookie_value ) then
							--localized.ngx_log(localized.ngx_LOG_TYPE,"name is "..cookiename)
							--localized.ngx_log(localized.ngx_LOG_TYPE,"value is "..cookievalue)
							cookie_match = 1
							if guest_value == 1 then
								guest_or_logged_in = 1
							end
							break --break out since found match
						end
					end
				end
			end
		end
		return cookie_match, guest_or_logged_in
	end

	for i=1,#content_type_list do
		if faster_than_match(content_type_list[i][1]) or localized.string_find(localized.URL, content_type_list[i][1]) then --if our host matches one in the table
			if content_type_list[i][10] == 1 then
				localized.ngx_header["X-Cache-Status"] = "MISS"
			end

			local request_method_match = 0
			local cookie_match = 0
			local guest_or_logged_in = 0
			local request_uri_match = 0
			if content_type_list[i][7] ~= "" then
				for a=1, #content_type_list[i][7] do
					if localized.ngx_var.request_method == content_type_list[i][7][a] then
						request_method_match = 1
						break
					end
				end
				if request_method_match == 0 then
					--if content_type_list[i][5] == 1 then
						--localized.ngx_log(localized.ngx_LOG_TYPE, "request method not matched")
					--end
					--goto end_for_loop
				end
			end
			if content_type_list[i][8] ~= "" and content_type_list[i][8] ~= nil then
				for a=1, #content_type_list[i][8] do
					local cookie_name = content_type_list[i][8][a][1]
					local cookie_value = content_type_list[i][8][a][2]
					cookie_match, guest_or_logged_in = grab_cookies(cookie_name, cookie_value, content_type_list[i][8][a][3])
				end
				if cookie_match == 1 then
					if guest_or_logged_in == 0 then --if guest user cache only then bypass cache for logged in users
						--goto end_for_loop
						--if content_type_list[i][5] == 1 then
							--localized.ngx_log(localized.ngx_LOG_TYPE, " GUEST ONLY cache " .. guest_or_logged_in )
						--end
					else
						--if content_type_list[i][5] == 1 then
							--localized.ngx_log(localized.ngx_LOG_TYPE, " BOTH GUEST and LOGGED_IN in cache " .. guest_or_logged_in )
						--end
						cookie_match = 0 --set to 0
					end
				end
			end
			if content_type_list[i][9] ~= "" and content_type_list[i][9] ~= nil then
				for a=1, #content_type_list[i][9] do
					if faster_than_match(content_type_list[i][9][a]) or localized.string_find(localized.request_uri, content_type_list[i][9][a] ) then
						request_uri_match = 1
						break
					end
				end
				if request_uri_match == 1 then
					--if content_type_list[i][5] == 1 then
						--localized.ngx_log(localized.ngx_LOG_TYPE, "request uri matched so bypass")
					--end
					--goto end_for_loop
				end
			end

			if request_method_match == 1 and cookie_match == 0 and request_uri_match == 0 then

				--I use this to override the status output
				local function response_status_match(resstatus)
					--localized.ngx_log(localized.ngx_LOG_TYPE, " res status is " .. localized.tostring(resstatus) )
					if resstatus == 100 then
						return localized.ngx_HTTP_CONTINUE --(100)
					end
					if resstatus == 101 then
						return localized.ngx_HTTP_SWITCHING_PROTOCOLS --(101)
					end
					if resstatus == 200 then
						return localized.ngx_HTTP_OK --(200)
					end
					if resstatus == 201 then
						return localized.ngx_HTTP_CREATED --(201)
					end
					if resstatus == 202 then
						return localized.ngx_HTTP_ACCEPTED --(202)
					end
					if resstatus == 204 then
						return localized.ngx_HTTP_NO_CONTENT --(204)
					end
					if resstatus == 206 then
						return localized.ngx_HTTP_PARTIAL_CONTENT --(206)
					end
					if resstatus == 300 then
						return localized.ngx_HTTP_SPECIAL_RESPONSE --(300)
					end
					if resstatus == 301 then
						return localized.ngx_HTTP_MOVED_PERMANENTLY --(301)
					end
					if resstatus == 302 then
						return localized.ngx_HTTP_MOVED_TEMPORARILY --(302)
					end
					if resstatus == 303 then
						return localized.ngx_HTTP_SEE_OTHER --(303)
					end
					if resstatus == 304 then
						return localized.ngx_HTTP_NOT_MODIFIED --(304)
					end
					if resstatus == 307 then
						return localized.ngx_HTTP_TEMPORARY_REDIRECT --(307)
					end
					if resstatus == 308 then
						return localized.ngx_HTTP_PERMANENT_REDIRECT --(308)
					end
					if resstatus == 400 then
						return localized.ngx_HTTP_BAD_REQUEST --(400)
					end
					if resstatus == 401 then
						return localized.ngx_HTTP_UNAUTHORIZED --(401)
					end
					if resstatus == 402 then
						return localized.ngx_HTTP_PAYMENT_REQUIRED --(402)
					end
					if resstatus == 403 then
						return localized.ngx_HTTP_FORBIDDEN --(403)
					end
					if resstatus == 404 then
						return localized.ngx_HTTP_OK --override lua error attempt to set status 404 via localized.ngx_exit after sending out the response status 200
						--return localized.ngx_HTTP_NOT_FOUND --(404)
					end
					if resstatus == 405 then
						return localized.ngx_HTTP_NOT_ALLOWED --(405)
					end
					if resstatus == 406 then
						return localized.ngx_HTTP_NOT_ACCEPTABLE --(406)
					end
					if resstatus == 408 then
						return localized.ngx_HTTP_REQUEST_TIMEOUT --(408)
					end
					if resstatus == 409 then
						return localized.ngx_HTTP_CONFLICT --(409)
					end
					if resstatus == 410 then
						return localized.ngx_HTTP_GONE --(410)
					end
					if resstatus == 426 then
						return localized.ngx_HTTP_UPGRADE_REQUIRED --(426)
					end
					if resstatus == 429 then
						return localized.ngx_HTTP_TOO_MANY_REQUESTS --(429)
					end
					if resstatus == 444 then
						return localized.ngx_HTTP_CLOSE --(444)
					end
					if resstatus == 451 then
						return localized.ngx_HTTP_ILLEGAL --(451)
					end
					if resstatus == 500 then
						return localized.ngx_HTTP_INTERNAL_SERVER_ERROR --(500)
					end
					if resstatus == 501 then
						return localized.ngx_HTTP_NOT_IMPLEMENTED --(501)
					end
					if resstatus == 501 then
						return localized.ngx_HTTP_METHOD_NOT_IMPLEMENTED --(501)
					end
					if resstatus == 502 then
						return localized.ngx_HTTP_BAD_GATEWAY --(502)
					end
					if resstatus == 503 then
						return localized.ngx_HTTP_SERVICE_UNAVAILABLE --(503)
					end
					if resstatus == 504 then
						return localized.ngx_HTTP_GATEWAY_TIMEOUT --(504)
					end
					if resstatus == 505 then
						return localized.ngx_HTTP_VERSION_NOT_SUPPORTED --(505)
					end
					if resstatus == 507 then
						return localized.ngx_HTTP_INSUFFICIENT_STORAGE --(507)
					end
					--If none of above just pass the numeric status back
					return resstatus
				end

				local function headers_forward()
					local output = nil
					if content_type_list[i][18] ~= nil and #content_type_list[i][18] > 0 then
						--for headerName, header in localized.next, content_type_list[i][18] do
							--localized.ngx_log(localized.ngx_LOG_TYPE, " localized.ngx.location.capture forwarding header name " .. headerName .. " value " .. header )
						--end
						output = content_type_list[i][18]
					end
					return output
				end

				local map = {
					GET = localized.ngx_HTTP_GET,
					HEAD = localized.ngx_HTTP_HEAD,
					PUT = localized.ngx_HTTP_PUT,
					POST = localized.ngx_HTTP_POST,
					DELETE = localized.ngx_HTTP_DELETE,
					OPTIONS = localized.ngx_HTTP_OPTIONS,
					MKCOL = localized.ngx_HTTP_MKCOL,
					COPY = localized.ngx_HTTP_COPY,
					MOVE = localized.ngx_HTTP_MOVE,
					PROPFIND = localized.ngx_HTTP_PROPFIND,
					PROPPATCH = localized.ngx_HTTP_PROPPATCH,
					LOCK = localized.ngx_HTTP_LOCK,
					UNLOCK = localized.ngx_HTTP_UNLOCK,
					PATCH = localized.ngx_HTTP_PATCH,
					TRACE = localized.ngx_HTTP_TRACE,
					CONNECT = localized.ngx_HTTP_CONNECT, --does not exist but put here never know in the future
				}

				--[[
				For debugging tests i have checked these and they work fine i am leaving this here for future refrence
				curl post request test - curl.exe "http://localhost/" -H "User-Agent: testagent" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Accept-Language: en-GB,en;q=0.5" -H "Accept-Encoding: gzip, deflate, br, zstd" -H "DNT: 1" -H "Connection: keep-alive" -H "Cookie: name1=1; name2=2; logged_in=1" -H "Upgrade-Insecure-Requests: 1" -H "Sec-Fetch-Dest: document" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: none" -H "Sec-Fetch-User: ?1" -H "Priority: u=0, i" -H "Pragma: no-cache" -H "Cache-Control: no-cache" --request POST --data '{"username":"xyz","password":"xyz"}' -H "Content-Type: application/json"
				curl post no data test - curl.exe "http://localhost/" -H "User-Agent: testagent" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Accept-Language: en-GB,en;q=0.5" -H "Accept-Encoding: gzip, deflate, br, zstd" -H "DNT: 1" -H "Connection: keep-alive" -H "Cookie: name1=1; name2=2; logged_in=1" -H "Upgrade-Insecure-Requests: 1" -H "Sec-Fetch-Dest: document" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: none" -H "Sec-Fetch-User: ?1" -H "Priority: u=0, i" -H "Pragma: no-cache" -H "Cache-Control: no-cache" --request POST -H "Content-Type: application/json"

				client_body_in_file_only on; #nginx config to test / debug on post data being stored in file incase of large post data sizes the nginx memory buffer was not big enough i turned this on to check this works as it should.
				]]
				localized.ngx_req_read_body()
				local request_body = localized.ngx_req_get_body_data()
				local request_body_file = ""
				if not request_body then
					local file = localized.ngx_req_get_body_file()
					if file then
						request_body_file = file
					end
					--client_body_in_file_only on; #nginx config to test / debug
					--localized.ngx_log(localized.ngx_LOG_TYPE, " request_body_file is " .. request_body_file )
				end
				if request_body_file ~= "" then
					local fh, err = io.open(request_body_file, "rb")
					if err then
						localized.ngx_status = localized.ngx_HTTP_INTERNAL_SERVER_ERROR
						localized.ngx_log(localized.ngx_LOG_TYPE, "error reading request_body_file:", err)
						return
						--goto end_for_loop
					end
					request_body = fh:read("*all")
					fh:close()
				end
				if request_body == nil then
					request_body = "" --set to empty string
				end

				local req_headers = localized.ngx_req_get_headers() --get all request headers

				localized.cached_restyhttp = nil
				local function check_resty_http()
					if localized.cached_restyhttp ~= nil then
						return localized.cached_restyhttp
					end
					local pcall = pcall
					local require = require
					localized.cached_restyhttp = pcall(require, "resty.http") --check if resty http library exists will be true or false
					return localized.cached_restyhttp
				end

				local cached = content_type_list[i][3] or ""
				if cached ~= "" then
					local ttl = content_type_list[i][4] or ""
					local cookie_string = ""
					if guest_or_logged_in == 1 then
						local cookies = req_headers["cookie"] or "" --for dynamic pages
						if localized.type(cookies) ~= "table" then
							--localized.ngx_log(localized.ngx_LOG_TYPE, " cookies are string ")
							cookie_string = cookies
						else
							--localized.ngx_log(localized.ngx_LOG_TYPE, " cookies are table ")
							for t=1, #cookies do
								cookie_string = cookie_string .. cookies[t]
							end
						end
					else
						req_headers["cookie"] = "" --avoid cache poisoning by removing REQUEST header cookies to ensure user is logged out when the expected logged_in cookie is missing
					end
					--localized.ngx_log(localized.ngx_LOG_TYPE, " cookies are " .. cookie_string)
					
					--TODO: convert cache key to a smaller storage format to use less memory for storage perhaps hex or binary etc
					local key = localized.ngx_var.request_method .. localized.scheme .. "://" .. localized.host .. content_type_list[i][12] .. cookie_string .. request_body --fastcgi_cache_key / proxy_cache_key - GET - https - :// - localized.host - localized.request_uri - request_header["cookie"] - request_body
					--localized.ngx_log(localized.ngx_LOG_TYPE, " full cache key is " .. key)

					local content_type_cache = cached:get("content-type"..key) or nil

					if content_type_cache == nil then
						if #content_type_list[i][6] > 0 then

							if content_type_list[i][13] and check_resty_http() then
								local httpc = require("resty.http").new()
								local res = httpc:request_uri(content_type_list[i][12], {
									method = map[localized.ngx_var.request_method],
									body = request_body, --localized.ngx_var.request_body,
									headers = headers_forward(),
								})
								if res then
									for z=1, #content_type_list[i][6] do
										if #res.body > 0 and res.status == content_type_list[i][6][z] then
											local output_minified = res.body

											local content_type_header_match = 0
											if res.headers ~= nil and localized.type(res.headers) == "table" then
												for headerName, header in localized.next, res.headers do
													--localized.ngx_log(localized.ngx_LOG_TYPE, " header name" .. headerName .. " value " .. header )
													if localized.string_lower(localized.tostring(headerName)) == "content-type" then
														if faster_than_match(content_type_list[i][2]) or localized.string_find(header, content_type_list[i][2]) == nil then
															--goto end_for_loop
															content_type_header_match = 1
														end
													end
												end
											end

											if content_type_header_match == 0 then
												localized.get_resp_content_type_counter = localized.get_resp_content_type_counter+2 --make sure we dont run again

												local file_size_bigger = 0
												if content_type_list[i][15] ~= "" and #output_minified > content_type_list[i][15] then
													if content_type_list[i][5] == 1 then
														localized.ngx_log(localized.ngx_LOG_TYPE, " File size bigger than maximum allowed not going to cache " .. #output_minified .. " and " .. content_type_list[i][15] )
													end
													--goto end_for_loop
													file_size_bigger = 1
												end

												local file_size_smaller = 0
												if content_type_list[i][16] ~= "" and #output_minified < content_type_list[i][16] then
													if content_type_list[i][5] == 1 then
														localized.ngx_log(localized.ngx_LOG_TYPE, " File size smaller than minimum allowed not going to cache " .. #output_minified .. " and " .. content_type_list[i][16] )
													end
													--goto end_for_loop
													file_size_smaller = 1
												end

												if file_size_bigger == 0 and file_size_smaller == 0 then

													if content_type_list[i][14] ~= "" and #content_type_list[i][14] > 0 then
														for x=1,#content_type_list[i][14] do
															output_minified = localized.string_gsub(output_minified, content_type_list[i][14][x][1], content_type_list[i][14][x][2])
														end --end foreach regex check
													end

													if content_type_list[i][5] == 1 then
														localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Cache] Page not yet cached or ttl has expired so putting into cache key : " .. key )
													end
													localized.ngx_header.content_type = content_type_list[i][2]
													if content_type_list[i][10] == 1 then
														localized.ngx_header["X-Cache-Status"] = "UPDATING"
													end
													cached:set(key, output_minified, ttl)
													cached:set("s"..key, res.status, ttl)
													if res.headers ~= nil and localized.type(res.headers) == "table" then
														for headerName, header in localized.next, res.headers do
															local header_original = headerName --so we do not make the header all lower case on insert
															if content_type_list[i][17] ~= "" or #content_type_list[i][17] > 0 then
																for a=1, #content_type_list[i][17] do
																	if localized.string_lower(localized.tostring(header_original)) == localized.string_lower(content_type_list[i][17][a]) then
																		cached:set(localized.string_lower(localized.tostring(header_original))..key, header, ttl)
																	end
																end
															end
															--localized.ngx_log(localized.ngx_LOG_TYPE, " header name" .. headerName .. " value " .. header )
															localized.ngx_header[headerName] = header
														end
													end
													if content_type_list[i][11] == 1 and guest_or_logged_in == 0 then
														localized.ngx_header["Set-Cookie"] = nil
													end
													localized.ngx_header["Content-Length"] = #output_minified
													--localized.ngx_status = res.status
													localized.ngx_status = response_status_match(res.status)
													localized.ngx_say(output_minified)
													localized.ngx_exit(response_status_match(content_type_list[i][6][z]))
													--localized.ngx_exit(content_type_list[i][6][z])
													break
												end --file size bigger and smaller
											end
										end
									end
								end --end if res

							else

								local res = localized.ngx.location.capture(content_type_list[i][12], {
								method = map[localized.ngx_var.request_method],
								body = request_body, --localized.ngx_var.request_body,
								args = "",
								headers = headers_forward(),
								})
								if res then
									for z=1, #content_type_list[i][6] do
										if #res.body > 0 and res.status == content_type_list[i][6][z] then
											local output_minified = res.body

											local content_type_header_match = 0
											if res.header ~= nil and localized.type(res.header) == "table" then
												for headerName, header in localized.next, res.header do
													--localized.ngx_log(localized.ngx_LOG_TYPE, " header name" .. headerName .. " value " .. header )
													if localized.string_lower(localized.tostring(headerName)) == "content-type" then
														if faster_than_match(content_type_list[i][2]) or localized.string_find(header, content_type_list[i][2]) == nil then
															--goto end_for_loop
															content_type_header_match = 1
														end
													end
												end
											end

											if content_type_header_match == 0 then
												localized.get_resp_content_type_counter = localized.get_resp_content_type_counter+2 --make sure we dont run again

												local file_size_bigger = 0
												if content_type_list[i][15] ~= "" and #output_minified > content_type_list[i][15] then
													if content_type_list[i][5] == 1 then
														localized.ngx_log(localized.ngx_LOG_TYPE, " File size bigger than maximum allowed not going to cache " .. #output_minified .. " and " .. content_type_list[i][15] )
													end
													--goto end_for_loop
													file_size_bigger = 1
												end

												local file_size_smaller = 0
												if content_type_list[i][16] ~= "" and #output_minified < content_type_list[i][16] then
													if content_type_list[i][5] == 1 then
														localized.ngx_log(localized.ngx_LOG_TYPE, " File size smaller than minimum allowed not going to cache " .. #output_minified .. " and " .. content_type_list[i][16] )
													end
													--goto end_for_loop
													file_size_smaller = 1
												end

												if file_size_bigger == 0 and file_size_smaller == 0 then

													if content_type_list[i][14] ~= "" and #content_type_list[i][14] > 0 then
														for x=1,#content_type_list[i][14] do
															output_minified = localized.string_gsub(output_minified, content_type_list[i][14][x][1], content_type_list[i][14][x][2])
														end --end foreach regex check
													end

													if content_type_list[i][5] == 1 then
														localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Cache] Page not yet cached or ttl has expired so putting into cache key : " .. key )
													end
													localized.ngx_header.content_type = content_type_list[i][2]
													if content_type_list[i][10] == 1 then
														localized.ngx_header["X-Cache-Status"] = "UPDATING"
													end
													cached:set(key, output_minified, ttl)
													cached:set("s"..key, res.status, ttl)
													if res.header ~= nil and localized.type(res.header) == "table" then
														for headerName, header in localized.next, res.header do
															local header_original = headerName --so we do not make the header all lower case on insert
															if content_type_list[i][17] ~= "" or #content_type_list[i][17] > 0 then
																for a=1, #content_type_list[i][17] do
																	if localized.string_lower(localized.tostring(header_original)) == localized.string_lower(content_type_list[i][17][a]) then
																		cached:set(localized.string_lower(localized.tostring(header_original))..key, header, ttl)
																	end
																end
															end
															--localized.ngx_log(localized.ngx_LOG_TYPE, " header name" .. headerName .. " value " .. header )
															localized.ngx_header[headerName] = header
														end
													end
													if content_type_list[i][11] == 1 and guest_or_logged_in == 0 then
														localized.ngx_header["Set-Cookie"] = nil
													end
													localized.ngx_header["Content-Length"] = #output_minified
													--localized.ngx_status = res.status
													localized.ngx_status = response_status_match(res.status)
													localized.ngx_say(output_minified)
													localized.ngx_exit(response_status_match(content_type_list[i][6][z]))
													--localized.ngx_exit(content_type_list[i][6][z])
													break
												end --file size bigger and smaller
											end
										end
									end
								end --end if res
							end
						end

					else --if content_type_cache == nil then

						if content_type_cache and localized.string_find(content_type_cache, content_type_list[i][2]) then
							localized.get_resp_content_type_counter = localized.get_resp_content_type_counter+2 --make sure we dont run again

							if content_type_list[i][5] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Cache] Served from cache key : " .. key )
							end

							local output_minified = cached:get(key)
							local res_status = cached:get("s"..key)

							--localized.ngx_header.content_type = content_type_list[i][2]
							if content_type_list[i][10] == 1 then
								localized.ngx_header["X-Cache-Status"] = "HIT"
							end
							if content_type_list[i][17] ~= "" or #content_type_list[i][17] > 0 then
								for a=1, #content_type_list[i][17] do
									local header_name = localized.string_lower(content_type_list[i][17][a])
									local check_header = cached:get(header_name..key) or nil
									if check_header ~= nil then
										--localized.ngx_log(localized.ngx_LOG_TYPE, " check_header " .. check_header )
										localized.ngx_header[header_name] = check_header
									end
								end
							end
							if content_type_list[i][11] == 1 and guest_or_logged_in == 0 or guest_or_logged_in == 1 then
								localized.ngx_header["Set-Cookie"] = nil
							end
							localized.ngx_header["Content-Length"] = #output_minified
							--localized.ngx_status = res_status
							localized.ngx_status = response_status_match(res_status)
							localized.ngx_say(output_minified)
							localized.ngx_exit(response_status_match(res_status))
							--localized.ngx_exit(res_status)

						end
					end --if content_type_cache == nil then

				else --shared mem zone not specified
					if #content_type_list[i][6] > 0 then
						--[[]]
						if content_type_list[i][13] and check_resty_http() then
							local httpc = require("resty.http").new()
							local res = httpc:request_uri(content_type_list[i][12], {
								method = map[localized.ngx_var.request_method],
								body = request_body, --localized.ngx_var.request_body,
								headers = headers_forward(),
							})
							if res then
								for z=1, #content_type_list[i][6] do
									if #res.body > 0 and res.status == content_type_list[i][6][z] then
										local output_minified = res.body

										local content_type_header_match = 0
										if res.headers ~= nil and localized.type(res.headers) == "table" then
											for headerName, header in localized.next, res.headers do
												--localized.ngx_log(localized.ngx_LOG_TYPE, " header name" .. headerName .. " value " .. header )
												if localized.string_lower(localized.tostring(headerName)) == "content-type" then
													if faster_than_match(content_type_list[i][2]) or localized.string_find(header, content_type_list[i][2]) == nil then
														--goto end_for_loop
														content_type_header_match = 1
													end
												end
											end
										end

										if content_type_header_match == 0 then
											localized.get_resp_content_type_counter = localized.get_resp_content_type_counter+2 --make sure we dont run again

											local file_size_bigger = 0
											if content_type_list[i][15] ~= "" and #output_minified > content_type_list[i][15] then
												if content_type_list[i][5] == 1 then
													localized.ngx_log(localized.ngx_LOG_TYPE, " File size bigger than maximum allowed not going to cache " .. #output_minified .. " and " .. content_type_list[i][15] )
												end
												--goto end_for_loop
												file_size_bigger = 1
											end

											local file_size_smaller = 0
											if content_type_list[i][16] ~= "" and #output_minified < content_type_list[i][16] then
												if content_type_list[i][5] == 1 then
													localized.ngx_log(localized.ngx_LOG_TYPE, " File size smaller than minimum allowed not going to cache " .. #output_minified .. " and " .. content_type_list[i][16] )
												end
												--goto end_for_loop
												file_size_smaller = 1
											end

											if file_size_bigger == 0 and file_size_smaller == 0 then

												if content_type_list[i][14] ~= "" and #content_type_list[i][14] > 0 then
													for x=1,#content_type_list[i][14] do
														output_minified = localized.string_gsub(output_minified, content_type_list[i][14][x][1], content_type_list[i][14][x][2])
													end --end foreach regex check
												end

												if res.headers ~= nil and localized.type(res.headers) == "table" then
													for headerName, header in localized.next, res.headers do
														--localized.ngx_log(localized.ngx_LOG_TYPE, " header name" .. headerName .. " value " .. header )
														localized.ngx_header[headerName] = header
													end
												end
												--if content_type_list[i][11] == 1 and guest_or_logged_in == 0 then
													--localized.ngx_header["Set-Cookie"] = nil
												--end
												localized.ngx_header["Content-Length"] = #output_minified
												--localized.ngx_status = res.status
												localized.ngx_status = response_status_match(res.status)
												localized.ngx_say(output_minified)
												localized.ngx_exit(response_status_match(content_type_list[i][6][z]))
												--localized.ngx_exit(content_type_list[i][6][z])
												break
											end --file size bigger and smaller
										end
									end
								end
							end --end if res

						else
						--[[]]

							local res = localized.ngx.location.capture(content_type_list[i][12], {
							method = map[localized.ngx_var.request_method],
							body = request_body, --localized.ngx_var.request_body,
							args = "",
							headers = headers_forward(),
							})
							if res then
								for z=1, #content_type_list[i][6] do
									if #res.body > 0 and res.status == content_type_list[i][6][z] then
										local output_minified = res.body

										local content_type_header_match = 0
										if res.header ~= nil and localized.type(res.header) == "table" then
											for headerName, header in localized.next, res.header do
												--localized.ngx_log(localized.ngx_LOG_TYPE, " header name" .. headerName .. " value " .. header )
												if localized.string_lower(localized.tostring(headerName)) == "content-type" then
													if faster_than_match(content_type_list[i][2]) or localized.string_find(header, content_type_list[i][2]) == nil then
														--goto end_for_loop
														content_type_header_match = 1
													end
												end
											end
										end

										if content_type_header_match == 0 then
											localized.get_resp_content_type_counter = localized.get_resp_content_type_counter+2 --make sure we dont run again

											local file_size_bigger = 0
											if content_type_list[i][15] ~= "" and #output_minified > content_type_list[i][15] then
												if content_type_list[i][5] == 1 then
													localized.ngx_log(localized.ngx_LOG_TYPE, " File size bigger than maximum allowed not going to cache " .. #output_minified .. " and " .. content_type_list[i][15] )
												end
												--goto end_for_loop
												file_size_bigger = 1
											end

											local file_size_smaller = 0
											if content_type_list[i][16] ~= "" and #output_minified < content_type_list[i][16] then
												if content_type_list[i][5] == 1 then
													localized.ngx_log(localized.ngx_LOG_TYPE, " File size smaller than minimum allowed not going to cache " .. #output_minified .. " and " .. content_type_list[i][16] )
												end
												--goto end_for_loop
												file_size_smaller = 1
											end

											if file_size_bigger == 0 and file_size_smaller == 0 then

												if content_type_list[i][14] ~= "" and #content_type_list[i][14] > 0 then
													for x=1,#content_type_list[i][14] do
														output_minified = localized.string_gsub(output_minified, content_type_list[i][14][x][1], content_type_list[i][14][x][2])
													end --end foreach regex check
												end

												if res.header ~= nil and localized.type(res.header) == "table" then
													for headerName, header in localized.next, res.header do
														--localized.ngx_log(localized.ngx_LOG_TYPE, " header name" .. headerName .. " value " .. header )
														localized.ngx_header[headerName] = header
													end
												end
												--if content_type_list[i][11] == 1 and guest_or_logged_in == 0 then
													--localized.ngx_header["Set-Cookie"] = nil
												--end
												localized.ngx_header["Content-Length"] = #output_minified
												--localized.ngx_status = res.status
												localized.ngx_status = response_status_match(res.status)
												localized.ngx_say(output_minified)
												localized.ngx_exit(response_status_match(content_type_list[i][6][z]))
												--localized.ngx_exit(content_type_list[i][6][z])
												break
											end --file size bigger and smaller
										end
									end
								end
							end --end if res
						end
					end

					--break --break out loop

				end --end shared mem zone
			end --if request_method_match == 1 and cookie_match == 0 and request_uri_match == 0 then
		end --end if URL match check
		--::end_for_loop::

		if i >= #content_type_list then --last occurance
			--localized.ngx_log(localized.ngx_LOG_TYPE,  "count is " .. i .. " " .. localized.get_resp_content_type_counter .. " resp_content_type before " .. get_resp_content_type() .. " and " .. localized.ngx_header["Content-Type"]  )
			if localized.content_type_fix then
				get_resp_content_type(1) --fix for random bug where content-type output is application/octet-stream on text/html seems to only happen on a / directory not a /index.html
			end
			--localized.ngx_log(localized.ngx_LOG_TYPE,  localized.get_resp_content_type_counter .. " resp_content_type after " .. get_resp_content_type() )
		end

	end --end content_type foreach mime type table check
end --end minification function

minification(localized.content_cache)
end
