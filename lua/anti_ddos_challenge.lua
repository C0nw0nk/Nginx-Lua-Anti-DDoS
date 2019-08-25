
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
I am not responsible for what you do with this script nor liable,
This script was released under default Copyright Law as a proof of concept.
For those who want to know what that means for your use of this script read the following : http://choosealicense.com/no-license/

Legal Usage :
For those who wish to use this in production you should contact me to purchase a private license to use this legally.
For those who wish to use this in a commerical enviorment contact me to come to an agreement and purchase a commerical usage license.
For those who wish to purchase the rights to this from me contact me also to discuss pricing and terms and come to a sensible agreement.

Contact : (You can also contact me via github)
https://www.facebook.com/C0nw0nk

]]


--[[
Configuration :
]]
local AntiDDoSAuth = AntiDDoSAuth or {} --Define our local Table to easly change the name at anytime to prevent collisions with other scripts or global Lua variables on the server.

--[[
Shared memory cache
]]
--AntiDDoSAuth.shared_memory = ngx.shared.antiddos_auth_memory_space --What ever memory space your server has set / defined for this to use

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
]]
local remote_addr = ngx.var.remote_addr --Users IP address

local currenttime = ngx.time() --Current time on server

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
local javascript_REQUEST_TYPE = 3 --Default 3

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
if(!/bot|curl|kodi|xbmc|wget|urllib|python|winhttp|httrack|alexa|ia_archiver|facebook|twitter|linkedin|pingdom|google|baidu|bing|msn|duckduckgo|teoma|slurp|yahoo|yandex/i.test(navigator.userAgent)){
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
local JavascriptPuzzleVars = [[]] .. os.date("%Y%m%d",os.time()-24*60*60) .. [[ + ]] .. os.date("%d%m%Y",os.time()-24*60*60) ..[[]] --Javascript output of our two random numbers
local JavascriptPuzzleVars_answer = os.date("%Y%m%d",os.time()-24*60*60) + os.date("%d%m%Y",os.time()-24*60*60) --lua output of our two random numbers
local JavascriptPuzzleVars_answer = math.floor(JavascriptPuzzleVars_answer+0.5) --fix bug removing the 0. decimal on the end of the figure
local JavascriptPuzzleVars_answer = tostring(JavascriptPuzzleVars_answer) --convert the numeric output to a string
--ngx.log(ngx.ERR, "expected answer"..JavascriptPuzzleVars_answer) --output the answer to the log

--[[
Cookie Anti-DDos names
]]
local challenge = "__uip" --this is the first main unique identification of our cookie name
local cookie_name_start_date = challenge.."_start_date" --our cookie start date name of our firewall
local cookie_name_end_date = challenge.."_end_date" --our cookie end date name of our firewall
local cookie_name_encrypted_start_and_end_date = challenge.."_combination" --our cookie challenge unique id name

--[[
TODO:
Encrypt/Obfuscate Javascript output to prevent content scrappers and bots decrypting it to try and bypass the browser auth checks. Wouldn't want to make life to easy for them now would I.
]]

--[[
TODO:
Google ReCaptcha
]]

--[[
End Configuration


Users with little understanding don't edit beyond this point you will break the script most likely. (You should not need to be warned but now you have been told.) Proceed at own Risk!

Please do not touch anything below here unless you understand the code you read and know the consiquences.

This is where things get very complex. ;)

]]


--[[
Begin Required Functions
]]

--function to encrypt strings with our secret key / password provided
local function calculate_signature(str)
	return ngx.encode_base64(ngx.hmac_sha1(secret, ngx.md5(str)))
	:gsub("[+/=]", {["+"] = "-", ["/"] = "_", ["="] = ""}) --Replace + with - and replace / with _ and remove =
end
--calculate_signature(str)

--generate random strings on the fly
--qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890
local charset = {}
for i = 48,  57 do table.insert(charset, string.char(i)) end --0-9 numeric
--for i = 65,  90 do table.insert(charset, string.char(i)) end --A-Z uppercase
--for i = 97, 122 do table.insert(charset, string.char(i)) end --a-z lowercase
table.insert(charset, string.char(95)) --insert number 95 underscore
local function stringrandom(length)
	--math.randomseed(os.time())
	if length > 0 then
		--return "a"
		return stringrandom(length - 1) .. charset[math.random(1, #charset)]
	else
		return ""
	end
end
--stringrandom(10)

local scheme = ngx.var.scheme --scheme is HTTP or HTTPS
local host = ngx.var.host --host is website domain name
local request_uri = ngx.var.request_uri --request uri is full URL link including query strings and arguements
local URL = scheme .. "://" .. host .. request_uri
local user_agent = ngx.var.http_user_agent --user agent of browser

local expected_header_status = 200 --503
local authentication_page_status_output = 200

local domain = ""
if host == nil then
	domain = host:match("[%w%.]*%.(%w+%.%w+)") --Remove subdomains from the server_name (host) to output .domain.com
else
	domain = "localhost"
end

local answer = calculate_signature(remote_addr) --create our encrypted unique identification for the user visiting the website.

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
	--our end date cookie
	local cookie_name_end_date_name = "cookie_" .. cookie_name_end_date
	local cookie_name_end_date_value = ngx.var[cookie_name_end_date_name] or ""
	--our start date and end date combined to a unique id
	local cookie_name_encrypted_start_and_end_date_name = "cookie_" .. cookie_name_encrypted_start_and_end_date
	local cookie_name_encrypted_start_and_end_date_value = ngx.var[cookie_name_encrypted_start_and_end_date_name] or ""

	--ngx.log(ngx.ERR, "cookie name " .. cookie_name .. " | cookie value is "..cookie_value)

	if cookie_value ~= answer then --if cookie value not equal to or matching our expected cookie they should be giving us
		return --return to refresh the page so it tries again
	end

	--if x-auth-answer is correct to the user unique id time stamps etc meaning browser figured it out then set a new cookie that grants access without needed these checks
	local req_headers = ngx.req.get_headers() --get all request headers
	if req_headers["x-requested-with"] == "XMLHttpRequest" then --if request header matches request type of XMLHttpRequest
		--ngx.log(ngx.ERR, "x-auth-answer result | "..req_headers["x-auth-answer"]) --output x-auth-answer to log
		if req_headers["x-auth-answer"] == JavascriptPuzzleVars_answer then --if the answer header provided by the browser Javascript matches what our Javascript puzzle answer should be
			ngx.header["Set-Cookie"] = { --set our cookies granting the user temporary access to the website
				challenge.."="..cookie_value.."; path=/; domain=." .. domain .. "; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";", --apply our uid cookie incase javascript setting this cookies time stamp correctly has issues
				cookie_name_start_date.."="..ngx.cookie_time(currenttime).."; path=/; domain=." .. domain .. "; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";", --start date cookie
				cookie_name_end_date.."="..ngx.cookie_time(currenttime+expire_time).."; path=/; domain=." .. domain .. "; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";", --end date cookie
				cookie_name_encrypted_start_and_end_date.."="..calculate_signature(remote_addr .. ngx.cookie_time(currenttime) .. ngx.cookie_time(currenttime+expire_time) ).."; path=/; domain=." .. domain .. "; expires=" .. ngx.cookie_time(currenttime+expire_time) .. "; Max-Age=" .. expire_time .. ";", --start and end date combined to unique id
			}
		end
	end

	--ngx.log(ngx.ERR, "cookie start date | "..cookie_name_start_date_value) --log user provided cookie start date
	--ngx.log(ngx.ERR, "cookie end date | "..cookie_name_end_date_value) --log user provided cookie end date
	--ngx.log(ngx.ERR, "cookie encrypted combination value | "..cookie_name_encrypted_start_and_end_date_value) --log user provided cookie combined encrypted value

	if cookie_name_start_date_value ~= nil and cookie_name_end_date_value ~= nil and cookie_name_encrypted_start_and_end_date_value ~= nil then --if all our cookies exist
		local cookie_name_end_date_value_unix = ngx.parse_http_time(cookie_name_end_date_value) or nil --convert our cookie end date provided by the user into a unix time stamp
		if cookie_name_end_date_value_unix == nil or cookie_name_end_date_value_unix == "" then --if our cookie end date date in unix does not exist
			return --return to refresh the page so it tries again
		end
		if cookie_name_end_date_value_unix <= currenttime then --if our cookie end date is less than or equal to the current date meaning the users authentication time expired
			--ngx.log(ngx.ERR, "cookie less than current time : " .. cookie_name_end_date_value_unix .. " | " .. currenttime ) --log output the users provided cookie time
			return --return to refresh the page so it tries again
		end
		if cookie_name_encrypted_start_and_end_date_value ~= calculate_signature(remote_addr .. cookie_name_start_date_value .. cookie_name_end_date_value) then --if users authentication encrypted cookie not equal to or matching our expected cookie they should be giving us
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

local title = host .. [[ | Anti-DDoS Flood Protection and Firewall by Conor McKnight]]

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

local JavascriptPuzzleVariable_name = "_" .. stringrandom(10)

local javascript_REQUEST_headers = [[
xhttp.setRequestHeader('X-Auth-Answer', ]] .. JavascriptPuzzleVariable_name .. [[); //make the answer what ever the browser figures it out to be
			xhttp.setRequestHeader('X-Requested-with', 'XMLHttpRequest');
]]

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
			document.cookie = ']] .. challenge .. [[=]] .. answer .. [[' + '; expires=' + ']] .. ngx.cookie_time(currenttime+expire_time) .. [[' + '; domain=.]] .. domain .. [[; path=/';
			//javascript puzzle for browser to figure out to get answer
			]] .. JavascriptVars_opening .. [[
			]] .. JavascriptPuzzleVariable .. [[
			]] .. JavascriptVars_closing .. [[
			//end javascript puzzle
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function() {
				if (this.readyState == 4 && this.status == ]] .. expected_header_status .. [[) { //status may be 503 so local var to control both response and switch between POST and GET
					window.location.reload();
					/*document.getElementById("status").innerHTML =*/
					/*this.responseText;*/ //body response
					/*xhttp.getAllResponseHeaders();*/
					var response_header1 = xhttp.getResponseHeader('x-response-answer'); //expected response header if post/get request passed
					var response_header2 = xhttp.getResponseHeader('set-cookie'); //expected response header if post/get request passed
					if (response_header1 && response_header2) {
						/*window.location.reload();*/
						document.getElementById("status").innerHTML = "Refresh your page."; //incase they block or don't allow javascript to refresh.
					} else {
						/*window.location.reload();*/ //this one works for some reason
						document.getElementById("status").innerHTML = "Your request failed." + response_header2
					}
				} else {
					/*document.getElementById("status").innerHTML = "Your request failed."*/
					window.location.reload();
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
--TODO: include lua to encrypt/obfuscate javascript
--[[
include javascript_library.lua --required library to encrypt/obfuscate the output
javascript_anti_ddos = encrypt_javascript(javascript_anti_ddos) --encrypt/obfuscate the javascript output
]]

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
<meta charset="UTF-8" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge,chrome=1" />
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
<meta name="robots" content="noindex, nofollow" />
<title>]] .. title .. [[</title>
<style type="text/css">
]] .. style_sheet .. [[
</style>
]] .. head_ad_slot .. [[
<script type="text/javascript">
]] .. javascript_anti_ddos .. [[
</script>
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
ngx.header["X-Content-Type-Options"] = "nosniff"
ngx.header["X-Frame-Options"] = "SAMEORIGIN"
ngx.header["X-XSS-Protection"] = "1; mode=block"
ngx.header["Cache-Control"] = "public, max-age=0 no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
ngx.header["Pragma"] = "no-cache"
ngx.header["Expires"] = "0"
ngx.header["X-Anti-DDoS"] = "Conor McKnight | facebook.com/C0nw0nk"
ngx.header.content_type = "text/html; charset=UTF-8"
ngx.status = expected_header_status
ngx.say(anti_ddos_html_output)
ngx.exit(ngx.HTTP_OK)
