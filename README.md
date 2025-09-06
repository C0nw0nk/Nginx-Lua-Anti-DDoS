[![Languages](https://img.shields.io/github/languages/count/C0nw0nk/Nginx-Lua-Anti-DDoS) ![Top language](https://img.shields.io/github/languages/top/C0nw0nk/Nginx-Lua-Anti-DDoS) ![File size](https://img.shields.io/github/size/C0nw0nk/Nginx-Lua-Anti-DDoS/lua/anti_ddos_challenge.lua)](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/wiki/funding) [![Build and Publish RPM/DEB Packages](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/actions/workflows/build-publish.yml/badge.svg)](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/actions/workflows/build-publish.yml)

[![Cloudflare I am Under Attack Mode!](https://blog.cloudflare.com/content/images/im_under_attack_page.png.scaled500.png)](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/wiki/funding)

[Master Branch for Modern Nginx Lua Builds](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/tree/master) - [Old Outdated Nginx Lua Builds use this branch](https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/tree/old-outdated-nginx-lua-builds)

# Nginx-Lua-Anti-DDoS
A Anti-DDoS script to protect Nginx web servers using Lua with a Javascript based authentication puzzle inspired by Cloudflare I am under attack mode I built my own Anti-DDoS authentication HTML page puzzle intergrating my Lua, Javascript, HTML and HTTP knowledge.

Mitigate a DDoS attack of any size using my free DDoS protection. Don't get ddos attacked!

If you're under attack and use my script during the attack, visitors will receive an interstitial page for about five seconds while I analyze the traffic to make sure it is a legitimate human visitor.

This can protect you from many different forms of DDoS works with both HTTP and HTTPS / SSL traffic.

No limit on attack size
Uptime guarantee

# Features :

These are some of the features I built into the script so far.

## Security

Limit IP requests / Flooding

Automatically turn on Under Attack mode if DDoS detected

I am Under Attack Mode (DDoS Authentication HTML Page)

IP Address Whitelist

IP Subnet Ranges Whitelist

IP Address Blacklist

IP Subnet Ranges Blacklist

User-Agent Whitelist

User-Agent Blacklist

Protected area / Restricted access field username / password box to restrict access to sites / paths.

Enable or disable logging of users who either fail or succeed solving the authentication puzzle. (Fail2Ban users can use this to ban bots AI tools and IP addresses from the log file)

Range header filtering Most download / Video streaming sites and services use range headers this allows you to filter and block slowhttp / slowloris attack types

## WAF (Web Application Firewall)

IPv4 and IPv6 blocking and whitelisting including subnet ranges.

User-Agent blocking and whitelisting to block bad bots and exploits / scanners.

Ability to inspect POST Data / Fields and block malicious POST requests / exploits.

Ability to inspect URL for malicious content SQL/SQI Injections XSS attacks / exploits.

Ability to inspect query strings and arguements for malicious content / exploits.

Ability to inspect all Request Headers provided by the client connecting.

Ability to inspect cookies for exploits.

## Caching Speed and Performance

Query String Sorting

Query String Whitelist

Query String Removal (It is a blacklist but it will just drop / remove the argument from the URL not block the request)

Minification / Compression of files removing white space and nulled out code / lines JS JavaScript, CSS Stylesheets, HTML etc

## Customization of error pages responses and webpage outputs

Custom error page interception to replace with your own error pages

Hide Web application errors such as PHP errorrs MySQL errors it will intercept them and display a custom error page instead of showing visitors sensative information

Modify webpage outputs to replace contents on pages / files

# Information :

If you have any bugs issues or problems just post a Issue request.

https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/issues

If you fork or make any changes to improve this or fix problems please do make a pull request for the community who also use this. 

https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/pulls

## Be sure to use the latest Nginx+Lua builds and libraries to avoid any issues.

# Usage / Installation :

Edit settings inside `anti_ddos_challenge.lua` to cater for your own unique needs or improve my work. (Please share your soloutions and additions)

https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/blob/master/lua/anti_ddos_challenge.lua

Add this to your Nginx configuration folder.

`nginx/conf/lua/`

Once installed into your `nginx/conf/` folder.

Add this to your HTTP block or it can be in a server or location block depending where you want this script to run for individual locations the entire server or every single website on the server.

```
lua_shared_dict antiddos 70m; #Anti-DDoS shared memory zone to track requests per each unique user
lua_shared_dict antiddos_blocked 70m; #Anti-DDoS shared memory where blocked users are put
lua_shared_dict ddos_counter 10m; #Anti-DDoS shared memory zone to track total number of blocked users
lua_shared_dict jspuzzle_tracker 70m; #Anti-DDoS shared memory zone monitors each unique ip and number of times they stack up failing to solve the puzzle

access_by_lua_file anti_ddos_challenge.lua;
```

### Example nginx.conf :

This will run for all websites on the nginx server

```
http {

#shared memory addresses in http block
lua_shared_dict antiddos 70m; #Anti-DDoS shared memory zone to track requests per each unique user
lua_shared_dict antiddos_blocked 70m; #Anti-DDoS shared memory where blocked users are put
lua_shared_dict ddos_counter 10m; #Anti-DDoS shared memory zone to track total number of blocked users
lua_shared_dict jspuzzle_tracker 70m; #Anti-DDoS shared memory zone monitors each unique ip and number of times they stack up failing to solve the puzzle

#nginx config settings etc
access_by_lua_file anti_ddos_challenge.lua;
#more config settings and some server stuff

}
```

This will make it run for this website only

```
http {
#shared memory addresses in http block
lua_shared_dict antiddos 70m; #Anti-DDoS shared memory zone to track requests per each unique user
lua_shared_dict antiddos_blocked 70m; #Anti-DDoS shared memory where blocked users are put
lua_shared_dict ddos_counter 10m; #Anti-DDoS shared memory zone to track total number of blocked users
lua_shared_dict jspuzzle_tracker 70m; #Anti-DDoS shared memory zone monitors each unique ip and number of times they stack up failing to solve the puzzle
}

server {
#nginx config settings etc
access_by_lua_file anti_ddos_challenge.lua;
#more config settings and some server stuff
}
```

This will run in this location block only

```
http {
#shared memory addresses in http block
lua_shared_dict antiddos 70m; #Anti-DDoS shared memory zone to track requests per each unique user
lua_shared_dict antiddos_blocked 70m; #Anti-DDoS shared memory where blocked users are put
lua_shared_dict ddos_counter 10m; #Anti-DDoS shared memory zone to track total number of blocked users
lua_shared_dict jspuzzle_tracker 70m; #Anti-DDoS shared memory zone monitors each unique ip and number of times they stack up failing to solve the puzzle
}

location / {
#nginx config settings etc
access_by_lua_file anti_ddos_challenge.lua;
#more config settings and some server stuff
}
```

### Other setup options

https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/wiki

For setting up the script to run with Tor .onion services, Cloudflares proxy services, Configuration options of the script view the wiki.

# Requirements :
NONE! :D You only need Nginx + Lua to use my scripts.

###### Where can you download Nginx + Lua ?

Openresty provide Nginx + Lua builds for Windows Linux etc here.

https://openresty.org/en/download.html

Nginx4windows has Windows specific builds with Lua here.

http://nginx-win.ecsds.eu/

Or you can download the source code for Nginx here and compile Nginx yourself with Lua.

https://nginx.org/en/download.html

# About :

I was inspired to create this because of Cloudflare feature "I'm Under Attack Mode" https://www.cloudflare.com/

There are similar sites and services like BitMitigate but I prefer my own script over their methods.

```
If you're under attack and have this feature enabled during the attack, visitors will receive an interstitial page for about five seconds while we analyze the traffic to make sure it is a legitimate human visitor.

Advanced DDoS Attack Protection

Unmetered DDoS mitigation to maintain performance and availability

Denial of Service attacks continue to grow in sophistication and force: more distributed, greater volumes of traffic, and encroaching on the application layer.

A successful attack increases unnecessary costs on your infrastructure and IT/security staff. More importantly, it hurts your revenue, customer satisfaction, and brand.

To combat attacks and stay online, you’ll need a solution that’s resilient scalable, and intelligent.

Mitigate a DDoS attack of any size or duration, Don't get ddos attacked!
```

I love that feature so much ontop of having it enabled on all my Cloudflare proxied sites I decided to make it into a feature on my own servers so the traffic that hits my servers without coming from Cloudflares network is kept in check and authenticated! (Every little helps right!)

Thank you to @Cloudflare for the inspiration and your community for all the love, A big thanks to the @openresty community you guys rock Lua rocks you are all so awesome!

Lets build a better internet together! Where Speed, Privacy, Security and Compression matter!

Here are links to my favorite communities :)

http://openresty.org/en/

https://community.cloudflare.com/

# Protected attack types :
```
All Layer 7 Attacks
Mitigating Historic Attacks
DoS
DoS Implications
DDoS
All Brute Force Attacks
Zero day exploits
Social Engineering
Rainbow Tables
Password Cracking Tools
Password Lists
Dictionary Attacks
Time Delay
Any Hosting Provider
Any CMS or Custom Website
Unlimited Attempt Frequency
Search Attacks
HTTP Basic Authentication
HTTP Digest Authentication
HTML Form Based Authentication
Mask Attacks
Rule-Based Search Attacks
Combinator Attacks
Botnet Attacks
Unauthorized IPs
IP Whitelisting
Bruter
THC Hydra
John the Ripper
Brutus
Ophcrack
unauthorized logins
Injection
Broken Authentication and Session Management
Sensitive Data Exposure
XML External Entities (XXE)
Broken Access Control
Security Misconfiguration
Cross-Site Scripting (XSS)
Insecure Deserialization
Using Components with Known Vulnerabilities
Insufficient Logging & Monitoring
And many others…
```
# Features :

# Advanced DDoS Attack Protection
My script gives you Unmetered DDoS mitigation to maintain performance and availability for free
Denial of Service attacks continue to grow in sophistication and force: more distributed, greater volumes of traffic, and encroaching on the application layer.
A successful attack increases unnecessary costs on your infrastructure and IT/security staff. More importantly, it hurts your revenue, customer satisfaction, and brand.
To combat attacks and stay online, you’ll need a solution that’s resilient scalable, and intelligent.

#### Common Types of DDoS Attacks

# Block Malicious Bot Abuse
Block abusive bots from damaging Internet properties through content scraping, fraudulent checkout, and account takeover.

# Prevent Customer Data Breach
Prevent attackers from compromising sensitive customer data, such as user credentials, credit card information, and other personally identifiable information.

#### Layered Security Defense
layered security approach combines multiple DDoS mitigation capabilities into one service. It prevents disruptions caused by bad traffic, while allowing good traffic through, keeping websites, applications and APIs highly available and performant.
#### HTTP Flood (Layer 7)
HTTP flood attacks generate high volumes of HTTP, GET, or POST requests from multiple sources, targeting the application layer, causing service degradation or unavailability.

Defend against the largest attacks

# Shared Network Intelligence / Collective Intelligence
With every new property, contributor and person using this script your help and contributions to this script makes everyones network safer. You are helping identify and block new and evolving threats across the entire internet back bone / infrastructure.

# No Performance Tradeoffs
Eliminate security induced latencies by integrating my script with your servers. You do not need to rely on third party services like Cloudflare, BitMitigate, Sucuri or other such CDN Cloud distributed networks or companies anymore I have given you the tool for free.

# Web Application Firewall
enterprise-class web application firewall (WAF) protects your Internet property from common vulnerabilities like SQL injection attacks, cross-site scripting, and cross-site forgery requests and protectects your existing infrastructure.

# Rate Limiting

Control to block suspicious visitors

Rate Limiting protects against denial-of-service attacks, brute-force login attempts, and other types of abusive behavior targeting the application layer.

Rate Limiting provides the ability to configure thresholds, define responses, and gain valuable insights into specific URLs of websites, applications, or API endpoints. It adds granular HTTP/HTTPS traffic control. This also reduces bandwidth costs by eliminating unpredictable traffic spikes or attacks.

# Protect any Web Application
This script can protect every web application ever built.
```
Drupal
WordPress
Joomla
Flash
Magento
PHP
Plone
WHMCS
Atlassian Products
Adult video script avs
KVS Kernel Video Sharing
Clip Bucket
Tube sites
Content Management Systems
Social networks
scripts
backends proxy proxies
PHP
Python
Porn sites xxx adult
gaming networks servers sites
forums
vbulletin
phpbb
mybb
smf simple machines forum
xenforo
web hosting
And many more...
```

# Government
Protection for government gateways and websites. With foriegn agencies targeting critical infastructure this will help all government and critical civilian infastructure stay online.

# Payment e-comerce content management
If you use Joomla, Drupal, Wordpress, phpbb, mybb, vbulletin popular cms or forum software this will ensure maximum uptime and protection.

# Military MoD
Military grade protection for infastructure. MoD military of defence / Armed forces websites. Protecting Police and Army core or law enforcement.

# Crypto Currency
This script works well for crypto currency sites due to the nature of wallet controls security and access of crypto based websites it verifys traffic can run javascript and is legitimate before allowing them access protecting sensitive content like wallet access every crypto website that has a swap or dex / cex centralised or decentralised exchange will find this a must have requiremnet for their peer-to-peer marketplace where transactions occur directly between crypto traders.

# Tor network / Project .onion :
You can also use this script to protect servers and sites on the Tor network preventing ddos on .onion links. It can help stop attacks on the deepweb / darkweb aswell as on the mainline internet for those who browse your site through the tor browser it makes sure they are legitimate users.

# HTTP(S) / HTTP2 / HTTP3 / QUIC :
So with modern internet protocols yes this script does work with all of them! It can protect both encrypted and unencrypted connections and traffic served over TCP aswell as UDP the new method for HTTP3/QUIC connections.

# Works with :
Nginx

Nginx + Lua

Openresty

Custom Nginx builds with Lua compiled

Litespeed / Litespeedtech as can be seen here https://openlitespeed.org/kb/openlitespeed-lua-module/ the reason this works with Litespeed Lua is because they use Openresty Lua builds on their server as can be understood here https://openlitespeed.org/kb/openlitespeed-lua-module/#Use
