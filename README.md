# Nginx-Lua-Anti-DDoS
A Anti-DDoS script to protect Nginx web servers using Lua with a Javascript based authentication puzzle inspired by Cloudflare I am under attack mode I built my own Anti-DDoS authentication HTML page puzzle intergrating my Lua, Javascript, HTML and HTTP knowledge.

Mitigate a DDoS attack of any size using DDoS my free protection. Don't get ddos attacked!

If you're under attack and use my script during the attack, visitors will receive an interstitial page for about five seconds while I analyze the traffic to make sure it is a legitimate human visitor.

This can protect you from many different forms of DDoS works with both HTTP and HTTPS / SSL traffic.

No limit on attack size
Uptime guarantee


# Information :

If you have any bugs issues or problems just post a Issue request.

https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/issues

If you fork or make any changes to improve this or fix problems please do make a pull request for the community who also use this. 

https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/pulls

# Usage :

Edit settings inside `anti_ddos_challenge.lua` to cater for your own unique needs or improve my work. (Please share your soloutions and additions)

https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/blob/master/lua/anti_ddos_challenge.lua#L48

Add this to your Nginx configuration folder.

`nginx/conf/lua/`

Once installed into your `nginx/conf/` folder.

Add this to your HTTP block or it can be in a server or location block depending where you want this script to run for individual locations the entire server or every single website on the server.

```
access_by_lua_file anti_ddos_challenge.lua;
```

### Example nginx.conf :

This will run for all websites on the nginx server

```
http {
#nginx config settings etc
access_by_lua_file anti_ddos_challenge.lua;
#more config settings and some server stuff
}
```

This will make it run for this website only

```
server {
#nginx config settings etc
access_by_lua_file anti_ddos_challenge.lua;
#more config settings and some server stuff
}
```

This will run in this location block only

```
location / {
#nginx config settings etc
access_by_lua_file anti_ddos_challenge.lua;
#more config settings and some server stuff
}
```

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
And many more...
```
