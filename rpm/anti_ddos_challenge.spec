############################################################
# Version Macros (set via build parameters or defaults)
############################################################
%{!?script_ver:   %global script_ver   1.0}
%{!?release_tag:  %global release_tag  1}

############################################################
# Package Information
############################################################
Name:           nginx-lua-anti-ddos-challenge
Version:        %{script_ver}
Release:        %{release_tag}
Summary:        Nginx Lua Anti-DDoS script

License:        MIT
URL:            https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS
Source0:        anti_ddos_challenge.lua
SOURCE1:        LICENSE
Source2:        README.md

BuildArch:      noarch

# Dont explicit require due to compatiblity
#Requires:       lua luajit2 lua-socket
#Requires:       lua-resty-core >= 0.1.28

%description
This package provides `anti_ddos_challenge.lua`, a Lua script designed to protect Nginx web servers from DDoS attacks by implementing an authentication puzzle mechanism.

**Dependencies and Requirements:**

- Nginx must be compiled with the Lua module enabled.
- The Lua environment should include:
  - lua
  - luajit2
  - lua-socket
  - lua-resty-core (version 0.1.28 or higher)

These dependencies are critical as the script relies on them for proper functionality within the Nginx Lua module context.

Make sure to install and configure these prerequisites before deploying this script to ensure its effectiveness and compatibility.

%prep
# No preparation needed

%build
# No build needed

%install
rm -rf %{buildroot}
install -D -m 0644 %{SOURCE0} %{buildroot}/etc/nginx/anti_ddos_challenge.lua
install -D -m 0644 %{SOURCE1} %{buildroot}/usr/share/licenses/%{name}/LICENSE
install -D -m 0644 %{SOURCE2} %{buildroot}/usr/share/doc/%{name}/README.md

%files
%license LICENSE
%doc README.md
%config(noreplace) /etc/nginx/anti_ddos_challenge.lua

%post
if [ -f /etc/nginx/anti_ddos_challenge.lua.rpmnew ]; then
  echo "Warning: /etc/nginx/anti_ddos_challenge.lua already exists and differs from the packaged version."
  echo "A new version of the file has been installed as /etc/nginx/anti_ddos_challenge.lua.rpmnew."
  echo "Please review and merge changes if appropriate."
fi

# Auto added - DONT REMOVE
%changelog
* Tue Sep 09 2025 C0nw0nk <C0nw0nk@github> - 1.7-1
- Added Security feature to prevent spoofing on the Proxy headers CF-Connecting-IP or X-forwarded-for.
- For example a smart DDoS attack will send a fake CF-Connecting-IP header or X-Forwarded-For header in their request
- They do this to see if your server will use their real ip or the fake header they provide to you most servers do not even check this I do :)
- Example : `curl.exe "http://localhost/" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Accept-Language: en-GB,en;q=0.5" -H "Accept-Encoding: gzip, deflate, br, zstd" -H "DNT: 1" -H "Connection: keep-alive" -H "Cookie: name1=1; name2=2; logged_in=1" -H "Upgrade-Insecure-Requests: 1" -H "Sec-Fetch-Dest: document" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: none" -H "Sec-Fetch-User: ?1" -H "Priority: u=0, i" -H "Pragma: no-cache" -H "Cache-Control: no-cache" -H "User-Agent:testagent1" -H "CF-Connecting-IP: 1" -H "X-Forwarded-For: 1" `
- Improvements for Tor / Onion network users script should now detect Tor automatically no need to change any settings.
- Improve Page Caching cookie matching
- Internal request header tracking encrypted so only the nginx process can use these headers
- localize and and re-order some vars and functions for better performance and execution ordering
* Sun Sep 07 2025 C0nw0nk <C0nw0nk@github> - 1.6-1
- Added Feature localized.ip_whitelist_bypass_flood_protection = 0 --0 IP's in whitelist can still be banned / blocked for DDoS flooding behaviour 1 IP's bypass the flood detection
- Fixed Rate limit being double
- Tidy IP checks by using a function
- Increase default minimum request size from 20 bytes to 40 bytes
- Improve the default User-Agent block string for empty user-agent to pick up spaces as empty also
- Better setting for shared memory zones
- Add crawler IP's google bing to whitelist example
- Fix for cloudflare and proxys solving javascript puzzle make sure they don't override the 503 status and send their own custom error page.
* Sun Sep 07 2025 C0nw0nk <C0nw0nk@github> - 1.6-1
- Added Feature localized.ip_whitelist_bypass_flood_protection = 0 --0 IP's in whitelist can still be banned / blocked for DDoS flooding behaviour 1 IP's bypass the flood detection
- Fixed Rate limit being double
- Tidy IP checks by using a function
- Increase default minimum request size from 20 bytes to 40 bytes
- Improve the default User-Agent block string for empty user-agent to pick up spaces as empty also
- Better setting for shared memory zones
- Add crawler IP's google bing to whitelist example
- Fix for cloudflare and proxys solving javascript puzzle make sure they don't override the 503 status and send their own custom error page.
* Fri Sep 05 2025 C0nw0nk <C0nw0nk@github> - 1.5-1
- Fixed log to show IP address.
- IPs in the block range to get added to shared memory zone if exist
- IPs in whitelist range to get added to shared memory zone if exist
- Added Feature javascript authentication puzzle protection users who fail to solve the javascript puzzle more than a certain number of times can be blocked.
- Added feature ability to run external commands on IP addresses in the block list useful if you want to use iptables to block an address before it even reaches the nginx worker process.
* Fri Sep 05 2025 C0nw0nk <C0nw0nk@github> - 1.5-1
- Fixed log to show IP address.
- IPs in the block range to get added to shared memory zone if exist
- IPs in whitelist range to get added to shared memory zone if exist
- Added Feature javascript authentication puzzle protection users who fail to solve the javascript puzzle more than a certain number of times can be blocked.
- Added feature ability to run external commands on IP addresses in the block list useful if you want to use iptables to block an address before it even reaches the nginx worker process.
* Wed Sep 03 2025 C0nw0nk <C0nw0nk@github> - 1.4-1
- localize next functions
- Add ability to override ngx.location.capture headers being sent to backends.
* Wed Sep 03 2025 C0nw0nk <C0nw0nk@github> - 1.4-1
- localize next functions
- Add ability to override ngx.location.capture headers being sent to backends.
* Wed Sep 03 2025 C0nw0nk <C0nw0nk@github> - 1.3-1
- localize vars so the script is compatible with all nginx lua versions old and new.
- Fix content-type header depending on how early in execution process we are with nginx the content-type header could still be nil so i have fixed it.
* Wed Sep 03 2025 C0nw0nk <C0nw0nk@github> - 1.3-1
- localize vars so the script is compatible with all nginx lua versions old and new.
- Fix content-type header depending on how early in execution process we are with nginx the content-type header could still be nil so i have fixed it.
* Sat Aug 23 2025 C0nw0nk <C0nw0nk@github> - 1.2-1
- Fixed both guest and logged in user cache
- Fixed POST request caching
- Change default value to false in-case other scripts are present on the Nginx server to be executed after this script.
- Improved content cache key so it works with other request types like POST etc
* Sat Aug 23 2025 C0nw0nk <C0nw0nk@github> - 1.2-1
- Fixed both guest and logged in user cache
- Fixed POST request caching
- Change default value to false in-case other scripts are present on the Nginx server to be executed after this script.
- Improved content cache key so it works with other request types like POST etc
* Wed Aug 20 2025 C0nw0nk <C0nw0nk@github> - 1.1-1
- Added Feature Content-Type Caching using ngx.location.capture
- This is the same as `proxy_cache` or `fastcgi_cache` in nginx just more features and better.
- Added Feature HTML modification / Modify you can capture and modify pages outputs with this includding adding javascript to pages etc.
- Added Feature option for users who have other scripts on their nginx server to be able to run those after this. `ngx_exit` trigger.
- Fixed the shdict check i left it as a string `tostring` and a true or false check was not working properly.
* Sat Aug 09 2025 C0nw0nk <C0nw0nk@github> - 1.0-1
- Initial packaging (RPM and DEB) for anti_ddos_challenge.lua created and maintained by C0nw0nk (https://github.com/C0nw0nk)
* Sat Aug 09 2025 C0nw0nk <C0nw0nk@github> - 1.0-1
- Initial packaging (RPM and DEB) for anti_ddos_challenge.lua created and maintained by C0nw0nk (https://github.com/C0nw0nk)
* Sat Aug 09 2025 C0nw0nk <C0nw0nk@github> - 1.0-1
- Initial packaging (RPM and DEB) for anti_ddos_challenge.lua created and maintained by C0nw0nk (https://github.com/C0nw0nk)
