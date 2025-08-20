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
* Sat Aug 09 2025 C0nw0nk <C0nw0nk@github> - 1.0-1
- Initial packaging (RPM and DEB) for anti_ddos_challenge.lua created and maintained by C0nw0nk (https://github.com/C0nw0nk)
* Sat Aug 09 2025 C0nw0nk <C0nw0nk@github> - 1.0-1
- Initial packaging (RPM and DEB) for anti_ddos_challenge.lua created and maintained by C0nw0nk (https://github.com/C0nw0nk)
* Sat Aug 09 2025 C0nw0nk <C0nw0nk@github> - 1.0-1
- Initial packaging (RPM and DEB) for anti_ddos_challenge.lua created and maintained by C0nw0nk (https://github.com/C0nw0nk)
