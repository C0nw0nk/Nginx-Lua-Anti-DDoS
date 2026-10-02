
--[[
Introduction and details :
Script Version: 6.1

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
localized.package = package
localized.pcall = pcall
localized.require = require
localized.ngx = ngx
localized.ffi = localized.ffi or (localized.package.loaded.ffi or (localized.pcall(localized.require, "ffi") and localized.require("ffi")))
localized.bit_bxor = bit.bxor
localized.bit_lshift = bit.lshift
localized.bit_rshift = bit.rshift
localized.bit_band = bit.band
localized.math_floor = math.floor
if localized.prng_state==nil then localized.prng_state=localized.bit_band(localized.math_floor((localized.ngx and localized.ngx.now() or os.time())*1000000),0xFFFFFFFF) end math.randomseed=function(new_seed) if not new_seed then local counter=(localized.seed_counter or 0)+1 localized.seed_counter=counter local hash=localized.bit_band(localized.math_floor((localized.ngx and localized.ngx.now() or os.time())*1000000)+counter,0xFFFFFFFF) hash=localized.bit_bxor(hash,localized.bit_rshift(hash,16)) hash=localized.bit_band(hash*0x85ebca6b,0xFFFFFFFF) hash=localized.bit_bxor(hash,localized.bit_rshift(hash,13)) hash=localized.bit_band(hash*0xc2b2ae35,0xFFFFFFFF) new_seed=localized.bit_bxor(hash,localized.bit_rshift(hash,16)) end local final_seed=localized.bit_band(new_seed,0xFFFFFFFF) localized.prng_state=final_seed return final_seed end math.random=function(m,n) local state=localized.prng_state state=localized.bit_bxor(state,localized.bit_lshift(state,13)) state=localized.bit_bxor(state,localized.bit_rshift(state,17)) state=localized.bit_bxor(state,localized.bit_lshift(state,5)) state=localized.bit_band(state,0xFFFFFFFF) localized.prng_state=state if not m then return state/4294967296 elseif not n then return(state%m)+1 else return(state%(n-m+1))+m end end --override math.rnadomseed and math.random
localized.math_sin = math.sin
localized.math_pi = math.pi
localized.math_sqrt = math.sqrt
if localized.prng_state==nil then localized.prng_state=localized.bit_band(localized.math_floor((localized.ngx and localized.ngx.now() or os.time())*1000000),0xFFFFFFFF) end localized.math_randomseed=function(new_seed) if not new_seed then local counter=(localized.seed_counter or 0)+1 localized.seed_counter=counter local hash=localized.bit_band(localized.math_floor((localized.ngx and localized.ngx.now() or os.time())*1000000)+counter,0xFFFFFFFF) hash=localized.bit_bxor(hash,localized.bit_rshift(hash,16)) hash=localized.bit_band(hash*0x85ebca6b,0xFFFFFFFF) hash=localized.bit_bxor(hash,localized.bit_rshift(hash,13)) hash=localized.bit_band(hash*0xc2b2ae35,0xFFFFFFFF) new_seed=localized.bit_bxor(hash,localized.bit_rshift(hash,16)) end local final_seed=localized.bit_band(new_seed,0xFFFFFFFF) localized.prng_state=final_seed return final_seed end localized.math_random=function(m,n) local state=localized.prng_state state=localized.bit_bxor(state,localized.bit_lshift(state,13)) state=localized.bit_bxor(state,localized.bit_rshift(state,17)) state=localized.bit_bxor(state,localized.bit_lshift(state,5)) state=localized.bit_band(state,0xFFFFFFFF) localized.prng_state=state if not m then return state/4294967296 elseif not n then return(state%m)+1 else return(state%(n-m+1))+m end end --create localized.math_random() and localized.math_randomseed()
localized.table_sort = function(data, compare) if localized.table_s == nil then localized.table_s = table.sort end local in_reg = (function() return localized.tostring(data) end)()..(function() return localized.tostring(compare) end)() if localized.table_sort_run ~= nil and localized.table_sort_run[in_reg.."one"] ~= nil then return localized.table_sort_run[in_reg.."one"] end if localized.table_sort_run == nil then localized.table_sort_run = {} end localized.table_sort_run[in_reg.."one"] = {} localized.table_sort_run[in_reg.."one"] = localized.table_s(data, compare) return localized.table_sort_run[in_reg.."one"] end
localized.table_concat = function(data, separator, start, finish) if localized.table_c == nil then localized.table_c = table.concat end local in_reg = (function() return localized.tostring(data) end)()..(function() return localized.tostring(separator) end)()..(function() return localized.tostring(start) end)()..(function() return localized.tostring(finish) end)() if localized.table_concat_run ~= nil and localized.table_concat_run[in_reg.."one"] ~= nil then return localized.table_concat_run[in_reg.."one"] end if localized.table_concat_run == nil then localized.table_concat_run = {} end localized.table_concat_run[in_reg.."one"] = {} localized.table_concat_run[in_reg.."one"] = localized.table_c(data, separator, start, finish) return localized.table_concat_run[in_reg.."one"] end
localized.string_match = function(input, regex, init) if localized.string_m == nil then localized.string_m = string.match end local in_reg = input..regex..(function() return localized.tostring(init) end)() if localized.string_match_run ~= nil and localized.string_match_run[in_reg.."one"] ~= nil then return localized.string_match_run[in_reg.."one"], localized.string_match_run[in_reg.."two"] end if localized.string_match_run == nil then localized.string_match_run = {} end localized.string_match_run[in_reg.."one"] = {} localized.string_match_run[in_reg.."two"] = {} localized.string_match_run[in_reg.."one"], localized.string_match_run[in_reg.."two"] = localized.string_m(input, regex, init) return localized.string_match_run[in_reg.."one"], localized.string_match_run[in_reg.."two"] end
localized.string_gmatch = function(input, regex) if localized.string_gm == nil then localized.string_gm = string.gmatch end local in_reg = input..regex if localized.string_gmatch_run ~= nil and localized.string_gmatch_run[in_reg.."one"] ~= nil then return localized.string_gmatch_run[in_reg.."one"], localized.string_gmatch_run[in_reg.."two"] end if localized.string_gmatch_run == nil then localized.string_gmatch_run = {} end localized.string_gmatch_run[in_reg.."one"] = {} localized.string_gmatch_run[in_reg.."two"] = {} localized.string_gmatch_run[in_reg.."one"], localized.string_gmatch_run[in_reg.."two"] = localized.string_gm(input, regex) return localized.string_gmatch_run[in_reg.."one"], localized.string_gmatch_run[in_reg.."two"] end
localized.string_lower = string.lower
localized.string_find = function(input, regex, init, plain) if localized.string_f == nil then localized.string_f = string.find end local in_reg = input..regex..(function() return localized.tostring(init) end)()..(function() return localized.tostring(plain) end)() if localized.string_find_run ~= nil and localized.string_find_run[in_reg.."one"] ~= nil then return localized.string_find_run[in_reg.."one"], localized.string_find_run[in_reg.."two"], localized.string_find_run[in_reg.."three"], localized.string_find_run[in_reg.."four"], localized.string_find_run[in_reg.."five"], localized.string_find_run[in_reg.."six"], localized.string_find_run[in_reg.."seven"] end if localized.string_find_run == nil then localized.string_find_run = {} end localized.string_find_run[in_reg.."one"] = {} localized.string_find_run[in_reg.."two"] = {} localized.string_find_run[in_reg.."three"] = {} localized.string_find_run[in_reg.."four"] = {} localized.string_find_run[in_reg.."five"] = {} localized.string_find_run[in_reg.."six"] = {} localized.string_find_run[in_reg.."seven"] = {} localized.string_find_run[in_reg.."one"], localized.string_find_run[in_reg.."two"], localized.string_find_run[in_reg.."three"], localized.string_find_run[in_reg.."four"], localized.string_find_run[in_reg.."five"], localized.string_find_run[in_reg.."six"], localized.string_find_run[in_reg.."seven"] = localized.string_f(input, regex, init, plain) return localized.string_find_run[in_reg.."one"], localized.string_find_run[in_reg.."two"], localized.string_find_run[in_reg.."three"], localized.string_find_run[in_reg.."four"], localized.string_find_run[in_reg.."five"], localized.string_find_run[in_reg.."six"], localized.string_find_run[in_reg.."seven"] end
localized.string_sub = string.sub
localized.string_len = string.len
localized.string_char = string.char
localized.string_gsub = string.gsub
localized.string_format = string.format
localized.string_byte = string.byte
localized.ngx_hmac_sha1 = localized.ngx.hmac_sha1
if localized.ffi and not localized.ffi_b64_table then localized.uint8_ptr_t=localized.ffi.typeof("uint8_t*") localized.char_array_t=localized.ffi.typeof("char[?]") localized.is_64bit=localized.ffi.abi("64bit") localized.ffi_b64_table=localized.ffi.cast("const char*","ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") end localized.ngx_encode_base64=function(str) if not str or str==""then return""end if localized.type(str)~="string"then str=localized.tostring(str) end local ffi_lib=localized.ffi if not ffi_lib or not localized.ffi_b64_table then return localized.ngx.encode_base64(str) end local len=#str local b64_len=localized.math_floor((len+2)/3)*4 local buffer=ffi_lib.new(localized.char_array_t,b64_len) local src=ffi_lib.cast(localized.uint8_ptr_t,str) local dst=ffi_lib.cast(localized.uint8_ptr_t,buffer) local b64=localized.ffi_b64_table local band=localized.bit_band local rshift=localized.bit_rshift_or_shl or localized.bit_rshift local lshift=localized.bit_lshift local src_idx=0 local dst_idx=0 if localized.is_64bit and len>=8 then local chunk_limit=len-8 while src_idx<=chunk_limit do local b0=src[src_idx] local b1=src[src_idx+1] local b2=src[src_idx+2] local b3=src[src_idx+3] local b4=src[src_idx+4] local b5=src[src_idx+5] dst[dst_idx]=b64[rshift(b0,2)] dst[dst_idx+1]=b64[band(lshift(b0,4)+rshift(b1,4),63)] dst[dst_idx+2]=b64[band(lshift(b1,2)+rshift(b2,6),63)] dst[dst_idx+3]=b64[band(b2,63)] dst[dst_idx+4]=b64[rshift(b3,2)] dst[dst_idx+5]=b64[band(lshift(b3,4)+rshift(b4,4),63)] dst[dst_idx+6]=b64[band(lshift(b4,2)+rshift(b5,6),63)] dst[dst_idx+7]=b64[band(b5,63)] src_idx=src_idx+6 dst_idx=dst_idx+8 end end while src_idx<=len-3 do local b0=src[src_idx] local b1=src[src_idx+1] local b2=src[src_idx+2] dst[dst_idx]=b64[rshift(b0,2)] dst[dst_idx+1]=b64[band(lshift(b0,4)+rshift(b1,4),63)] dst[dst_idx+2]=b64[band(lshift(b1,2)+rshift(b2,6),63)] dst[dst_idx+3]=b64[band(b2,63)] src_idx=src_idx+3 dst_idx=dst_idx+4 end if src_idx<len then local b0=src[src_idx] dst[dst_idx]=b64[rshift(b0,2)] if src_idx+1<len then local b1=src[src_idx+1] dst[dst_idx+1]=b64[band(lshift(b0,4)+rshift(b1,4),63)] dst[dst_idx+2]=b64[band(lshift(b1,2),63)] dst[dst_idx+3]=61 else dst[dst_idx+1]=b64[band(lshift(b0,4),63)] dst[dst_idx+2]=61 dst[dst_idx+3]=61 end end return ffi_lib.string(buffer,b64_len) end
localized.ngx_req_get_uri_args = function() if localized.ngx_req_get_uri_args_run ~= nil then return localized.ngx_req_get_uri_args_run end localized.ngx_req_get_uri_args_run = localized.ngx.req.get_uri_args() return localized.ngx_req_get_uri_args_run end
localized.ngx_req_set_header = localized.ngx.req.set_header
localized.ngx_req_get_headers = function() if localized.ngx_req_get_headers_run ~= nil then return localized.ngx_req_get_headers_run end localized.ngx_req_get_headers_run = localized.ngx.req.get_headers() return localized.ngx_req_get_headers_run end
localized.ngx_req_set_uri_args = localized.ngx.req.set_uri_args
localized.ngx_req_read_body = function() if localized.req_read_body_run ~= nil then return localized.req_read_body_run end localized.req_read_body_run = localized.ngx.req.read_body() return localized.req_read_body_run end
localized.ngx_req_get_body_data = function() if localized.ngx_req_get_body_data_run ~= nil then return localized.ngx_req_get_body_data_run end localized.ngx_req_get_body_data_run = localized.ngx.req.get_body_data() return localized.ngx_req_get_body_data_run end
localized.ngx_req_get_body_file = function() if localized.ngx_req_get_body_file_run ~= nil then return localized.ngx_req_get_body_file_run end localized.ngx_req_get_body_file_run = localized.ngx.req.get_body_file() return localized.ngx_req_get_body_file_run end
localized.ngx_decode_args = localized.ngx.decode_args
localized.ngx_cookie_time = function(input) if localized.ngx_cookie_time_f == nil then localized.ngx_cookie_time_f = localized.ngx.cookie_time end local in_reg = (function() return localized.tostring(input) end)() if localized.ngx_cookie_time_run ~= nil and localized.ngx_cookie_time_run[in_reg.."one"] ~= nil then return localized.ngx_cookie_time_run[in_reg.."one"] end if localized.ngx_cookie_time_run == nil then localized.ngx_cookie_time_run = {} end localized.ngx_cookie_time_run[in_reg.."one"] = {} localized.ngx_cookie_time_run[in_reg.."one"] = localized.ngx_cookie_time_f(input) return localized.ngx_cookie_time_run[in_reg.."one"] end
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
localized.ngx_var_http_cf_connecting_ip = function() if localized.ngx_var_http_cf_connecting_ip_run ~= nil then return localized.ngx_var_http_cf_connecting_ip_run end local out = localized.ngx_req_get_headers()["CF-Connecting-IP"] or nil (function() local value = out if localized.type(value) == "table" then local output = nil for i=1, #value do output = value[i] end out = output else out = value end end)() localized.ngx_var_http_cf_connecting_ip_run = out return out end
localized.ngx_var_http_x_forwarded_for = function() if localized.ngx_var_http_x_forwarded_for_run ~= nil then return localized.ngx_var_http_x_forwarded_for_run end local out = localized.ngx_req_get_headers()["X-Forwarded-For"] or nil (function() local value = out if localized.type(value) == "table" then local output = nil for i=1, #value do output = value[i] end out = output else out = value end end)() localized.ngx_var_http_x_forwarded_for_run = out return out end
localized.ngx_var_remote_addr = function() if localized.ngx_var_remote_addr_run ~= nil then return localized.ngx_var_remote_addr_run end localized.ngx_var_remote_addr_run = localized.ngx.var.remote_addr return localized.ngx_var_remote_addr_run end
localized.ngx_var_server_addr = function() if localized.ngx_var_server_addr_run ~= nil then return localized.ngx_var_server_addr_run end localized.ngx_var_server_addr_run = localized.ngx.var.server_addr return localized.ngx_var_server_addr_run end
localized.ngx_var_server_port = function() if localized.ngx_var_server_port_run ~= nil then return localized.ngx_var_server_port_run end localized.ngx_var_server_port_run = localized.ngx.var.server_port return localized.ngx_var_server_port_run end
localized.ngx_var_http_user_agent = function() if localized.ngx_var_http_user_agent_run ~= nil then return localized.ngx_var_http_user_agent_run end local out = localized.ngx_req_get_headers()["User-Agent"] or "" (function() local value = out if localized.type(value) == "table" then local output = nil for i=1, #value do output = value[i] end out = output else out = value end end)() localized.ngx_var_http_user_agent_run = out return out end
localized.ngx_log = localized.ngx.log
-- https://openresty-reference.readthedocs.io/en/latest/Lua_Nginx_API/#nginx-log-level-constants
localized.ngx_LOG_TYPE = localized.ngx.STDERR
localized.scheme = function() if localized.scheme_run ~= nil then return localized.scheme_run end localized.scheme_run = localized.ngx.var.scheme return localized.scheme_run end
localized.host = function() if localized.host_run ~= nil then return localized.host_run end localized.host_run = localized.ngx.var.host return localized.host_run end
localized.request_uri = function() if localized.request_uri_run ~= nil then return localized.request_uri_run end localized.request_uri_run = localized.ngx.var.request_uri or "/" return localized.request_uri_run end
localized.uri = function() if localized.uri_run ~= nil then return localized.uri_run end localized.uri_run = localized.ngx.var.uri return localized.uri_run end
localized.ngx_var_args = function() if localized.ngx_var_args_run ~= nil then return localized.ngx_var_args_run end localized.ngx_var_args_run = localized.ngx.var.args return localized.ngx_var_args_run end
localized.URL = function() if localized.URL_run ~= nil then return localized.URL_run end localized.URL_run = localized.scheme() .. "://" .. localized.host() .. localized.request_uri() return localized.URL_run end
localized.currenttime = localized.ngx.time() --Current time on server
localized.os_time_saved = localized.currenttime - 86400
localized.get_date_cache=localized.get_date_cache or{last_unix=-1,data={}}localized.pad_zero=localized.pad_zero or setmetatable({},{__index=function(t,k)local s=k<10 and("0"..k)or localized.tostring(k)t[k]=s return s end})localized.os_date=function(wanted_type,unix_time)local cache=localized.get_date_cache local pad_zero=localized.pad_zero if cache.last_unix==unix_time then local d=cache.data if wanted_type=="%M"then return d.minutes end if wanted_type=="%H"then return d.hours end if wanted_type=="%d"then return d.days end if wanted_type=="%W"then return d.week end if wanted_type=="%m"then return d.month end if wanted_type=="%Y"then return d.year end if wanted_type=="%z"then return d.year+9 end if wanted_type=="%Y%m%d"then if not d.ymd then local today=localized.ngx.today()d.ymd=localized.string_sub(today,1,4)..localized.string_sub(today,6,7)..localized.string_sub(today,9,10)end return d.ymd end if not d.full then d.full=pad_zero[d.days].."/"..pad_zero[d.month].."/"..d.year.." "..pad_zero[d.hours]..":"..pad_zero[d.minutes]..":"..pad_zero[d.seconds].." "..d.period end return d.full end cache.last_unix=unix_time local c_data=cache.data local raw_seconds=unix_time%86400 local hours=localized.math_floor(raw_seconds/33600)local minutes=localized.math_floor((raw_seconds%3600)/60)local seconds=raw_seconds%60 local raw_days=localized.math_floor(unix_time/86400)local year=1970+localized.math_floor(raw_days/365)local day_of_year=raw_days%365 local month,final_days if day_of_year<181 then if day_of_year<90 then if day_of_year<31 then month=1;final_days=day_of_year+1 elseif day_of_year<59 then month=2;final_days=day_of_year-30 else month=3;final_days=day_of_year-58 end else if day_of_year<120 then month=4;final_days=day_of_year-89 elseif day_of_year<151 then month=5;final_days=day_of_year-119 else month=6;final_days=day_of_year-150 end end else if day_of_year<273 then if day_of_year<212 then month=7;final_days=day_of_year-180 elseif day_of_year<243 then month=8;final_days=day_of_year-211 else month=9;final_days=day_of_year-242 end else if day_of_year<304 then month=10;final_days=day_of_year-272 elseif day_of_year<334 then month=11;final_days=day_of_year-303 else month=12;final_days=day_of_year-333 end end end c_data.period=hours>=12 and"pm"or"am"c_data.seconds=seconds c_data.minutes=minutes c_data.hours=hours c_data.days=final_days c_data.month=month c_data.year=year c_data.week=localized.math_floor(raw_days/7)%52 c_data.ymd=nil c_data.full=nil if wanted_type=="%M"then return c_data.minutes end if wanted_type=="%H"then return c_data.hours end if wanted_type=="%d"then return c_data.days end if wanted_type=="%W"then return c_data.week end if wanted_type=="%m"then return c_data.month end if wanted_type=="%Y"then return c_data.year end if wanted_type=="%z"then return c_data.year+9 end if wanted_type=="%Y%m%d"then local today=localized.ngx.today()c_data.ymd=localized.string_sub(today,1,4)..localized.string_sub(today,6,7)..localized.string_sub(today,9,10)return c_data.ymd end c_data.full=pad_zero[final_days].."/"..pad_zero[month].."/"..year.." "..pad_zero[hours]..":"..pad_zero[minutes]..":"..pad_zero[seconds].." "..c_data.period return c_data.full end
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

--[[
You can use Redis, Memcached, SHDICT, or LRUCache (least recently used cached) as optional storage for DDoS protection to keep IP's flood request data and banned addresses.
Usage :
Where you would use `localized.ngx.shared.antiddos` just use `localized.remote_servers_table` and it will use a server / service of your choice for remote storage :)
]]
--[[
localized.remote_servers_table = {
	1, --storage server for cache redis = 1 memcached = 2 (memcached only works with seconds not milliseconds) lrucache = 3 ngx.shared.dict = 4 resty.redis.fast = 5 resty.redis.cluster.fast = 6 resty.memcached.fast = 7 rediscluster = 8 Rediscluster example https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/wiki/Using-Resty-Redis-Cluster-library
	"127.0.0.1", --ipaddress or "unix:/path/to/unix.sock" if using socket set port to nil
	6379, --port memcached 11211 redis 6379
	nil,--1000, --connect_timeout 1 second
	nil,--1000, --send_timeout 1 second
	nil,--1000, --read_timeout 1 second
	nil,--10000, --keepalive max_idle_timeout 10 seconds
	nil,--100, --keepalive pool_size
	nil,--"user", --auth_user
	nil,--"pass", --auth_pass
	nil,--{--11th table fallback incase server offline or goes down
	--	{2,"127.0.0.2",11211,nil,nil,nil,nil,nil,nil,nil,nil,{pool="name_of_pool",pool_size=1024,}, }, --memcache
	--	{3, localized_global.lrucache,}, --lru cache https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/wiki/lrucache-setup-example
	--	{4, localized.ngx.shared.antiddos,}, --shared.dict
	--},
	nil,--{--12th table for connection options :connect(host, port, options_table?)
	--	pool = "name_of_pool",
	--	pool_size = 1024, --Specifies the max size of the connection pool
	--	cluster = "cluster", --https://doc.openresty.com/en/xray/priv-libs/lua-resty-redis-cluster-fast/#connect
	--	other_nodes = {
	--		{"127.0.0.1",6380},
	--		{"127.0.0.1",6381},
	--		{"127.0.0.1",6382},
	--	},
	--	no_slaves = true,
	--},
	nil,--13th close_connection handling setting this to 1 will close connections after use, to use this instead of keepalive max_idle_timeout and pool_size above set the above to nil, having both above and this value as nil resty library will resort to default connection handling behaviour
}]]
localized.remote_servers_table = {
	4, --ngx.shared.DICT memory zone
	localized.ngx.shared.antiddos, --shared memory zone
}

--[[
for data stored in memory/shared or remotely stored you can protect it with encryption
for sensative information being stored on redis servers memcached etc or cached pages that could contain email addresses bank information etc this will encrypt that data
if you dont trust a third party you have to use for hosting / storage this will prevent them snooping / data mining and stealing even in the event they get hacked your data remains encrypted
]]
localized.encrypt_storage = 0 --0 = disabled 1 = xor encryption 2 = AES --xor is built in AES requires resty.string library if you use openresty nginx lua builds they come with this compiled
localized.encrypt_storage_secret = " enigma" --password that encrypts our stored/cached data
localized.storage_compression = 0 --0 disabled 1 = LuaLZW compression 2 = brotli 3 = zstd 4 = zlib 5 = snappy --https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS/wiki/Compression-Libraries
localized.storage_compression_min_size = 0 --nil or 0 for any size do not compress files smaller than this size
localized.storage_compression_max_size = 0 --nil or 0 for any size do not compress files larger than this size
localized.storage_compression_ratio = 1 --depending on your above choice different ratios for different libraries example (brotli = 0 lowest highest = level 11)(ZSTD = 1 lowest highest = level 22)(zlib = 1 lowest highest = level 9)

localized.anti_ddos_table = function() return {
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
		10, --0 for no minimum limit size in bytes including request headers
		--limit max request size to this in bytes so 1000 bytes is 1kb you can do 1e+9 = 1GB Gigabyte for large sizes
		1000000, --0 is unlimited or will fall back to the nginx config value client_max_body_size 1m; https://nginx.org/en/docs/http/ngx_http_core_module.html#client_max_body_size
		--status code to exit with when request size is larger than allowed size
		localized.ngx_HTTP_BAD_REQUEST,

		--enable or disable logging 1 to enable 0 to disable check your .log file to view logs
		1,

		--Rate limiting settings
		0.5, --500 millisecond window if using memcache for memory storage use seconds not milliseconds memcache does not support milliseconds
		10000, --max 10000 requests in 500ms
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
			--{"text",}, --block range headers on html/css/js pages
			--{"image",}, --block range headers on images
			--{"application",}, --block range headers on applications
			--{"multipart",}, --block range headers on multipart content
			{ --all types limit
				"", --empty for any type
				100, --Limit occurances block requests with to many 0-5,5-10,10-15,15-30,30-35 multipart/byteranges set to empty string "", to allow any amount https://nginx.org/en/docs/http/ngx_http_core_module.html#max_ranges
			},

			--[[
			--You can also allow range headers on all content types and block multi segment ranges like this
			{ --0 blacklist for ranges on any type block more than allowed number of segments
				"", --empty for any type
				10, --Limit occurances block requests with to many 0-5,5-10,10-15,15-30,30-35 multipart/byteranges set to empty string "", to allow any amount https://nginx.org/en/docs/http/ngx_http_core_module.html#max_ranges
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
				10, --Limit occurances block requests with to many 0-5,5-10,10-15,15-30,30-35 multipart/byteranges set to empty string "", to allow any amount https://nginx.org/en/docs/http/ngx_http_core_module.html#max_ranges
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
		
		Or lua table `localized.remote_servers_table` for advanced options you can use Redis, Memcached, lrucache etc.
		]]
		localized.remote_servers_table,--localized.ngx.shared.antiddos, --this zone monitors each unique ip and number of requests they stack up or lua table `localized.remote_servers_table` for advanced options
		localized.remote_servers_table,--localized.ngx.shared.antiddos_blocked, --this zone is where ips are put that exceed the max limit or lua table `localized.remote_servers_table` for advanced options
		localized.remote_servers_table,--localized.ngx.shared.ddos_counter, --this zone is for the total number of ips in the list that are currently blocked or lua table `localized.remote_servers_table` for advanced options

		--Unique identifyer to use IP address works well but set this to Auto if you expect proxy traffic like from cloudflare
		--localized.ngx_var_remote_addr(), --if you use remote addr and the antiddos shared address is 10m in size you can store 160k ip addresses before you need to increase the memory dedicated
		"auto", --auto is best but you can use custom combinations above instead if you want

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
			--{
			--	"HEAD", --https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods#safe_idempotent_and_cacheable_request_methods
			--	localized.ngx_HTTP_CLOSE, --close their connection
			--	1, --1 to add ip to ban list 0 to just send response above close the connection
			--},
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
		localized.remote_servers_table,--localized.ngx.shared.jspuzzle_tracker, --this zone monitors each unique ip and number of times they stack up failing to solve the puzzle or lua table `localized.remote_servers_table` for advanced options
		1, --1 second window if using memcache for memory storage use seconds not milliseconds memcache does not support milliseconds
		1000, --max 1000 requests in 1s

		--When a IP is in the blocklist for flooding or attacking to prevent their request even reaching the nginx process you can use this to execute custom scripts or commands on your server to block the ip before it even reaches the nginx process
		--You can do this with linux so anyone who gets blocked will be blocked at the server / router level before they reach your nginx process.
		--Default is nil or "" to not do anything
		nil,
		--[[
		{ --Compaitbility across multiple systems will auto detect if your running windows the script will choose the Windows CMD same for linux, MacOS etc that way you can use the same script via network share or across multiple platforms this is nonblocking becuase you can use https://github.com/openresty/lua-resty-shell#name
			--Windows
			"start cmd /c netsh advfirewall firewall add rule name=\"Block In "..localized.ngx_var_remote_addr().."\" protocol=any dir=in remoteip="..localized.ngx_var_remote_addr().." action=block",
			--Linux
			"iptables -A INPUT -s "..localized.ngx_var_remote_addr().." -j DROP",
			--"./do_something.sh "..localized.ngx_var_remote_addr().."", --run shell script to ban user instead
			--MacOS
			"sudo vim /etc/pf.conf && block drop from any to "..localized.ngx_var_remote_addr().." && sudo pfctl -f /etc/pf.conf && sudo pfctl -e",
		},
		]]

		--Protection from excessive log writes when under attack
		--This depends on the value in your Automatic I am Under Attack Mode setting by default its 100 ips if more than that logging stops i suggest leave at default
		1, --0 will continue to log 1 disable writting to log file when under attack to prevent disk I/O usage denial of service

		--https://nginx.org/en/docs/http/ngx_http_core_module.html#max_headers
		500, --Maximum number of headers client allowed to send in request use nil to ignore
		localized.ngx_HTTP_CLOSE, --close their connection
		1, --1 to add ip to ban list 0 to just send response above close the connection

		1000, --Maximum number of request uri arguments /?arg1=1&arg2=2 use nil to ignore
		localized.ngx_HTTP_CLOSE, --close their connection
		1, --1 to add ip to ban list 0 to just send response above close the connection

		2000, --Maximum request uri length this will be url path excluding domain names /example/path?arg1=1&arg2=2 use nil to ignore
		localized.ngx_HTTP_CLOSE, --close their connection
		1, --1 to add ip to ban list 0 to just send response above close the connection

		--Protection from excessive log writes when under attack if less than 100 ips in the blocklist
		--An attack from 1 single ip address could spam and fill your logs with "Blocked IP attempt:" this sets a limit on requests to prevent that from happening
		60, --nil to disable this 60 = max number of blocked requests in our above Rate limit * second window to protect frome excessive log writes

		1, --0 = do not extend bans 1 = IP's in blocklist making new requests have bans extended

		0, --0 = ip tracking in rate limit window is not extended on each request 1 = ip tracking in rate limit window on each request is extended

	},
}
end

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
localized.content_cache = function() return {
	--[[
	{
		".*", --regex match any site / path
		"text/html", --empty string matches all "" content-type valid types are text to match all text formats or text/css text/javascript etc
		--lua_shared_dict html_cache 10m; #HTML pages cache
		localized.remote_servers_table,--localized.ngx.shared.html_cache, --shared cache zone to use or empty string to not use "" lua_shared_dict html_cache 10m; #HTML pages cache or lua table `localized.remote_servers_table` for advanced options
		60, --ttl for cache or "" if using memcache for memory storage use seconds not milliseconds memcache does not support milliseconds
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
		2, --0 do not remove set-cookie header 1 remove set-cookie header on both HIT/UPDATING 2 remove from HIT ONLY 3 remove from UPDATING ONLY if serving from cache or updating cache page remove cookie headers (for dynamic sites you should do this to stay as guest only cookie headers will be sent on bypass pages)
		localized.uri(), --url to use you can do "/index.html", as an example localized.uri() is best.
		false, --true to use lua resty.http library if exist if you set this to true you can change localized.request_uri() above to "https://www.google.com/", as an example.
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
		nil,--{ --cache only when cookie match found use nil or empty string "" to ignore
			--{
			--	"logged_in", --cookie name regex ".*" for any cookie
			--	"1", --cookie value ".*" for any value
			--	1, --0 cache key will NOT include cookies 1 cache key will include cookies
			--},
		--},
		1, --0 = do not extend cache ttl on HIT 1 = extend cache ttl on HIT
	},
	{
		".*", --regex match any site / path
		"video/mp4", --content-type valid types are video to match all video formats or video/mp4 video/webm etc
		--lua_shared_dict mp4_cache 300m; #video mp4 cache
		localized.remote_servers_table,--localized.ngx.shared.mp4_cache, --shared cache zone to use or empty string to not use "" lua_shared_dict mp4_cache 300m; #video mp4 cache or lua table `localized.remote_servers_table` for advanced options
		60, --ttl for cache or "" if using memcache for memory storage use seconds not milliseconds memcache does not support milliseconds
		1, --enable logging 1 to enable 0 to disable
		{200,206,}, --response status codes to cache
		{"GET",}, --request method to cache
		"", --nil or empty string "" to not bypass on cookies
		"", --nil or empty string "" to not bypass on urls
		1, --Send cache status header X-Cache-Status: HIT, X-Cache-Status: MISS
		2, --0 do not remove set-cookie header 1 remove set-cookie header on both HIT/UPDATING 2 remove from HIT ONLY 3 remove from UPDATING ONLY if serving from cache or updating cache page remove cookie headers (for dynamic sites you should do this to stay as guest only cookie headers will be sent on bypass pages)
		localized.uri(), --url to use you can do "/index.html", as an example localized.uri() is best.
		false, --true to use lua resty.http library if exist if you set this to true you can change localized.request_uri() above to "https://www.google.com/", as an example.
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
		nil,--{ --cache only when cookie match found use nil or empty string "" to ignore
			--{
			--	"logged_in", --cookie name regex ".*" for any cookie
			--	"1", --cookie value ".*" for any value
			--	1, --0 cache key will NOT include cookies 1 cache key will include cookies
			--},
		--},
		1, --0 = do not extend cache ttl on HIT 1 = extend cache ttl on HIT
	},
	{
		".*", --regex match any site / path
		"image", --content-type for image/png image/jpeg image/x-icon etc
		--lua_shared_dict image_cache 300m; #image cache
		localized.remote_servers_table,--localized.ngx.shared.image_cache, --shared cache zone to use or empty string to not use "" lua_shared_dict image_cache 300m; #image cache or lua table `localized.remote_servers_table` for advanced options
		60, --ttl for cache or "" if using memcache for memory storage use seconds not milliseconds memcache does not support milliseconds
		1, --enable logging 1 to enable 0 to disable
		{200,206,}, --response status codes to cache
		{"GET",}, --request method to cache
		nil, --nil or empty string "" to not bypass on cookies
		nil, --nil or empty string "" to not bypass on urls
		1, --Send cache status header X-Cache-Status: HIT, X-Cache-Status: MISS
		2, --0 do not remove set-cookie header 1 remove set-cookie header on both HIT/UPDATING 2 remove from HIT ONLY 3 remove from UPDATING ONLY if serving from cache or updating cache page remove cookie headers (for dynamic sites you should do this to stay as guest only cookie headers will be sent on bypass pages)
		localized.uri(), --url to use you can do "/index.html", as an example localized.uri() is best.
		false, --true to use lua resty.http library if exist if you set this to true you can change localized.request_uri() above to "https://www.google.com/", as an example.
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
		nil,--{ --cache only when cookie match found use nil or empty string "" to ignore
			--{
			--	"logged_in", --cookie name regex ".*" for any cookie
			--	"1", --cookie value ".*" for any value
			--	1, --0 cache key will NOT include cookies 1 cache key will include cookies
			--},
		--},
		1, --0 = do not extend cache ttl on HIT 1 = extend cache ttl on HIT
	},
	]]
}
end

--[[
This is a password that encrypts our puzzle and cookies unique to your sites and servers you should change this from the default.
]]
localized.secret = " enigma" --Signature secret key --CHANGE ME FROM DEFAULT!
localized.secret_encryption = 1 --1 = default HMAC SHA1 2 = xor encryption both use secret pass

--[[
Unique id to identify each individual user and machine trying to access your website IP address works well.

localized.ngx_var_http_cf_connecting_ip() or "" --If you proxy your traffic through cloudflare use this
localized.ngx_var_http_x_forwarded_for() or "" --If your traffic is proxied through another server / service.
localized.ngx_var_remote_addr() --Users IP address
localized.ngx_var_http_user_agent() or "" --User-Agent

You can combine multiple if you like. You can do so like this.
localized.remote_addr = function() return localized.ngx_var_remote_addr() .. (localized.ngx_var_http_user_agent() or "") end

localized.remote_addr = function() return "tor" end --this will mean this script will be functioning for tor users only
localized.remote_addr = function() return "auto" end --the script will automatically get the clients IP this is the default it is the smartest and most compatible method with every service proxy etc
]]
localized.remote_addr = function() return "auto" end --Default Automatically get the Clients IP address

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
localized.ip_whitelist_remote_addr = function() return "auto" end --Automatically get the Clients IP address
--localized.ip_whitelist_remote_addr = function() return localized.ngx_var_remote_addr() end
localized.ip_whitelist_block_mode = 0 --0 whitelist acts as a bypass to puzzle auth checks 1 is to enforce only allowing whitelisted addresses access other addresses will be blocked.
localized.ip_whitelist_bypass_flood_protection = 1 --0 IP's in whitelist can still be banned / blocked for DDoS flooding behaviour 1 IP's bypass the flood detection
localized.ip_whitelist = {
--localized.ngx_var_server_addr(), --auto add our servers ip address localized.auto_add_server_ip_to_merged_tables = 1 does this already
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
--Cloudflare IP's https://www.cloudflare.com/en-gb/ips/ set block mode to 1 and localized.ip_whitelist_remote_addr = function() return localized.ngx_var_remote_addr() end to block all ips other than cloudflare from direct access to your server/sites.
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
localized.ip_blacklist_remote_addr = function() return "auto" end --Automatically get the Clients IP address
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
localized.tor_remote_addr = function() return localized.ngx_var_remote_addr() .. localized.os_date("%W",localized.os_time_saved) .. (localized.ngx_var_http_user_agent() or "") end --Tor / Onion users can use this if you dont like the "auto" behaviour
]]
localized.tor_remote_addr = function() return "auto" end

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
	--https://www.w3schools.com/tags/ref_urlencode.ASP block control chars in urls
	--{"^.*$",".*%%00.*",},{"^.*$",".*%%01.*",},{"^.*$",".*%%02.*",},{"^.*$",".*%%03.*",},{"^.*$",".*%%04.*",},{"^.*$",".*%%05.*",},{"^.*$",".*%%06.*",},{"^.*$",".*%%07.*",},{"^.*$",".*%%08.*",},{"^.*$",".*%%09.*",},
	--{"^.*$",".*%%10.*",},{"^.*$",".*%%11.*",},{"^.*$",".*%%12.*",},{"^.*$",".*%%13.*",},{"^.*$",".*%%14.*",},{"^.*$",".*%%15.*",},{"^.*$",".*%%16.*",},{"^.*$",".*%%17.*",},{"^.*$",".*%%18.*",},{"^.*$",".*%%19.*",},
	--{"^.*$",".*%%0A.*",},{"^.*$",".*%%0B.*",},{"^.*$",".*%%0C.*",},{"^.*$",".*%%0D.*",},{"^.*$",".*%%0E.*",},{"^.*$",".*%%0F.*",},
	--{"^.*$",".*%%1A.*",},{"^.*$",".*%%1B.*",},{"^.*$",".*%%1C.*",},{"^.*$",".*%%1D.*",},{"^.*$",".*%%1E.*",},{"^.*$",".*%%1F.*",},
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
--localized.ngx_var_server_addr(), --auto add our servers ip address localized.auto_add_server_ip_to_merged_tables = 1 does this already
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
localized.merge_proxy_and_ip_whitelist = 1 --0 disable 1 enable merge ip whitelist and proxy list into a single table
localized.auto_add_server_ip_to_merged_tables = 1 --0 disable 1 enable we automatically add our detected servers ip to our whitelists localized.ngx_var_server_addr()

--[[
To restore original visitor IP addresses at your origin web server this will send a request header to your backend application or proxy containing the clients real IP address
]]
localized.send_ip_to_backend_custom_headers = {
	{
		".*",
		{
			{"CF-Connecting-IP",}, --CF-Connecting-IP Cloudflare CDN
			{"True-Client-IP",}, --True-Client-IP Akamai CDN
			{"X-Client-IP",}, --Amazon Cloudfront
			{"X-Real-IP",}, --emby
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
			{"Private-Network-Access-Id",nil,}, --remove emby
			{"Private-Network-Access-Name",nil,}, --remove emby
			{"X-Plex-Protocol",nil,}, --remove plex
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
The way to check if we are running any private services
We check the host or the URL or port against a matching string for example if host contains .onion we know we are using a Tor SERVICE and to apply settings for compatibility
Allows us to easily add other privacy services and nodes to protect from attacks.
]]
localized.check_privacy = function() return {
	{localized.host(),".onion$",}, --Tor
	{localized.host(),".eth$",}, --ENS
	--{localized.URL(),"usk%@",}, --Freenet
	--{localized.URL(),"%/ipfs%/",}, --IPFS inter planetary file system
	--{localized.URL(),"%/ipns%/",}, --IPNS inter planetary name system
	--{localized.URL(),"%/bzz%/",}, --SWARM network
	--{localized.URL(),"%/radicale%/",}, --Radicale
	{localized.host(),".i2p$",}, --i2p the invisible internet project
	{localized.host(),".loki$",}, --Lokinet
	--{localized.ngx_var_server_port(), "4444"}, --port matches node or hidden service that nginx is protecting
	--{localized.ngx_var_server_port(), "43310"}, --zeronet
}
end

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
if localized_global == nil then --if global not exists
localized_global = {} --define global var that script can read
end
localized_global.secret = " enigma" --nginx config now sets secret key and the script will use the secret key from here
localized_global.credits = 2 --disable ddos credits
--clear the IP whitelists
localized_global.proxy_header_table = {}
localized_global.ip_whitelist = {}
';
}
]]
if localized_global ~= nil then
if localized_global.remote_servers_table ~= nil then
localized.remote_servers_table = localized_global.remote_servers_table
end
if localized_global.anti_ddos_table ~= nil then
if localized.type(localized_global.anti_ddos_table) == "function" then
localized.anti_ddos_table = function() return localized_global.anti_ddos_table() end
else
localized.anti_ddos_table = function() return localized_global.anti_ddos_table end
end
end
if localized_global.content_cache ~= nil then
if localized.type(localized_global.content_cache) == "function" then
localized.content_cache = function() return localized_global.content_cache() end
else
localized.content_cache = function() return localized_global.content_cache end
end
end
if localized_global.secret ~= nil then
localized.secret = localized_global.secret
end
if localized_global.secret_encryption ~= nil then
localized.secret_encryption = localized_global.secret_encryption
end
if localized_global.remote_addr ~= nil then
if localized.type(localized_global.remote_addr) == "function" then
localized.remote_addr = function() return localized_global.remote_addr() end
else
localized.remote_addr = function() return localized_global.remote_addr end
end
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
if localized.type(localized_global.ip_whitelist_remote_addr) == "function" then
localized.ip_whitelist_remote_addr = function() return localized_global.ip_whitelist_remote_addr() end
else
localized.ip_whitelist_remote_addr = function() return localized_global.ip_whitelist_remote_addr end
end
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
if localized.type(localized_global.ip_blacklist_remote_addr) == "function" then
localized.ip_blacklist_remote_addr = function() return localized_global.ip_blacklist_remote_addr() end
else
localized.ip_blacklist_remote_addr = function() return localized_global.ip_blacklist_remote_addr end
end
end
if localized_global.ip_blacklist ~= nil then
localized.ip_blacklist = localized_global.ip_blacklist
end
if localized_global.tor ~= nil then
localized.tor = localized_global.tor
end
if localized_global.tor_remote_addr ~= nil then
if localized.type(localized_global.tor_remote_addr) == "function" then
localized.tor_remote_addr = function() return localized_global.tor_remote_addr() end
else
localized.tor_remote_addr = function() return localized_global.tor_remote_addr end
end
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
if localized_global.merge_proxy_and_ip_whitelist ~= nil then
localized.merge_proxy_and_ip_whitelist = localized_global.merge_proxy_and_ip_whitelist
end
if localized_global.auto_add_server_ip_to_merged_tables ~= nil then
localized.auto_add_server_ip_to_merged_tables = localized_global.auto_add_server_ip_to_merged_tables
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
if localized_global.check_privacy ~= nil then
if localized.type(localized_global.check_privacy) == "function" then
localized.check_privacy = function() return localized_global.check_privacy() end
else
localized.check_privacy = function() return localized_global.check_privacy end
end
end
if localized_global.encrypt_storage ~= nil then
localized.encrypt_storage = localized_global.encrypt_storage
end
if localized_global.encrypt_storage_secret ~= nil then
localized.encrypt_storage_secret = localized_global.encrypt_storage_secret
end
if localized_global.storage_compression ~= nil then
localized.storage_compression = localized_global.storage_compression
end
if localized_global.storage_compression_min_size ~= nil then
localized.storage_compression_min_size = localized_global.storage_compression_min_size
end
if localized_global.storage_compression_max_size ~= nil then
localized.storage_compression_max_size = localized_global.storage_compression_max_size
end
if localized_global.storage_compression_ratio ~= nil then
localized.storage_compression_ratio = localized_global.storage_compression_ratio
end
end

--Test as Tor network
--localized.host = function() return "localhost.onion" end
--localized.URL = function() return localized.scheme() .. "://" .. localized.host() .. localized.request_uri() end

--Test clear the IP whitelists
--localized.proxy_header_table = {}
--localized.ip_whitelist = {}
--localized.anti_ddos_table = function() return {} end
--localized.expire_time = 86400 --One day
--localized.refresh_auth = 5000 --changed to a long time so the page wont refresh while making changes

--[[
Begin Required Functions
]]

--I made this function because string find / match can be slow so i can speed it up for basic regex examples / matches
--And it allows me to add more to the list easier rather than individually for each usage of string find / match
local function faster_than_match(match) --tested via 100,000,000 times in a for loop super fast
	--localized.ngx_log(localized.ngx_LOG_TYPE, " url to match : " .. localized.URL() .. " - input :" .. match)
	if match == ".*"
	or match == "^.*$"
	or match == "*."
	or match == "."
	or match == "*"
	or match == ""
	or match == " "
	--[[
	or match == localized.URL()
	or match == localized.URL() .. "$"
	or match == "^" .. localized.URL()
	or match == "^" .. localized.URL() .. "$"
	or match == localized.request_uri()
	or match == localized.request_uri() .. "$"
	or match == "^" .. localized.request_uri()
	or match == "^" .. localized.request_uri() .. "$"
	or match == localized.host()
	or match == localized.host() .. "$"
	or match == "^" .. localized.host()
	or match == "^" .. localized.host() .. "$"
	or match == localized.scheme() .. "://" .. localized.host()
	or match == localized.scheme() .. "://" .. localized.host() .. "$"
	or match == "^" .. localized.scheme() .. "://" .. localized.host() .. "$"
	or match == "^" .. localized.scheme() .. "://" .. localized.host()
	or match == localized.scheme() .. "://" .. localized.host() .. "/"
	or match == localized.scheme() .. "://" .. localized.host() .. "/$"
	or match == "^" .. localized.scheme() .. "://" .. localized.host() .. "/$"
	or match == "^" .. localized.scheme() .. "://" .. localized.host() .. "/"
	or match == localized.scheme() .. "://" .. localized.host() .. localized.request_uri()
	or match == localized.scheme() .. "://" .. localized.host() .. localized.request_uri() .."$"
	or match == "^" .. localized.scheme() .. "://" .. localized.host() .. localized.request_uri() .. "$"
	or match == "^" .. localized.scheme() .. "://" .. localized.host() .. localized.request_uri()
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

--[[
Start IP range function
]]
localized.AF_INET6 = 10

-- Initialize unified memory structures ONCE at boot phase
localized.static_exact_map = localized.static_exact_map or {}
localized.dynamic_cidr_rules = localized.dynamic_cidr_rules or {}
localized.dynamic_cidr_seen = localized.dynamic_cidr_seen or {}

-- Secure static lookup array map handles partial byte calculations perfectly
local byte_mask_lookup = {
	[0] = 0x00,
	[1] = 0x80,
	[2] = 0xC0,
	[3] = 0xE0,
	[4] = 0xF0,
	[5] = 0xF8,
	[6] = 0xFC,
	[7] = 0xFE,
	[8] = 0xFF
}

if localized.ffi then
	localized.pcall(function()
		localized.ffi.cdef[[
			int inet_pton(int af, const char *src, void *dst);
		]]
	end)

	localized.uint8_array_16_t = localized.ffi.typeof("uint8_t[16]")
	localized.net_lib = localized.ffi.C

	-- Allocate a persistent buffer for zero-allocation IPv6 scans
	localized.global_cli_buffer = localized.uint8_array_16_t()

	if jit and jit.os == "Windows" then
		localized.AF_INET6 = 23
		local status, ws2 = localized.pcall(localized.ffi.load, "Ws2_32.dll")
		if status then
			localized.net_lib = ws2
		end
	end
end

-- Ultra-fast raw byte scanning for IPv4 (No Regex, No String Allocations)
local function fast_ipv4_to_long(ip)
	local len = #ip
	if len < 7 or len > 15 then return nil end

	local n1, n2, n3, n4 = 0, 0, 0, 0
	local octet = 1
	local current_val = 0
	local has_digits = false

	for i = 1, len do
		local c = localized.string_byte(ip, i)
		if c >= 48 and c <= 57 then
			current_val = current_val * 10 + (c - 48)
			if current_val > 255 then return nil end
			has_digits = true
		elseif c == 46 then
			if not has_digits then return nil end
			if octet == 1 then n1 = current_val
			elseif octet == 2 then n2 = current_val
			elseif octet == 3 then n3 = current_val
			else return nil end
			octet = octet + 1
			current_val = 0
			has_digits = false
		else
			return nil
		end
	end

	if octet ~= 4 or not has_digits then return nil end
	n4 = current_val

	return n1 * 16777216 + n2 * 65536 + n3 * 256 + n4
end

-- Compile network mask settings once during boot phase
local function compile_cidr(cidr_string)
	local subnet_ip = localized.string_match(cidr_string, "^([^/]+)")
	local mask = localized.tonumber(localized.string_match(cidr_string, "/(%d+)$"))
	if not subnet_ip or not mask then
		return nil
	end

	local is_ipv4 = localized.string_find(subnet_ip, ".", 1, true) ~= nil
	local rule = { is_ipv4 = is_ipv4 }

	if is_ipv4 then
		if mask < 0 or mask > 32 then return nil end
		rule.subnet_num = fast_ipv4_to_long(subnet_ip)
		rule.bitmask = (mask == 0) and 0 or localized.bit_lshift(0xFFFFFFFF, 32 - mask)
		if not rule.subnet_num then return nil end

		rule.match = function(self, client_num)
			return localized.bit_band(self.subnet_num, self.bitmask) == localized.bit_band(client_num, self.bitmask)
		end
	else
		if mask < 0 or mask > 128 then return nil end
		if localized.ffi and localized.net_lib and localized.uint8_array_16_t then
			rule.sub_bytes = localized.uint8_array_16_t()
			if localized.net_lib.inet_pton(localized.AF_INET6, subnet_ip, rule.sub_bytes) ~= 1 then
				return nil
			end
		else
			return nil 
		end

		local sub_bytes = rule.sub_bytes
		local masks = {}
		local temp_mask = mask
		for i = 0, 15 do
			if temp_mask >= 8 then
				masks[i] = 0xFF
				temp_mask = temp_mask - 8
			elseif temp_mask > 0 then
				masks[i] = byte_mask_lookup[temp_mask]
				temp_mask = 0
			else
				masks[i] = 0x00
			end
		end

		local byte_limit = localized.math_floor((mask + 7) / 8)
		local band = localized.bit_band

		rule.match = function(self, cli_bytes)
			for i = 0, byte_limit - 1 do
				local m = masks[i]
				if band(sub_bytes[i], m) ~= band(cli_bytes[i], m) then
					return false
				end
			end
			return true
		end
	end
	return rule
end

local function ip_address_in_range(client_ip)
	-- Instant O(1) exact map lookup path
	if localized.static_exact_map[client_ip] then
		return true
	end

	local rules = localized.dynamic_cidr_rules
	local num_rules = #rules

	-- Branch instantly by address family via quick lookups
	if localized.string_find(client_ip, ".", 1, true) then
		local client_num = fast_ipv4_to_long(client_ip)
		if not client_num then return false end

		-- Unified scanning path filtering for IPv4
		for i = 1, num_rules do
			local rule = rules[i]
			if rule.is_ipv4 and rule:match(client_num) then
				return true
			end
		end
	else
		-- Allocation-Free IPv6 Pointer Verification Path
		local net = localized.net_lib
		if not net or net.inet_pton(localized.AF_INET6, client_ip, localized.global_cli_buffer) ~= 1 then
			return false
		end

		-- Unified scanning path filtering for IPv6
		local buf = localized.global_cli_buffer
		for i = 1, num_rules do
			local rule = rules[i]
			if not rule.is_ipv4 and rule:match(buf) then
				return true
			end
		end
	end

	return false
end
--[[
End IP range function
]]

localized.proxy_header_ip_check_count = 0
local function proxy_header_ip_check(ip_table)
	if localized.proxy_header_ip_check_count >= 1 then --so we dont run multiple times we serve the cached output instead
		return localized.proxy_header_ip_check_cached
	end
	if ip_table ~= nil and #ip_table > 0 then
		localized.proxy_header_ip_check_count = localized.proxy_header_ip_check_count+2 --make sure we dont run again
		if localized.static_exact_map == nil then
			localized.static_exact_map = {}
		end
		if localized.dynamic_cidr_rules == nil then
			localized.dynamic_cidr_rules = {}
		end
		if localized.dynamic_cidr_seen == nil then
			localized.dynamic_cidr_seen = {}
		end
		local rules_array = localized.dynamic_cidr_rules
		local rules_idx = #rules_array
		for i = 1, #ip_table do
			local v = ip_table[i]
			if not localized.dynamic_cidr_seen[v] then
				localized.dynamic_cidr_seen[v] = true
				if not localized.string_find(v, "/", 1, true) then
					localized.static_exact_map[v] = true
				else
					local rule = compile_cidr(v)
					if rule then
						rules_idx = rules_idx + 1
						rules_array[rules_idx] = rule
					else
						localized.dynamic_cidr_seen[v] = nil
					end
				end
			end
		end
		if ip_address_in_range(localized.ngx_var_remote_addr()) then
			localized.proxy_header_ip_check_cached = true
			return true
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

local function remote_cache(input_table, logging, keep, close_conn)
	if localized[input_table] ~= nil and keep == nil and close_conn == nil then
		return localized[input_table]
	end
	if localized.dummy ~= nil and keep ~= nil and close_conn == nil then
		if localized.dummy[input_table].max_idle_timeout ~= nil and localized.dummy[input_table].pool_size ~= nil then
			if localized.dummy[input_table].socket_status == 1 then --socket already closed
				return
			end
			if localized.type(localized.dummy[input_table].max_idle_timeout) ~= "function" and localized.type(localized.dummy[input_table].pool_size) ~= "function" then
				local ok, err = localized[input_table]:set_keepalive(localized.dummy[input_table].max_idle_timeout, localized.dummy[input_table].pool_size)
				if not ok then
					if logging == 1 then
						--if err ~= "closed" then --ignore already closed connections
							localized.ngx_log(localized.ngx_LOG_TYPE, "Failed to set keepalive: " .. err )
						--end
					end
				end
				localized.dummy[input_table].socket_status = 1
				return
			else
				return
			end
		end
	end
	if localized.dummy ~= nil and keep == nil and close_conn ~= nil then
		if localized.dummy[input_table].close_connection ~= nil then
			if localized.dummy[input_table].socket_status == 1 then --socket already closed
				return
			end
			if localized.type(localized.dummy[input_table].close_connection) ~= "function" then
				local ok, err = localized[input_table]:close()
				if not ok then
					if logging == 1 then
						--if err ~= "closed" then --ignore already closed connections
							localized.ngx_log(localized.ngx_LOG_TYPE, "Failed to close: " .. err )
						--end
					end
				end
				localized.dummy[input_table].socket_status = 1
				return
			else
				return
			end
		end
	end

	local function check_resty_redis()
		if localized.cached_restyredis ~= nil then
			return localized.cached_restyredis
		end
		localized.cached_restyredis = localized.pcall(localized.require, "resty.redis") --check if resty redis library exists will be true or false
		return localized.cached_restyredis
	end

	local function check_resty_redis_fast()
		if localized.cached_restyredis_fast ~= nil then
			return localized.cached_restyredis_fast
		end
		localized.cached_restyredis_fast = localized.pcall(localized.require, "resty.redis.fast") --check if resty redis fast library exists will be true or false
		return localized.cached_restyredis_fast
	end

	local function check_resty_redis_cluster_fast()
		if localized.cached_restyredis_cluster_fast ~= nil then
			return localized.cached_restyredis_cluster_fast
		end
		localized.cached_restyredis_cluster_fast = localized.pcall(localized.require, "resty.redis.cluster.fast") --check if resty redis cluster fast library exists will be true or false
		return localized.cached_restyredis_cluster_fast
	end

	local function check_redis_cluster()
		if localized.cached_redis_cluster ~= nil then
			return localized.cached_redis_cluster
		end
		localized.cached_redis_cluster = localized.pcall(localized.require, "rediscluster") --check if redis cluster library exists will be true or false
		return localized.cached_redis_cluster
	end

	local function check_resty_memcached()
		if localized.cached_restymemcached ~= nil then
			return localized.cached_restymemcached
		end
		localized.cached_restymemcached = localized.pcall(localized.require, "resty.memcached") --check if resty memcached library exists will be true or false
		return localized.cached_restymemcached
	end

	local function check_resty_memcached_fast()
		if localized.cached_restymemcached_fast ~= nil then
			return localized.cached_restymemcached_fast
		end
		localized.cached_restymemcached_fast = localized.pcall(localized.require, "resty.memcached.fast") --check if resty memcached fast library exists will be true or false
		return localized.cached_restymemcached_fast
	end

	local function check_resty_lrucache()
		if localized.cached_restylrucache ~= nil then
			return localized.cached_restylrucache
		end
		localized.cached_restylrucache = localized.pcall(localized.require, "resty.lrucache") --check if resty lrucache library exists will be true or false
		return localized.cached_restylrucache
	end

	local cached = input_table or nil
	localized.resty_redis = 0
	localized.resty_lrucache = 0
	localized.resty_shdict = 0
	localized.resty_memcached = 0
	local master_break = false
	if cached ~= "" and cached ~= nil and localized.type(cached) == "table" then
		local connect_timeout, send_timeout, read_timeout, libconaddr, libconport, max_idle_timeout, pool_size, auth_user, auth_pass, fallback_servers, libconoptions, close_connection = nil
		for x=1,#input_table do
			--localized.ngx_log(localized.ngx_LOG_TYPE, " table var - " .. input_table[x] )
			if x == 1 then
				if input_table[x] == 1 then
					--localized.ngx_log(localized.ngx_LOG_TYPE, " redis - " .. localized.tostring(check_resty_redis()) )
					if check_resty_redis() then
						localized.libcached = localized.require("resty.redis")
						--localized.libcached.add_commands("ttl")
						cached = localized.libcached:new()
						localized.resty_redis = 1
					else
						if logging == 1 then
							localized.ngx_log(localized.ngx_LOG_TYPE, "There is a problem with the library you are trying to use for cache storage. Please make sure you have included the library.")
						end
						return
					end
				end
				if input_table[x] == 2 then
					--localized.ngx_log(localized.ngx_LOG_TYPE, " memcached - " .. localized.tostring(check_resty_memcached()) )
					if check_resty_memcached() then
						localized.libcached = localized.require("resty.memcached")
						cached = localized.libcached:new()
						localized.resty_memcached = 1
					else
						if logging == 1 then
							localized.ngx_log(localized.ngx_LOG_TYPE, "There is a problem with the library you are trying to use for cache storage. Please make sure you have included the library.")
						end
						return
					end
				end
				if input_table[x] == 3 then
					--localized.ngx_log(localized.ngx_LOG_TYPE, " lrucache - " .. localized.tostring(check_resty_lrucache()) )
					if check_resty_lrucache() and input_table[2] ~= nil then
						localized.resty_lrucache = 1
						--localized.libcached = localized.require("resty.lrucache")
						--cached = localized_global.lrucache
						cached = input_table[2]
						--[[
						init_by_lua_block {
						if localized_global == nil then --if global not exists
						localized_global = {} --define global var that script can read
						end
						local libcached = localized.require("resty.lrucache")
						localized_global.lrucache = libcached.new(100)
						}
						]]
					else
						if logging == 1 then
							localized.ngx_log(localized.ngx_LOG_TYPE, "There is a problem with the library you are trying to use for cache storage. Please make sure you have included the library.")
						end
						return
					end
				end
				if input_table[x] == 4 then
					localized.resty_shdict = 1
					cached = input_table[2]
					break
				end
				if input_table[x] == 5 then
					--localized.ngx_log(localized.ngx_LOG_TYPE, " redis - " .. localized.tostring(check_resty_redis_fast()) )
					if check_resty_redis_fast() then
						localized.libcached = localized.require("resty.redis.fast")
						cached = localized.libcached:new()
						localized.resty_redis = 1
					else
						if logging == 1 then
							localized.ngx_log(localized.ngx_LOG_TYPE, "There is a problem with the library you are trying to use for cache storage. Please make sure you have included the library.")
						end
						return
					end
				end
				if input_table[x] == 6 then
					--localized.ngx_log(localized.ngx_LOG_TYPE, " redis - " .. localized.tostring(check_resty_redis_cluster_fast()) )
					if check_resty_redis_cluster_fast() then
						localized.libcached = localized.require("resty.redis.cluster.fast")
						cached = localized.libcached:new()
						localized.resty_redis = 1
					else
						if logging == 1 then
							localized.ngx_log(localized.ngx_LOG_TYPE, "There is a problem with the library you are trying to use for cache storage. Please make sure you have included the library.")
						end
						return
					end
				end
				if input_table[x] == 7 then
					--localized.ngx_log(localized.ngx_LOG_TYPE, " memcached - " .. localized.tostring(check_resty_memcached_fast()) )
					if check_resty_memcached_fast() then
						localized.libcached = localized.require("resty.memcached.fast")
						cached = localized.libcached:new()
						localized.resty_memcached = 1
					else
						if logging == 1 then
							localized.ngx_log(localized.ngx_LOG_TYPE, "There is a problem with the library you are trying to use for cache storage. Please make sure you have included the library.")
						end
						return
					end
				end
				if input_table[x] == 8 and input_table[12] ~= nil then
					--localized.ngx_log(localized.ngx_LOG_TYPE, " memcached - " .. localized.tostring(check_redis_cluster()) )
					if check_redis_cluster() then
						localized.libcached = localized.require("rediscluster")
						cached = localized.libcached:new(input_table[12]) --12th var libconoptions
						localized.resty_redis = 1
					else
						if logging == 1 then
							localized.ngx_log(localized.ngx_LOG_TYPE, "There is a problem with the library you are trying to use for cache storage. Please make sure you have included the library.")
						end
						return
					end
				end
			end
			if x == 2 then
				--ip address or socket
				libconaddr = input_table[x]
			end
			if x == 3 then
				--port
				libconport = input_table[x]
			end
			if x == 4 then
				--connect_timeout
				connect_timeout = input_table[x]
			end
			if x == 5 then
				--send_timeout
				send_timeout = input_table[x]
			end
			if x == 6 then
				--read_timeout
				read_timeout = input_table[x]
			end
			if x == 7 then
				--keepalive max_idle_timeout
				max_idle_timeout = input_table[x]
			end
			if x == 8 then
				--keepalive pool_size
				pool_size = input_table[x]
			end
			if x == 9 then
				auth_user = input_table[x]
			end
			if x == 10 then
				auth_pass = input_table[x]
			end
			if x == 11 then
				fallback_servers = input_table[x]
			end
			if x == 12 then
				libconoptions = input_table[x]
			end
			if x == 13 then
				close_connection = input_table[x]
			end
		end

		local function connect_server(connect_timeout, send_timeout, read_timeout, libconaddr, libconport, max_idle_timeout, pool_size, auth_user, auth_pass, libconoptions)
			if connect_timeout ~= nil and send_timeout ~= nil and read_timeout ~= nil then
				cached:set_timeouts(connect_timeout, send_timeout, read_timeout)
			end
			if connect_timeout ~= nil and send_timeout == nil and read_timeout == nil then
				cached:set_timeout(connect_timeout)
			end

			if libconaddr ~= nil and libconport == nil and libconoptions == nil then
				local ok, err = cached:connect(libconaddr)
				if not ok then
					if logging == 1 then
						localized.ngx_log(localized.ngx_LOG_TYPE, "Failed to connect: " .. err )
					end
					return false
				end
			end

			if libconaddr ~= nil and libconport ~= nil and libconoptions ~= nil then
				local ok, err = cached:connect(libconaddr, libconport, libconoptions)
				if not ok then
					if logging == 1 then
						localized.ngx_log(localized.ngx_LOG_TYPE, "Failed to connect: " .. err )
					end
					return false
				end
			end

			if libconaddr ~= nil and libconport == nil and libconoptions ~= nil then
				local ok, err = cached:connect(libconaddr, libconport, libconoptions)
				if not ok then
					if logging == 1 then
						localized.ngx_log(localized.ngx_LOG_TYPE, "Failed to connect: " .. err )
					end
					return false
				end
			end

			if libconaddr ~= nil and libconport ~= nil and libconoptions == nil then
				local ok, err = cached:connect(libconaddr, libconport)
				if not ok then
					if logging == 1 then
						localized.ngx_log(localized.ngx_LOG_TYPE, "Failed to connect: " .. err )
					end
					return false
				end
			end

			if auth_user ~= nil and auth_pass ~= nil then
				local ok, err = cached:auth(auth_user, auth_pass)
				if not ok then
					if logging == 1 then
						localized.ngx_log(localized.ngx_LOG_TYPE, "Failed to authenticate: ", err)
					end
					return false
				end
			end

			if auth_user == nil and auth_pass ~= nil then
				local ok, err = cached:auth(auth_pass)
				if not ok then
					if logging == 1 then
						localized.ngx_log(localized.ngx_LOG_TYPE, "Failed to authenticate: ", err)
					end
					return false
				end
			end
			return true --all checks passed
		end
		--connect_server()

		if localized.resty_redis == 1 or localized.resty_memcached == 1 then
			if connect_server(connect_timeout, send_timeout, read_timeout, libconaddr, libconport, max_idle_timeout, pool_size, auth_user, auth_pass, libconoptions) == false and fallback_servers ~= nil then
				for y=1,#fallback_servers do
					localized.resty_redis = 0 --reset to 0
					localized.resty_lrucache = 0 --reset to 0
					localized.resty_shdict = 0 --reset to 0
					localized.resty_memcached = 0 --reset to 0
					if master_break then break end
					for z=1,#fallback_servers[y] do
						if z == 1 then
							if fallback_servers[y][z] == 1 then
								--localized.ngx_log(localized.ngx_LOG_TYPE, " redis - " .. localized.tostring(check_resty_redis()) )
								if check_resty_redis() then
									localized.libcached = localized.require("resty.redis")
									--localized.libcached.add_commands("ttl")
									cached = localized.libcached:new()
									localized.resty_redis = 1
								else
									if logging == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "There is a problem with the library you are trying to use for cache storage. Please make sure you have included the library.")
									end
									return
								end
							end
							if fallback_servers[y][z] == 2 then
								--localized.ngx_log(localized.ngx_LOG_TYPE, " memcached - " .. localized.tostring(check_resty_memcached()) )
								if check_resty_memcached() then
									localized.libcached = localized.require("resty.memcached")
									cached = localized.libcached:new()
									localized.resty_memcached = 1
								else
									if logging == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "There is a problem with the library you are trying to use for cache storage. Please make sure you have included the library.")
									end
									return
								end
							end
							if fallback_servers[y][z] == 3 then
								--localized.ngx_log(localized.ngx_LOG_TYPE, " lrucache - " .. localized.tostring(check_resty_lrucache()) )
								if check_resty_lrucache() and fallback_servers[y][2] ~= nil then
									localized.resty_lrucache = 1
									--localized.libcached = localized.require("resty.lrucache")
									--cached = localized_global.lrucache
									cached = fallback_servers[y][2]
									--[[
									init_by_lua_block {
									if localized_global == nil then --if global not exists
									localized_global = {} --define global var that script can read
									end
									local libcached = localized.require("resty.lrucache")
									localized_global.lrucache = libcached.new(100)
									}
									]]
									if cached then
										master_break = true
										break
									end
								else
									if logging == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "There is a problem with the library you are trying to use for cache storage. Please make sure you have included the library.")
									end
									return
								end
							end
							if fallback_servers[y][z] == 4 then
								localized.resty_shdict = 1
								cached = fallback_servers[y][2]
								if cached then
									master_break = true
									break
								end
							end
							if fallback_servers[y][z] == 5 then
								--localized.ngx_log(localized.ngx_LOG_TYPE, " redis - " .. localized.tostring(check_resty_redis_fast()) )
								if check_resty_redis_fast() then
									localized.libcached = localized.require("resty.redis.fast")
									cached = localized.libcached:new()
									localized.resty_redis = 1
								else
									if logging == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "There is a problem with the library you are trying to use for cache storage. Please make sure you have included the library.")
									end
									return
								end
							end
							if fallback_servers[y][z] == 6 then
								--localized.ngx_log(localized.ngx_LOG_TYPE, " redis - " .. localized.tostring(check_resty_redis_cluster_fast()) )
								if check_resty_redis_cluster_fast() then
									localized.libcached = localized.require("resty.redis.cluster.fast")
									cached = localized.libcached:new()
									localized.resty_redis = 1
								else
									if logging == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "There is a problem with the library you are trying to use for cache storage. Please make sure you have included the library.")
									end
									return
								end
							end
							if fallback_servers[y][z] == 7 then
								--localized.ngx_log(localized.ngx_LOG_TYPE, " memcached - " .. localized.tostring(check_resty_memcached_fast()) )
								if check_resty_memcached_fast() then
									localized.libcached = localized.require("resty.memcached.fast")
									cached = localized.libcached:new()
									localized.resty_memcached = 1
								else
									if logging == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "There is a problem with the library you are trying to use for cache storage. Please make sure you have included the library.")
									end
									return
								end
							end
							if fallback_servers[y][z] == 8 and fallback_servers[y][12] ~= nil then
								--localized.ngx_log(localized.ngx_LOG_TYPE, " memcached - " .. localized.tostring(check_redis_cluster()) )
								if check_redis_cluster() then
									localized.libcached = localized.require("rediscluster")
									cached = localized.libcached:new(fallback_servers[y][12]) --12th var libconoptions
									localized.resty_redis = 1
								else
									if logging == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "There is a problem with the library you are trying to use for cache storage. Please make sure you have included the library.")
									end
									return
								end
							end
						end
						if z == 2 then
							--ip address or socket
							libconaddr = fallback_servers[y][z]
						end
						if z == 3 then
							--port
							libconport = fallback_servers[y][z]
						end
						if z == 4 then
							--connect_timeout
							connect_timeout = fallback_servers[y][z]
						end
						if z == 5 then
							--send_timeout
							send_timeout = fallback_servers[y][z]
						end
						if z == 6 then
							--read_timeout
							read_timeout = fallback_servers[y][z]
						end
						if z == 7 then
							--keepalive max_idle_timeout
							max_idle_timeout = fallback_servers[y][z]
						end
						if z == 8 then
							--keepalive pool_size
							pool_size = fallback_servers[y][z]
						end
						if z == 9 then
							auth_user = fallback_servers[y][z]
						end
						if z == 10 then
							auth_pass = fallback_servers[y][z]
						end
						if z == 12 then
							libconoptions = fallback_servers[y][z]
						end
						if z == 13 then
							close_connection = fallback_servers[y][z]
						end
						if localized.resty_redis == 1 or localized.resty_memcached == 1 then
							if connect_server(connect_timeout, send_timeout, read_timeout, libconaddr, libconport, max_idle_timeout, pool_size, auth_user, auth_pass, libconoptions) == true then
								master_break = true
								break
							end
						end
					end
				end
			end
		end
		if max_idle_timeout ~= nil and pool_size ~= nil then
			if localized.dummy == nil then
				localized.dummy = {}
			end
			localized.dummy[input_table] = cached
			localized.dummy[input_table].max_idle_timeout = max_idle_timeout
			localized.dummy[input_table].pool_size = pool_size
		end
		if close_connection ~= nil then
			if localized.dummy == nil then
				localized.dummy = {}
			end
			localized.dummy[input_table] = cached
			localized.dummy[input_table].close_connection = close_connection
		end
	end
	localized[input_table] = cached
	return cached --all checks passed
end

local function close_connection(method)
	if localized.anti_ddos_table() ~= nil and #localized.anti_ddos_table() > 0 and localized.dummy ~= nil and method == nil then
		for i=1,#localized.anti_ddos_table() do --for each host/path in our table
			local v = localized.anti_ddos_table()[i]
			if faster_than_match(v[1]) or localized.string_find(localized.URL(), v[1]) then --if our host matches one in the table
				if localized.request_limit == nil then
					localized.request_limit = remote_cache(v[19], v[7])
					--localized.request_limit = v[19] or nil --What ever memory space your server has set / defined for this to use
				end
				if localized.blocked_addr == nil then
					localized.blocked_addr = remote_cache(v[20], v[7])
					--localized.blocked_addr = v[20] or nil
				end
				if localized.ddos_counter == nil then
					localized.ddos_counter = remote_cache(v[21], v[7])
					--localized.ddos_counter = v[21] or nil
				end
				if localized.request_limit ~= nil and localized.blocked_addr ~= nil and localized.ddos_counter ~= nil then
					if localized.resty_redis == 1 or localized.resty_memcached == 1 then
						if localized.dummy ~= nil then
							local tab_request_limit, tab_blocked_addr, tab_ddos_counter, tab_logging = v[19], v[20], v[21], v[7]
							--keepalive
							remote_cache(tab_request_limit, tab_logging, 1)
							remote_cache(tab_blocked_addr, tab_logging, 1)
							remote_cache(tab_ddos_counter, tab_logging, 1)
							--close_connection
							remote_cache(tab_request_limit, tab_logging, nil, 1)
							remote_cache(tab_blocked_addr, tab_logging, nil, 1)
							remote_cache(tab_ddos_counter, tab_logging, nil, 1)
						end
					end
				end
				break
			end
		end
	end
	if localized.content_cache() ~= nil and #localized.content_cache() > 0 and localized.dummy ~= nil and method == 1 then
		for i=1,#localized.content_cache() do --for each host/path in our table
			local v = localized.content_cache()[i]
			if faster_than_match(v[1]) or localized.string_find(localized.URL(), v[1]) then --if our host matches one in the table
				if localized.resty_redis == 1 or localized.resty_memcached == 1 then
					if localized.dummy ~= nil then
						local tab_cached, tab_logging = v[3], v[5]
						--keepalive
						remote_cache(tab_cached, tab_logging, 1)
						--close_connection
						remote_cache(tab_cached, tab_logging, nil, 1)
					end
				end
				break
			end
		end
	end
end

local function WAF_Checks()
if localized.WAF_Runs ~= nil then --only run once
	return
end
if localized.remote_addr() == "auto" then
	if localized.ngx_var_http_cf_connecting_ip() ~= nil then
		if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
			localized.remote_addr = function() return localized.ngx_var_http_cf_connecting_ip() end
		else --you are not really cloudflare dont pretend you are to bypass flood protection
			localized.remote_addr = function() return localized.ngx_var_remote_addr() end
		end
	elseif localized.ngx_var_http_x_forwarded_for() ~= nil then
		if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
			localized.remote_addr = function() return localized.ngx_var_http_x_forwarded_for() end
		else
			localized.remote_addr = function() return localized.ngx_var_remote_addr() end
		end
	else
		localized.remote_addr = function() return localized.ngx_var_remote_addr() end
	end
end
if localized.remote_addr() == "tor" then
	localized.remote_addr = function() return localized.tor_remote_addr() end
	if localized.tor_remote_addr() == "auto" then
		localized.remote_addr = function() return localized.ngx_var_remote_addr() end
		localized.tor_remote_addr = function() return localized.ngx_var_remote_addr() end
	end
end
--[[WAF Web Application Firewall POST Request arguments filter]]
local function WAF_Post_Requests()
	--if localized.next(localized.WAF_POST_Request_table) ~= nil then --Check Post filter table has rules inside it
	if localized.WAF_POST_Request_table ~= nil and #localized.WAF_POST_Request_table > 0 and localized.ngx.req.get_method() == "POST" then --Check Post filter table has rules inside it

		localized.ngx_req_read_body() --Grab the request Body
		local request_body = localized.ngx_req_get_body_data()
		local read_request_body_args = (request_body or "") --Put the request body arguments into a variable
		local args = nil
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
			local function check_ngx_io()
				if localized.cached_ngx_io ~= nil then
					return localized.cached_ngx_io
				end
				localized.cached_ngx_io = localized.pcall(localized.require, "ngx.io") --check if ngx.io library exists will be true or false
				return localized.cached_ngx_io
			end
			if check_ngx_io() and localized.read_file == nil then
				local read_file = localized.require("ngx.io")
				localized.read_file = read_file.open
			end
			if not check_ngx_io() and localized.read_file == nil then
				localized.read_file = io.open
			end
			local fh, err = localized.read_file(request_body_file, "r")
			if err then
				localized.ngx_status = localized.ngx_HTTP_INTERNAL_SERVER_ERROR
				localized.ngx_log(localized.ngx_LOG_TYPE, "error reading request_body_file:", err)
				return
			end
			request_body = fh:read("*a")
			fh:close()
		end
		if request_body == nil then
			--request_body = "" --set to empty string
			args = (localized.ngx_decode_args(read_request_body_args) or "") --Put the Post args in to a table
		else
			args = (localized.ngx_decode_args(request_body) or "") --Put the Post args in to a table
		end

		if localized.next(args) ~= nil then --Check Post args table has contents
		--if #args > 0 then --Check Post args table has contents

			local arguement1 = nil --create empty variable
			local arguement2 = nil --create empty variable

			for key, value in localized.next, args do
				if localized.type(value) ~= "table" then
					for i=1,#localized.WAF_POST_Request_table do
						arguement1 = nil --reset to nil each loop
						arguement2 = nil --reset to nil each loop
						local value = localized.WAF_POST_Request_table[i] --put table value into variable
						local argument_name = value[1] or "" --get the WAF TABLE argument name or empty
						local argument_value = value[2] or "" --get the WAF TABLE arguement value or empty
						local args_name = localized.tostring(key) or "" --variable to store POST data argument name
						local args_value = localized.tostring(key) or "" --variable to store POST data argument value
						--local args_value = localized.string_gsub(args_value, "[^A-Za-z0-9_.-]", function(c) return localized.string_format("%%%02X", localized.string_byte(c)) end)
						local args_value = localized.ngx.escape_uri(args_value,2)
						if args_name ~= "" and args_name ~= "nil" then
							if localized.string_find(args_name, argument_name) then --if the argument name in my table matches the one in the POST request
								arguement1 = 1
							end
						end
						if args_value ~= "" and args_value ~= "nil" then
							if localized.string_find(args_value, argument_value) then --if the argument value in my table matches the one the POST request
								arguement2 = 1
							end
						end
						if arguement1 and arguement2 then --if what would of been our empty vars have been changed to not empty meaning a WAF match then block the request
							localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked Request POST args prohibited : arg_name = " .. argument_name .. " - arg_value = " .. argument_value .. " - IP : " .. localized.remote_addr())
							close_connection()
							return localized.ngx_exit(localized.ngx_HTTP_FORBIDDEN) --deny user access
						end
					end
				else
					for z=1,#value do
						for i=1,#localized.WAF_POST_Request_table do
							arguement1 = nil --reset to nil each loop
							arguement2 = nil --reset to nil each loop
							local values = localized.WAF_POST_Request_table[i] --put table value into variable
							local argument_name = values[1] or "" --get the WAF TABLE argument name or empty
							local argument_value = values[2] or "" --get the WAF TABLE arguement value or empty
							local args_name = localized.tostring(key) or "" --variable to store Header data argument name
							local args_value = localized.tostring(value[z]) or ""
							--local args_value = localized.string_gsub(args_value, "[^A-Za-z0-9_.-]", function(c) return localized.string_format("%%%02X", localized.string_byte(c)) end)
							local args_value = localized.ngx.escape_uri(args_value,2)
							if args_name ~= "" and args_name ~= "nil" then
								if localized.string_find(args_name, argument_name) then --if the argument name in my table matches the one in the request
									arguement1 = 1
								end
							end
							if args_value ~= "" and args_value ~= "nil" then
								if localized.string_find(args_value, argument_value) then --if the argument value in my table matches the one the request
									arguement2 = 1
								end
							end
							if arguement1 and arguement2 then --if what would of been our empty vars have been changed to not empty meaning a WAF match then block the request
								localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked Request POST args prohibited : arg_name = " .. argument_name .. " - arg_value = " .. argument_value .. " - IP : " .. localized.remote_addr())
								close_connection()
								return localized.ngx_exit(localized.ngx_HTTP_FORBIDDEN) --deny user access
							end
						end
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
				if localized.type(value) ~= "table" then
					for i=1,#localized.WAF_Header_Request_table do
						arguement1 = nil --reset to nil each loop
						arguement2 = nil --reset to nil each loop
						local values = localized.WAF_Header_Request_table[i] --put table value into variable
						local argument_name = values[1] or "" --get the WAF TABLE argument name or empty
						local argument_value = values[2] or "" --get the WAF TABLE arguement value or empty
						local args_name = localized.tostring(key) or "" --variable to store Header data argument name
						local args_value = localized.tostring(argument_request_headers[args_name]) or ""
						if args_name ~= "" and args_name ~= "nil" then
							if localized.string_find(args_name, argument_name) then --if the argument name in my table matches the one in the request
								arguement1 = 1
							end
						end
						if args_value ~= "" and args_value ~= "nil" then
							if localized.string_find(args_value, argument_value) then --if the argument value in my table matches the one the request
								arguement2 = 1
							end
						end
						if arguement1 and arguement2 then --if what would of been our empty vars have been changed to not empty meaning a WAF match then block the request
							localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked Request Header prohibited : arg_name = " .. argument_name .. " - arg_value = " .. argument_value .. " - IP : " .. localized.remote_addr())
							close_connection()
							return localized.ngx_exit(localized.ngx_HTTP_FORBIDDEN) --deny user access
						end
					end
				else
					for z=1,#value do
						for i=1,#localized.WAF_Header_Request_table do
							arguement1 = nil --reset to nil each loop
							arguement2 = nil --reset to nil each loop
							local values = localized.WAF_Header_Request_table[i] --put table value into variable
							local argument_name = values[1] or "" --get the WAF TABLE argument name or empty
							local argument_value = values[2] or "" --get the WAF TABLE arguement value or empty
							local args_name = localized.tostring(key) or "" --variable to store Header data argument name
							local args_value = localized.tostring(value[z]) or ""
							if args_name ~= "" and args_name ~= "nil" then
								if localized.string_find(args_name, argument_name) then --if the argument name in my table matches the one in the request
									arguement1 = 1
								end
							end
							if args_value ~= "" and args_value ~= "nil" then
								if localized.string_find(args_value, argument_value) then --if the argument value in my table matches the one the request
									arguement2 = 1
								end
							end
							if arguement1 and arguement2 then --if what would of been our empty vars have been changed to not empty meaning a WAF match then block the request
								localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked Request Header prohibited : arg_name = " .. argument_name .. " - arg_value = " .. argument_value .. " - IP : " .. localized.remote_addr())
								close_connection()
								return localized.ngx_exit(localized.ngx_HTTP_FORBIDDEN) --deny user access
							end
						end
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
				if localized.type(value) ~= "table" then
					for i=1,#localized.WAF_query_string_Request_table do
						arguement1 = nil --reset to nil each loop
						arguement2 = nil --reset to nil each loop
						local value = localized.WAF_query_string_Request_table[i] --put table value into variable
						local argument_name = value[1] or "" --get the WAF TABLE argument name or empty
						local argument_value = value[2] or "" --get the WAF TABLE arguement value or empty
						local args_name = localized.tostring(key) or "" --variable to store query string data argument name
						local args_value = localized.tostring(args[args_name]) or "" --variable to store query string data argument value
						--local args_value = localized.string_gsub(args_value, "[^A-Za-z0-9_.-]", function(c) return localized.string_format("%%%02X", localized.string_byte(c)) end)
						local args_value = localized.ngx.escape_uri(args_value,2)
						if args_name ~= "" and args_name ~= "nil" then
							if localized.string_find(args_name, argument_name) then --if the argument name in my table matches the one in the request
								arguement1 = 1
							end
						end
						if args_value ~= "" and args_value ~= "nil" then
							if localized.string_find(args_value, argument_value) then --if the argument value in my table matches the one the request
								arguement2 = 1
							end
						end
						if arguement1 and arguement2 then --if what would of been our empty vars have been changed to not empty meaning a WAF match then block the request
							localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked Request Query String prohibited : arg_name = " .. argument_name .. " - arg_value = " .. argument_value .. " - IP : " .. localized.remote_addr())
							close_connection()
							return localized.ngx_exit(localized.ngx_HTTP_FORBIDDEN) --deny user access
						end
					end
				else
					for z=1,#value do
						for i=1,#localized.WAF_query_string_Request_table do
							arguement1 = nil --reset to nil each loop
							arguement2 = nil --reset to nil each loop
							local values = localized.WAF_query_string_Request_table[i] --put table value into variable
							local argument_name = values[1] or "" --get the WAF TABLE argument name or empty
							local argument_value = values[2] or "" --get the WAF TABLE arguement value or empty
							local args_name = localized.tostring(key) or "" --variable to store Header data argument name
							local args_value = localized.tostring(value[z]) or ""
							--local args_value = localized.string_gsub(args_value, "[^A-Za-z0-9_.-]", function(c) return localized.string_format("%%%02X", localized.string_byte(c)) end)
							local args_value = localized.ngx.escape_uri(args_value,2)
							if args_name ~= "" and args_name ~= "nil" then
								if localized.string_find(args_name, argument_name) then --if the argument name in my table matches the one in the request
									arguement1 = 1
								end
							end
							if args_value ~= "" and args_value ~= "nil" then
								if localized.string_find(args_value, argument_value) then --if the argument value in my table matches the one the request
									arguement2 = 1
								end
							end
							if arguement1 and arguement2 then --if what would of been our empty vars have been changed to not empty meaning a WAF match then block the request
								localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked Request Query String prohibited : arg_name = " .. argument_name .. " - arg_value = " .. argument_value .. " - IP : " .. localized.remote_addr())
								close_connection()
								return localized.ngx_exit(localized.ngx_HTTP_FORBIDDEN) --deny user access
							end
						end
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
		Because localized.ngx.var.uri is a bit stupid I strip the query string of the request uri.
		The reason for this it is subject to normalisation
		Consecutive / characters are replace by a single / 
		and URL encoded characters are decoded 
		but then your back end webserver / application recieve the encoded uri!?
		So to keep the security strong I match the same version your web application would need protecting from (Yes the encoded copy that could contain malicious / exploitable contents)
		]]
		local args = localized.string_gsub(localized.request_uri(), "?.*", "") --remove the query string from the uri
		if args ~= nil and args ~= "" and args ~= "nil" and args ~= "/" then
			for i=1,#localized.WAF_URI_Request_table do --for each host in our table
				local v = localized.WAF_URI_Request_table[i]
				if faster_than_match(v[1]) or localized.string_find(localized.URL(), v[1]) then --if our host matches one in the table
					if localized.string_find(args, v[2]) then
						localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked Request URI prohibited : " .. localized.URL() .. " - IP : " .. localized.remote_addr())
						close_connection()
						return localized.ngx_exit(localized.ngx_HTTP_FORBIDDEN) --deny user access
					end
				end
			end
		end
	end
end
WAF_URI_Request()
--[[End WAF Web Application Firewall URI Request arguments filter]]
localized.WAF_Runs = 1
end
--WAF_Checks()

localized.get_resp_content_type_counter = 0
local function get_resp_content_type(forced) --incase content-type header not yet exists grab it
	local resp_content_type = nil
	if forced == nil then
		localized.get_resp_content_type_counter = localized.get_resp_content_type_counter+1
		if localized.ngx.header["content-type"] then
			--localized.ngx_log(localized.ngx_LOG_TYPE, " localized.ngx.header['content-type'] " .. localized.ngx.header["content-type"] )
			resp_content_type = localized.ngx.header["content-type"]
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
	local res = localized.ngx.location.capture(localized.uri(), {
		method = map["HEAD"],
		args = localized.ngx_var_args(),
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
	localized.ngx.header["content-type"] = resp_content_type --set header as content-type be either nil or the content-type
	localized.get_resp_content_type_counter = localized.get_resp_content_type_counter+2 --make sure we dont run again
	return resp_content_type
end
--localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Content-Type header is. " .. get_resp_content_type() )
--get_resp_content_type()

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

localized.table_union_seen = localized.table_union_seen or {}
localized.table_union_gen = localized.table_union_gen or 0
local function TableConcat(t1, t2)
	local len1 = #t1
	local len2 = #t2
	if len2 == 0 then return t1 end

	-- Grab our permanent tracking structures from the namespace
	local seen = localized.table_union_seen

	-- Increment the Generation-ID register (Safely wraps automatically at integer limits)
	local gen_id = localized.table_union_gen + 1
	localized.table_union_gen = gen_id

	-- Map existing t1 elements directly into the lookup array using our dynamic gen_id
	for i = 1, len1 do
		seen[t1[i]] = gen_id
	end

	-- Stream t2 variables using direct hardware register counters
	local idx = len1
	for i = 1, len2 do
		local val = t2[i]

		-- Instant O(1) matching evaluation replaces both the has_value and the cleanup loops
		if seen[val] ~= gen_id then
			seen[val] = gen_id
			idx = idx + 1
			t1[idx] = val
		end
	end

	-- The tracking map clears itself implicitly on the subsequent function call via gen_id incrementation
	return t1
end

--XOR Encryption/Decryption
if localized.ffi then
	-- Initialize your type anchors safely inside a persistent subsystem structure
	localized.ffi_types = localized.ffi_types or {
		uint8_ptr_t  = localized.ffi.typeof("uint8_t*"),
		uint32_ptr_t = localized.ffi.typeof("uint32_t*"),
		uint64_ptr_t = localized.ffi.typeof("uint64_t*"),
		char_array_t = localized.ffi.typeof("char[?]")
	}
	-- Detect system architecture width at startup
	localized.is_64bit = localized.ffi.abi("64bit")
end

local function xor_crypt(data, key)
	local len = #data
	local key_len = #key
	if len == 0 or key_len == 0 then return data end

	local ffi_lib = localized.ffi
	local types = localized.ffi_types

	-- Safe fallback check if the FFI layer or its cached types are missing
	if not ffi_lib or not types then
		local bxor = localized.bit_bxor
		local str_byte = localized.string_byte
		local str_char = localized.string_char
		local t_concat = localized.table_concat
		local key_bytes = {}
		for i = 1, key_len do key_bytes[i] = str_byte(key, i) end
		local t = {}
		for i = 1, len do
			local key_byte = key_bytes[((i - 1) % key_len) + 1]
			t[i] = str_char(bxor(str_byte(data, i), key_byte))
		end
		return t_concat(t)
	end

	-- Extract types out of our validated subsystem safe zone
	local uint8_ptr_t  = types.uint8_ptr_t
	local char_array_t = types.char_array_t
	local bxor          = localized.bit_bxor

	-- Pre-allocate exactly the right number of bytes in raw memory buffer space
	local buffer = ffi_lib.new(char_array_t, len)
	local key_src = ffi_lib.cast(uint8_ptr_t, key)

	if key_len == 4 or key_len == 8 then

		-- --- PATH A: 64-Bit Core Fast Path Execution ---
		if localized.is_64bit and types.uint64_ptr_t then
			local key_word = ffi_lib.new("uint64_t", 0)
			local kw_bytes = ffi_lib.cast(uint8_ptr_t, key_word)
			for i = 0, 7 do kw_bytes[i] = key_src[i % key_len] end

			local src64 = ffi_lib.cast(types.uint64_ptr_t, data)
			local dst64 = ffi_lib.cast(types.uint64_ptr_t, buffer)
			local num_words = localized.math_floor(len / 8)

			local mask = key_word
			for i = 0, num_words - 1 do
				dst64[i] = ffi_lib.bit.bxor(src64[i], mask)
			end

			local trailing_start = num_words * 8
			if trailing_start < len then
				local src8 = ffi_lib.cast(uint8_ptr_t, data)
				local dst8 = ffi_lib.cast(uint8_ptr_t, buffer)
				local k_idx = trailing_start % key_len
				for i = trailing_start, len - 1 do
					dst8[i] = bxor(src8[i], key_src[k_idx])
					k_idx = (k_idx + 1) % key_len
				end
			end
			return ffi_lib.string(buffer, len)

		-- --- PATH B: 32-Bit Core Fast Path Execution ---
		elseif types.uint32_ptr_t then
			local key_word = ffi_lib.new("uint32_t", 0)
			local kw_bytes = ffi_lib.cast(uint8_ptr_t, key_word)
			for i = 0, 3 do kw_bytes[i] = key_src[i % key_len] end

			local src32 = ffi_lib.cast(types.uint32_ptr_t, data)
			local dst32 = ffi_lib.cast(types.uint32_ptr_t, buffer)
			local num_words = localized.math_floor(len / 4)

			local mask = key_word
			for i = 0, num_words - 1 do
				dst32[i] = ffi_lib.bit.bxor(src32[i], mask)
			end

			local trailing_start = num_words * 4
			if trailing_start < len then
				local src8 = ffi_lib.cast(uint8_ptr_t, data)
				local dst8 = ffi_lib.cast(uint8_ptr_t, buffer)
				local k_idx = trailing_start % key_len
				for i = trailing_start, len - 1 do
					dst8[i] = bxor(src8[i], key_src[k_idx])
					k_idx = (k_idx + 1) % key_len
				end
			end
			return ffi_lib.string(buffer, len)
		end
	end

	local src = ffi_lib.cast(uint8_ptr_t, data)
	local dst = ffi_lib.cast(uint8_ptr_t, buffer)
	local data_idx = 0
	local chunk_limit = len - key_len

	while data_idx <= chunk_limit do
		for k_idx = 0, key_len - 1 do
			dst[data_idx + k_idx] = bxor(src[data_idx + k_idx], key_src[k_idx])
		end
		data_idx = data_idx + key_len
	end

	if data_idx < len then
		local k_idx = 0
		for i = data_idx, len - 1 do
			dst[i] = bxor(src[i], key_src[k_idx])
			k_idx = k_idx + 1
		end
	end

	return ffi_lib.string(buffer, len)
end


local function secure_storage(get_or_set, input, compress_type)
	if localized.ss ~= nil and localized.ss[input] ~= nil then
		return localized.ss[input] --cached secure storage output
	end
	--compress_type nil or 1 = compress 2 = decompress

	local function check_restyaes()
		if localized.cached_restyaes ~= nil then
			return localized.cached_restyaes
		end
		localized.cached_restyaes = localized.pcall(localized.require, "resty.aes") --check if resty.aes library exists will be true or false
		--https://github.com/openresty/lua-resty-string#synopsis
		return localized.cached_restyaes
	end
	local function check_lualzw()
		if localized.cached_lualzw ~= nil then
			return localized.cached_lualzw
		end
		localized.cached_lualzw = localized.pcall(localized.require, "lualzw") --check if lualzw library exists will be true or false
		--https://github.com/Rochet2/lualzw/blob/master/lualzw.lua
		--lua_package_path "./conf/lua/lualzw/?.lua;;";
		return localized.cached_lualzw
	end
	local function check_brotli()
		if localized.cached_brotli ~= nil then
			return localized.cached_brotli
		end
		localized.cached_brotli = localized.pcall(localized.require, "brotli.encoder") --check if brotli library exists will be true or false
		--choose a brotli ffi package thats nonblocking/asynchronous
		--https://github.com/sjnam/luajit-brotli#installation
		--lua_package_path "./conf/lua/brotli/?.lua;;";
		return localized.cached_brotli
	end
	local function check_zstd()
		if localized.cached_zstd ~= nil then
			return localized.cached_zstd
		end
		localized.cached_zstd = localized.pcall(localized.require, "zstd") --check if zstd library exists will be true or false
		--choose a zstd ffi package thats nonblocking/asynchronous
		--https://github.com/sjnam/luajit-zstd#installation
		--lua_package_path "./conf/lua/zstd/?.lua;;";
		return localized.cached_zstd
	end
	local function check_zlib()
		if localized.cached_zlib ~= nil then
			return localized.cached_zlib
		end
		localized.cached_zlib = localized.pcall(localized.require, "resty.zip") --check if zlib library exists will be true or false
		--choose a zlib ffi package thats nonblocking/asynchronous
		--https://github.com/doujiang24/lua-resty-zip
		return localized.cached_zlib
	end
	local function check_snappy()
		if localized.cached_snappy ~= nil then
			return localized.cached_snappy
		end
		localized.cached_snappy = localized.pcall(localized.require, "resty.snappy") --check if zlib library exists will be true or false
		--choose a snappy ffi package thats nonblocking/asynchronous
		--https://github.com/bungle/lua-resty-snappy/tree/master#installation
		--https://github.com/google/snappy
		return localized.cached_snappy
	end
	local function isnumber(value)
		return localized.tonumber(value) and true or false
	end
	local output = input or nil
	--attempt decryption before decompression
	if compress_type == 2 and localized.encrypt_storage == 1 and localized.encrypt_storage_secret ~= nil and localized.encrypt_storage_secret ~= "" then --xor encryption
		if localized.type(output) ~= "number" and isnumber(output) ~= true then
			output = xor_crypt(output, localized.encrypt_storage_secret)
		end
	end
	if compress_type == 2 and localized.encrypt_storage == 2 and localized.encrypt_storage_secret ~= nil and localized.encrypt_storage_secret ~= "" then --AES encryption
		if localized.type(output) ~= "number" and isnumber(output) ~= true and check_restyaes() then
			local aes = localized.require("resty.aes")
			local aes_encryption = aes:new(localized.encrypt_storage_secret)
			--the default cipher is AES 128 CBC with 1 round of MD5
			--for the key and a nil salt
			--you can change this to be more complex for example
			--local aes_encryption = aes:new(localized.encrypt_storage_secret,"MySalt!!", aes.cipher(256,"cbc"), aes.hash.sha512, 5)
			--AES 256 CBC with 5 rounds of SHA-512 for the key
			--and a salt of "MySalt!!"
			--Note: salt can be either nil or exactly 8 characters long
			if aes_encryption:decrypt(output) ~= nil then --pass input to be decrypted first
				output = aes_encryption:decrypt(output) --make output decrypted output
			end
		end
	end
	--end attempt decryption before decompression
	--start decompression
	if compress_type == 2 and localized.storage_compression == 1 and check_lualzw() then --LuaLZW decompression
		if localized.type(output) ~= "number" and isnumber(output) ~= true then
			local lualzw = localized.require("lualzw")
			local value_decompress, err = nil
			value_decompress, err = lualzw.decompress("c"..output)
			if err == nil then
				value_decompress = localized.string_sub(value_decompress, 2) --on success remove control char u
				output = value_decompress
			end
		end
	end
	if compress_type == 2 and localized.storage_compression == 2 and check_brotli() then --Brotli decompression
		if localized.type(output) ~= "number" and isnumber(output) ~= true then
			local brotli = localized.require("brotli.decoder")
			local decoder = brotli:new()
			local value_decompress, err = nil
			value_decompress, err = decoder:decompress(output)
			if err == nil then
				if decoder:isFinished() then
					decoder:destroy()
				end
				output = value_decompress
			end
		end
	end
	if compress_type == 2 and localized.storage_compression == 3 and check_zstd() then --ZSTD decompression
		if localized.type(output) ~= "number" and isnumber(output) ~= true then
			local zstandard = localized.require("zstd")
			local zstd = zstandard:new()
			local value_decompress, err = nil
			value_decompress, err = zstd:decompress(output)
			if err == nil then
				output = value_decompress
				zstd:free()
			end
		end
	end
	if compress_type == 2 and localized.storage_compression == 4 and check_zlib() then --Zlib decompression
		if localized.type(output) ~= "number" and isnumber(output) ~= true then
			local zlib = localized.require("resty.zip")
			local value_decompress, err = nil
			local zregex = "^/zs/(.*)/zs/"
			local zsize = localized.string_match(output, zregex)
			if zsize ~= nil then
				output = localized.string_gsub(output, zregex, "") --remove zsize from string
				value_decompress, err = zlib.uncompress(output, localized.tonumber(zsize)) --use original size to uncompress
				if err == nil then
					output = value_decompress
				end
			end
		end
	end
	if compress_type == 2 and localized.storage_compression == 5 and check_snappy() then --Snappy decompression
		if localized.type(output) ~= "number" and isnumber(output) ~= true then
			local snappy = localized.require("resty.snappy")
			local value_decompress, err = nil
			value_decompress, err = snappy.uncompress(output)
			if value_decompress then
				output = value_decompress
			end
		end
	end
	--end decompression
	--start compression
	if compress_type == nil and localized.storage_compression == 1 and check_lualzw() then --LuaLZW compression
		if localized.type(output) ~= "number" and isnumber(output) ~= true then
			if ((localized.storage_compression_min_size == 0 or localized.storage_compression_min_size == nil) and (localized.storage_compression_max_size == 0 or localized.storage_compression_max_size == nil)) or (#output > (localized.storage_compression_min_size or 0) and #output < (localized.storage_compression_max_size or 0)) or (#output > (localized.storage_compression_min_size or 0) and (localized.storage_compression_max_size == 0 or localized.storage_compression_max_size == nil)) or (#output < (localized.storage_compression_max_size or 0) and (localized.storage_compression_min_size == 0 or localized.storage_compression_min_size == nil)) then
			local lualzw = localized.require("lualzw")
			local value_compress, err = nil
			value_compress, err = lualzw.compress(output)
			if err == nil then
				value_compress = localized.string_sub(value_compress, 2) --on success remove control char c
				output = value_compress
			end
			end --size checks
		end
	end
	if compress_type == nil and localized.storage_compression == 2 and check_brotli() then --Brotli compression
		if localized.type(output) ~= "number" and isnumber(output) ~= true then
			if ((localized.storage_compression_min_size == 0 or localized.storage_compression_min_size == nil) and (localized.storage_compression_max_size == 0 or localized.storage_compression_max_size == nil)) or (#output > (localized.storage_compression_min_size or 0) and #output < (localized.storage_compression_max_size or 0)) or (#output > (localized.storage_compression_min_size or 0) and (localized.storage_compression_max_size == 0 or localized.storage_compression_max_size == nil)) or (#output < (localized.storage_compression_max_size or 0) and (localized.storage_compression_min_size == 0 or localized.storage_compression_min_size == nil)) then
			local brotli = localized.require("brotli.encoder")
			local encoder = brotli:new({quality=localized.storage_compression_ratio,}) --compress on level 0 lowest highest = level 11
			local value_compress, err = nil
			value_compress, err = encoder:compress(output)
			if err == nil then
				if encoder:isFinished() then
					encoder:destroy()
				end
				output = value_compress
			end
			end --size checks
		end
	end
	if compress_type == nil and localized.storage_compression == 3 and check_zstd() then --ZSTD compression
		if localized.type(output) ~= "number" and isnumber(output) ~= true then
			if ((localized.storage_compression_min_size == 0 or localized.storage_compression_min_size == nil) and (localized.storage_compression_max_size == 0 or localized.storage_compression_max_size == nil)) or (#output > (localized.storage_compression_min_size or 0) and #output < (localized.storage_compression_max_size or 0)) or (#output > (localized.storage_compression_min_size or 0) and (localized.storage_compression_max_size == 0 or localized.storage_compression_max_size == nil)) or (#output < (localized.storage_compression_max_size or 0) and (localized.storage_compression_min_size == 0 or localized.storage_compression_min_size == nil)) then
			local zstandard = localized.require("zstd")
			local zstd = zstandard:new()
			local value_compress, err = nil
			value_compress, err = zstd:compress(output, localized.storage_compression_ratio) --compress on level 1 lowest highest = level 22
			if err == nil then
				output = value_compress
				zstd:free()
			end
			end --size checks
		end
	end
	if compress_type == nil and localized.storage_compression == 4 and check_zlib() then --Zlib compression
		if localized.type(output) ~= "number" and isnumber(output) ~= true then
			if ((localized.storage_compression_min_size == 0 or localized.storage_compression_min_size == nil) and (localized.storage_compression_max_size == 0 or localized.storage_compression_max_size == nil)) or (#output > (localized.storage_compression_min_size or 0) and #output < (localized.storage_compression_max_size or 0)) or (#output > (localized.storage_compression_min_size or 0) and (localized.storage_compression_max_size == 0 or localized.storage_compression_max_size == nil)) or (#output < (localized.storage_compression_max_size or 0) and (localized.storage_compression_min_size == 0 or localized.storage_compression_min_size == nil)) then
			local zlib = localized.require("resty.zip")
			local value_compress, err = nil
			local zregex = "/zs/"
			value_compress, err = zlib.compress(output, localized.storage_compression_ratio) --compress on level 1 lowest highest = level 9
			if err == nil then
				value_compress = zregex .. #output .. zregex .. value_compress --store original size for use later
				output = value_compress
			end
			end --size checks
		end
	end
	if compress_type == nil and localized.storage_compression == 5 and check_snappy() then --Snappy compression
		if localized.type(output) ~= "number" and isnumber(output) ~= true then
			if ((localized.storage_compression_min_size == 0 or localized.storage_compression_min_size == nil) and (localized.storage_compression_max_size == 0 or localized.storage_compression_max_size == nil)) or (#output > (localized.storage_compression_min_size or 0) and #output < (localized.storage_compression_max_size or 0)) or (#output > (localized.storage_compression_min_size or 0) and (localized.storage_compression_max_size == 0 or localized.storage_compression_max_size == nil)) or (#output < (localized.storage_compression_max_size or 0) and (localized.storage_compression_min_size == 0 or localized.storage_compression_min_size == nil)) then
			local snappy = localized.require("resty.snappy")
			local value_compress, err = nil
			local value_compress, err = snappy.compress(output)
			if value_compress then
				output = value_compress
			end
			end --size checks
		end
	end
	--end compression
	--start encryption
	if compress_type == nil and localized.encrypt_storage == 1 and localized.encrypt_storage_secret ~= nil and localized.encrypt_storage_secret ~= "" then --xor encryption
		if localized.type(output) ~= "number" and isnumber(output) ~= true then
			local encrypted = nil
			encrypted = xor_crypt(output, localized.encrypt_storage_secret)
			if get_or_set == 0 then --get = 0
				output = encrypted
			elseif get_or_set == 1 then --set = 1
				output = encrypted
			elseif get_or_set == 2 then --expire = 2
				output = encrypted
			elseif get_or_set == 3 then --ttl = 3
				output = encrypted
			elseif get_or_set == 4 then --value = 4
				output = encrypted
			else --undefined
				output = encrypted
			end
		else
			output = output
		end
	elseif compress_type == nil and localized.encrypt_storage == 2 and localized.encrypt_storage_secret ~= nil and localized.encrypt_storage_secret ~= "" then --AES encryption
		if localized.type(output) ~= "number" and isnumber(output) ~= true and check_restyaes() then
			local aes = localized.require("resty.aes")
			local aes_encryption = aes:new(localized.encrypt_storage_secret)
			--the default cipher is AES 128 CBC with 1 round of MD5
			--for the key and a nil salt
			--you can change this to be more complex for example
			--local aes_encryption = aes:new(localized.encrypt_storage_secret,"MySalt!!", aes.cipher(256,"cbc"), aes.hash.sha512, 5)
			--AES 256 CBC with 5 rounds of SHA-512 for the key
			--and a salt of "MySalt!!"
			--Note: salt can be either nil or exactly 8 characters long
			local encrypted = nil
			if aes_encryption:decrypt(output) ~= nil then --pass input to be decrypted first
				encrypted = aes_encryption:decrypt(output)
			else
				encrypted = aes_encryption:encrypt(output)
			end
			if get_or_set == 0 then --get = 0
				output = encrypted
			elseif get_or_set == 1 then --set = 1
				output = encrypted
			elseif get_or_set == 2 then --expire = 2
				output = encrypted
			elseif get_or_set == 3 then --ttl = 3
				output = encrypted
			elseif get_or_set == 4 then --value = 4
				output = encrypted
			else --undefined
				output = encrypted
			end
		else
			output = output
		end
	elseif compress_type == nil and localized.encrypt_storage == 0 or localized.encrypt_storage == nil or localized.encrypt_storage_secret == nil or localized.encrypt_storage_secret == "" then --no encryption
		output = output
	end
	--end encryption
	if localized.ss == nil then
		localized.ss = {}
	end
	localized.ss[input] = output --cache output
	return output
end

local function internal_header_setup()
	if localized.anti_ddos_table() ~= nil and #localized.anti_ddos_table() > 0 then --do ip block checks before we bother generating headers
		for i=1,#localized.anti_ddos_table() do --for each host/path in our table
			local v = localized.anti_ddos_table()[i]
			if faster_than_match(v[1]) or localized.string_find(localized.URL(), v[1]) then --if our host matches one in the table
				--if localized.request_limit == nil then
					--localized.request_limit = remote_cache(v[19], v[7])
					--localized.request_limit = v[19] or nil --What ever memory space your server has set / defined for this to use
				--end
				if localized.blocked_addr == nil then
					localized.blocked_addr = remote_cache(v[20], v[7])
					--localized.blocked_addr = v[20] or nil
				end
				if localized.ddos_counter == nil then
					localized.ddos_counter = remote_cache(v[21], v[7])
					--localized.ddos_counter = v[21] or nil
				end
				if localized.blocked_addr ~= nil and localized.ddos_counter ~= nil then
					local rate_limit_window = v[8]
					local block_duration = v[10]
					local rate_limit_exit_status = v[11]

					local total_requests = localized.ddos_counter:get(secure_storage(0, "blocked_ip")) or 0
					if total_requests == nil or total_requests == localized.ngx.null then
						total_requests = 0
					end
					if total_requests ~= nil then
						total_requests = localized.tonumber(total_requests)
					end
					if v[33] == 1 then
						if total_requests > v[24] then --Automatically enable I am Under Attack Mode so disable logging
							v[7] = 0 --disable logging to prevent denial of service from excessive log file writes using up disk I/O
						end
					end

					--start real ip block
					local ip = localized.ngx_var_remote_addr()
					local blocked_time = localized.blocked_addr:get(secure_storage(0, ip)) --if for some reason their real ip is in the block list block them else fall back to other checks
					if blocked_time and blocked_time ~= localized.ngx.null then

						--stats total blocked requests in rate limit window
						local incr = localized.ddos_counter:get(secure_storage(0, "blocked_total_traffic")) or nil
						if incr == nil or incr == localized.ngx.null then
							if localized.resty_redis == 1 then
								localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, 1))
								localized.ddos_counter:expire(secure_storage(2, "blocked_total_traffic"), rate_limit_window)
							else
								localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, 1), rate_limit_window)
							end
						else
							local incr = localized.ddos_counter:get(secure_storage(0, "blocked_total_traffic"))
							if localized.resty_redis == 1 then
								localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, incr+1))
								if v[45] == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
									--localized.ddos_counter:expire(secure_storage(2, "blocked_total_traffic"), localized.ddos_counter:ttl(secure_storage(3, "blocked_total_traffic"))) --no support for ttl yet ?
									localized.ddos_counter:expire(secure_storage(2, "blocked_total_traffic"), rate_limit_window)
								else
									localized.ddos_counter:expire(secure_storage(2, "blocked_total_traffic"), rate_limit_window)
								end
							else
								if v[45] == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
									if localized.resty_memcached == 1 then
										localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, incr+1), rate_limit_window)
									elseif localized.resty_lrucache == 1 then
										localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, incr+1), rate_limit_window)
									else
										localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, incr+1), localized.ddos_counter:ttl(secure_storage(3, "blocked_total_traffic")))
									end
								else
									localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, incr+1), rate_limit_window)
								end
							end
							if incr ~= nil then
								incr = localized.tonumber(incr)
							end
							--localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] requests = " .. incr .. " - Max requests = " .. v[43])
							if v[33] == 1 then
								if v[43] ~= nil and incr > v[43] then
									v[7] = 0 --disable logging to prevent denial of service from excessive log file writes using up disk I/O
								end
							end
						end

						if v[7] == 1 then
							if v[23] == 1 or v[23] == 0 then
								if total_requests < v[24] then --Less than required amount to trigger Automatically enable I am Under Attack Mode so enable logging
									--localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) Blocked IP attempt: " .. ip .. " - URL : " .. localized.URL() )
									if v[44] ~= nil and v[44] == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) Blocked IP attempt: " .. ip .. " - URL : " .. localized.URL() .. " - Ban extended/ends on : " .. localized.ngx_cookie_time(blocked_time+block_duration) ) --ngx_cookie_time can be slow dont use this under attack
									else
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) Blocked IP attempt: " .. ip .. " - URL : " .. localized.URL() .. " - Ban ends on : " .. localized.ngx_cookie_time(blocked_time+block_duration) ) --ngx_cookie_time can be slow dont use this under attack
									end
								end
							end
						end
						if v[44] ~= nil and v[44] == 1 then
							if localized.resty_redis == 1 then
								localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime))
								localized.blocked_addr:expire(secure_storage(2, ip), block_duration)
							else
								localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime), block_duration) --update with current time to extend ban duration
							end
						end
						if rate_limit_exit_status ~= 444 and rate_limit_exit_status ~= 204 then --no point with gzip on these
							localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip --this can slow down nginx tested via 100,000,000 requests nulled out on the block pages
						end
						close_connection()
						return localized.ngx_exit(rate_limit_exit_status)
					end
					--end real ip
					--concatenate tables make sure both these tables are the same
					if localized.ip_whitelist ~= nil and #localized.ip_whitelist ~= 0 and localized.auto_add_server_ip_to_merged_tables ~= 0 and localized.merge_proxy_and_ip_whitelist == 0 then
						localized.ip_whitelist[#localized.ip_whitelist+1] = localized.ngx_var_server_addr() --make sure our own server address is whitelisted just incase
					end
					if localized.proxy_header_table ~= nil and #localized.proxy_header_table ~= 0 and localized.auto_add_server_ip_to_merged_tables ~= 0 and localized.merge_proxy_and_ip_whitelist == 0 then
						localized.proxy_header_table[#localized.proxy_header_table+1] = localized.ngx_var_server_addr() --make sure our own server address is whitelisted just incase
					end
					if localized.ip_whitelist ~= nil and localized.proxy_header_table ~= nil and #localized.ip_whitelist ~= 0 and #localized.proxy_header_table ~= 0 and localized.merge_proxy_and_ip_whitelist ~= 0 then
						localized.merge_table = TableConcat(localized.ip_whitelist, localized.proxy_header_table)
						if localized.auto_add_server_ip_to_merged_tables ~= 0 then
							localized.merge_table[#localized.merge_table+1] = localized.ngx_var_server_addr() --make sure our own server address is whitelisted just incase
						end
						localized.ip_whitelist = localized.merge_table
						localized.proxy_header_table = localized.merge_table
					end
					local ip = v[22]
					if ip == "auto" then
						if localized.ngx_var_http_cf_connecting_ip() ~= nil then
							if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
								ip = localized.ngx_var_http_cf_connecting_ip()
							else --you are not really cloudflare dont pretend you are to bypass flood protection
								ip = localized.ngx_var_remote_addr()
							end
						elseif localized.ngx_var_http_x_forwarded_for() ~= nil then
							if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
								ip = localized.ngx_var_http_x_forwarded_for()
							else
								ip = localized.ngx_var_remote_addr()
							end
						else
							ip = localized.ngx_var_remote_addr()
						end
					end
					local blocked_time = localized.blocked_addr:get(secure_storage(0, ip))
					if blocked_time and blocked_time ~= localized.ngx.null then

						--stats total blocked requests in rate limit window
						local incr = localized.ddos_counter:get(secure_storage(0, "blocked_total_traffic")) or nil
						if incr == nil or incr == localized.ngx.null then
							if localized.resty_redis == 1 then
								localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, 1))
								localized.ddos_counter:expire(secure_storage(2, "blocked_total_traffic"), rate_limit_window)
							else
								localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, 1), rate_limit_window)
							end
						else
							local incr = localized.ddos_counter:get(secure_storage(0, "blocked_total_traffic"))
							if localized.resty_redis == 1 then
								localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, incr+1))
								if v[45] == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
									--localized.ddos_counter:expire(secure_storage(2, "blocked_total_traffic"), localized.ddos_counter:ttl(secure_storage(3, "blocked_total_traffic"))) --no support for ttl yet ?
									localized.ddos_counter:expire(secure_storage(2, "blocked_total_traffic"), rate_limit_window)
								else
									localized.ddos_counter:expire(secure_storage(2, "blocked_total_traffic"), rate_limit_window)
								end
							else
								if v[45] == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
									if localized.resty_memcached == 1 then
										localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, incr+1), rate_limit_window)
									elseif localized.resty_lrucache == 1 then
										localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, incr+1), rate_limit_window)
									else
										localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, incr+1), localized.ddos_counter:ttl(secure_storage(3, "blocked_total_traffic")))
									end
								else
									localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, incr+1), rate_limit_window)
								end
							end
							if incr ~= nil then
								incr = localized.tonumber(incr)
							end
							--localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] requests = " .. incr .. " - Max requests = " .. v[43])
							if v[33] == 1 then
								if v[43] ~= nil and incr > v[43] then
									v[7] = 0 --disable logging to prevent denial of service from excessive log file writes using up disk I/O
								end
							end
						end

						if v[7] == 1 then
							if v[23] == 1 or v[23] == 0 then
								if total_requests < v[24] then --Less than required amount to trigger Automatically enable I am Under Attack Mode so enable logging
									--localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) Blocked IP attempt: " .. ip .. " - URL : " .. localized.URL() )
									if v[44] ~= nil and v[44] == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) Blocked IP attempt: " .. ip .. " - URL : " .. localized.URL() .. " - Ban extended/ends on : " .. localized.ngx_cookie_time(blocked_time+block_duration) ) --ngx_cookie_time can be slow dont use this under attack
									else
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) Blocked IP attempt: " .. ip .. " - URL : " .. localized.URL() .. " - Ban ends on : " .. localized.ngx_cookie_time(blocked_time+block_duration) ) --ngx_cookie_time can be slow dont use this under attack
									end
								end
							end
						end
						if v[44] ~= nil and v[44] == 1 then
							if localized.resty_redis == 1 then
								localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime))
								localized.blocked_addr:expire(secure_storage(2, ip), block_duration)
							else
								localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime), block_duration) --update with current time to extend ban duration
							end
						end
						if rate_limit_exit_status ~= 444 and rate_limit_exit_status ~= 204 then --no point with gzip on these
							localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip --this can slow down nginx tested via 100,000,000 requests nulled out on the block pages
						end
						close_connection()
						return localized.ngx_exit(rate_limit_exit_status)
					end
				end
				break
			end
		end
	end
	if localized.secret == " enigma" then --if its still default and unchanged by user
		localized.secret = localized.secret .. (function() local out = "" if localized.get_date_from_unix_cached ~= nil then out = localized.os_date("%W",localized.os_time_saved) end return out end)() --make more dynamic than default hopefully nobody does try to use default in production
		--you dont want this to change to frequently every time you change your secret key you will see users on a javascript puzzle page will need to pass auth again
	end
	--openresty have a simple version of this https://github.com/openresty/lua-nginx-module?tab=readme-ov-file#ngxreqis_internal but for old versions of nginx with lua i created this so backwards compatibility
	if localized.proxy_header_table ~= nil and #localized.proxy_header_table > 0 then --only set internal headers when proxy header checks are in use
		--internal header protection if the script needs to make a internal call like with the header_append_ip() / localized.send_ip_to_backend_custom_headers function we can track it.
		localized.ngx_var_http_internal_string = "1337"--internal bypass header value
		localized.ngx_var_http_internal_header_name = "internal" --internal bypass header name
		if localized.secret_encryption == nil or localized.secret_encryption == 1 then
			localized.ngx_var_http_internal_header_name = localized.ngx_hmac_sha1(localized.secret .. (function() local out = "" if localized.get_date_from_unix_cached ~= nil then out = localized.os_date("%W",localized.os_time_saved) end return out end)(), localized.ngx_var_http_internal_header_name) --encrypt this header so nobody can guess it or use it other than internal work calls
		else
			localized.ngx_var_http_internal_header_name = xor_crypt(localized.ngx_var_http_internal_header_name, localized.secret .. (function() local out = "" if localized.get_date_from_unix_cached ~= nil then out = localized.os_date("%W",localized.os_time_saved) end return out end)()) --encrypt this header so nobody can guess it or use it other than internal work calls
		end
		localized.ngx_var_http_internal_header_name = localized.ngx_encode_base64(localized.ngx_var_http_internal_header_name) --wrap encrypted header in base64
		localized.ngx_var_http_internal_header_name = localized.string_gsub(localized.ngx_var_http_internal_header_name, "[+/=]", "") --Remove +/=
		localized.ngx_var_http_internal = localized.ngx_req_get_headers()[localized.ngx_var_http_internal_header_name] or nil (function() local value = localized.ngx_var_http_internal if localized.type(value) == "table" then local output = nil for i=1, #value do output = value[i] end localized.ngx_var_http_internal = output else localized.ngx_var_http_internal = value end end)() --localized.ngx.var["http_"..localized.ngx_var_http_internal_header_name] or nil
		localized.ngx_var_http_internal_log = 0

		if localized.ngx_var_http_internal_log == 1 then --log the internal request headers
			localized.ngx_log(localized.ngx_LOG_TYPE, " internal header is - " .. localized.ngx_var_http_internal_header_name )
			if localized.ngx_var_http_internal ~= nil then --2nd layer
				for headerName, header in localized.next, localized.ngx_req_get_headers() do
					if localized.type(header) == "table" then
						for i=1,#header do
							localized.ngx_log(localized.ngx_LOG_TYPE, " 2nd layer " .. headerName .. " - " .. header[i] )
						end
					else
						localized.ngx_log(localized.ngx_LOG_TYPE, " 2nd layer " .. headerName .. " - " .. header )
					end
				end
			else --1st layer
				for headerName, header in localized.next, localized.ngx_req_get_headers() do
					if localized.type(header) == "table" then
						for i=1,#header do
							localized.ngx_log(localized.ngx_LOG_TYPE, " 1st layer " .. headerName .. " - " .. header[i] )
						end
					else
						localized.ngx_log(localized.ngx_LOG_TYPE, " 1st layer " .. headerName .. " - " .. header )
					end
				end
			end
		end
	end
end
internal_header_setup()

local function check_tor_onion()
	if localized.check_tor_onion_cached == nil then
		for i=1,#localized.check_privacy() do
			if localized.string_find(localized.string_lower(localized.check_privacy()[i][1]), localized.check_privacy()[i][2]) then
				localized.check_tor_onion_cached = true
				break
			else
				localized.check_tor_onion_cached = false
			end
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
		if localized.ip_whitelist_remote_addr() == "auto" then
			if localized.ngx_var_http_cf_connecting_ip() ~= nil then
				if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
					localized.ip_whitelist_remote_addr = function() return localized.ngx_var_http_cf_connecting_ip() end
				else --you are not really cloudflare dont pretend you are to bypass flood protection
					localized.ip_whitelist_remote_addr = function() return localized.ngx_var_remote_addr() end
				end
			elseif localized.ngx_var_http_x_forwarded_for() ~= nil then
				if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
					localized.ip_whitelist_remote_addr = function() return localized.ngx_var_http_x_forwarded_for() end
				else
					localized.ip_whitelist_remote_addr = function() return localized.ngx_var_remote_addr() end
				end
			else
				localized.ip_whitelist_remote_addr = function() return localized.ngx_var_remote_addr() end
			end
		end
		localized.ip_whitelist_flood_checks_count = localized.ip_whitelist_flood_checks_count+2 --make sure we dont run again
		if localized.static_exact_map == nil then
			localized.static_exact_map = {}
		end
		if localized.dynamic_cidr_rules == nil then
			localized.dynamic_cidr_rules = {}
		end
		if localized.dynamic_cidr_seen == nil then
			localized.dynamic_cidr_seen = {}
		end
		local rules_array = localized.dynamic_cidr_rules
		local rules_idx = #rules_array
		for i = 1, #ip_table do
			local v = ip_table[i]
			if not localized.dynamic_cidr_seen[v] then
				localized.dynamic_cidr_seen[v] = true
				if not localized.string_find(v, "/", 1, true) then
					localized.static_exact_map[v] = true
				else
					local rule = compile_cidr(v)
					if rule then
						rules_idx = rules_idx + 1
						rules_array[rules_idx] = rule
					else
						localized.dynamic_cidr_seen[v] = nil
					end
				end
			end
		end
		if ip_address_in_range(localized.ip_whitelist_remote_addr()) then
			localized.ip_whitelist_output_cached = false
			return false
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
	local function check_resty_shell()
		if localized.cached_restyshell ~= nil then
			return localized.cached_restyshell
		end
		localized.cached_restyshell = localized.pcall(localized.require, "resty.shell") --check if resty shell library exists will be true or false
		return localized.cached_restyshell
	end
	if check_resty_shell() and localized.os_exe == nil then
		local shell = localized.require("resty.shell")
		localized.os_exe = shell.run
	end
	if not check_resty_shell() and localized.os_exe == nil then
		localized.os_execute = io.popen --openresty xray shows this is cpu intensive so if user has resty.shell we use that above this is a fallback method
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
	if localized.anti_ddos_table() ~= nil and #localized.anti_ddos_table() > 0 then
		for i=1,#localized.anti_ddos_table() do
			if faster_than_match(localized.anti_ddos_table()[i][1]) or localized.string_find(localized.URL(), localized.anti_ddos_table()[i][1]) then --if our host matches one in the table
				local rate_limit_window = localized.anti_ddos_table()[i][8]
				local block_duration = localized.anti_ddos_table()[i][10]
				if localized.request_limit == nil then
					localized.request_limit = remote_cache(localized.anti_ddos_table()[i][19], localized.anti_ddos_table()[i][7])
					--localized.request_limit = localized.anti_ddos_table()[i][19] or nil --What ever memory space your server has set / defined for this to use
				end
				if localized.blocked_addr == nil then
					localized.blocked_addr = remote_cache(localized.anti_ddos_table()[i][20], localized.anti_ddos_table()[i][7])
					--localized.blocked_addr = localized.anti_ddos_table()[i][20] or nil
				end
				if localized.ddos_counter == nil then
					localized.ddos_counter = remote_cache(localized.anti_ddos_table()[i][21], localized.anti_ddos_table()[i][7])
					--localized.ddos_counter = localized.anti_ddos_table()[i][21] or nil
				end
				local ip = localized.anti_ddos_table()[i][22]
				if ip == "auto" then
					if localized.ngx_var_http_cf_connecting_ip() ~= nil then
						if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
							ip = localized.ngx_var_http_cf_connecting_ip()
						else --you are not really cloudflare dont pretend you are to bypass flood protection
							ip = localized.ngx_var_remote_addr()
						end
					elseif localized.ngx_var_http_x_forwarded_for() ~= nil then
						if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
							ip = localized.ngx_var_http_x_forwarded_for()
						else
							ip = localized.ngx_var_remote_addr()
						end
					else
						ip = localized.ngx_var_remote_addr()
					end
				end
				if check_tor_onion() then
					ip = localized.tor_remote_addr() --set ip as what the user wants the tor IP to be
					if localized.tor_remote_addr() == "auto" then
						ip = localized.ngx_var_remote_addr()
					end
				end
				if localized.request_limit ~= nil and localized.blocked_addr ~= nil and localized.ddos_counter ~= nil then --we can do so much more than the basic anti-ddos above
					if jsval ~= nil then
						if localized.jspuzzle_memory_zone == nil then
							localized.jspuzzle_memory_zone = remote_cache(localized.anti_ddos_table()[i][29], localized.anti_ddos_table()[i][7])
							--localized.jspuzzle_memory_zone = localized.anti_ddos_table()[i][29]
						end
						local jspuzzle_rate_limit_window = localized.anti_ddos_table()[i][30]
						local jspuzzle_request_limit = localized.anti_ddos_table()[i][31]
						if localized.jspuzzle_memory_zone ~= nil then
							local key = "pr" .. ip --set identifyer as pr and ip for to not use up to much memory
							local count = "" --create locals to use

							count = localized.jspuzzle_memory_zone:get(secure_storage(0, key)) or nil
							if count == nil or count == localized.ngx.null then
								if localized.resty_redis == 1 then
									localized.jspuzzle_memory_zone:set(secure_storage(1, key), secure_storage(4, 1))
									localized.jspuzzle_memory_zone:expire(secure_storage(2, key), jspuzzle_rate_limit_window)
								else
									localized.jspuzzle_memory_zone:set(secure_storage(1, key), secure_storage(4, 1), jspuzzle_rate_limit_window)
								end
							else
								count = localized.jspuzzle_memory_zone:get(secure_storage(0, key))
								if localized.resty_redis == 1 then
									localized.jspuzzle_memory_zone:set(secure_storage(1, key), secure_storage(4, count+1))
									if localized.anti_ddos_table()[i][45] == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
										--localized.jspuzzle_memory_zone:expire(secure_storage(2, key), localized.jspuzzle_memory_zone:ttl(secure_storage(3, key))) --no support for ttl yet ?
										localized.jspuzzle_memory_zone:expire(secure_storage(2, key), jspuzzle_rate_limit_window)
									else
										localized.jspuzzle_memory_zone:expire(secure_storage(2, key), jspuzzle_rate_limit_window)
									end
								else
									if localized.anti_ddos_table()[i][45] == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
										if localized.resty_memcached == 1 then
											localized.jspuzzle_memory_zone:set(secure_storage(1, key), secure_storage(4, count+1), jspuzzle_rate_limit_window)
										elseif localized.resty_lrucache == 1 then
											localized.jspuzzle_memory_zone:set(secure_storage(1, key), secure_storage(4, count+1), jspuzzle_rate_limit_window)
										else
											localized.jspuzzle_memory_zone:set(secure_storage(1, key), secure_storage(4, count+1), localized.jspuzzle_memory_zone:ttl(secure_storage(3, key)))
										end
									else
										localized.jspuzzle_memory_zone:set(secure_storage(1, key), secure_storage(4, count+1), jspuzzle_rate_limit_window)
									end
								end
								count = localized.jspuzzle_memory_zone:get(secure_storage(0, key))
							end
							if count ~= nil then
								count = localized.tonumber(count)
							end
							--Rate limit check
							if count ~= nil and count ~= localized.ngx.null then
								if count > jspuzzle_request_limit then
									if ip_whitelist_flood_checks(localized.ip_whitelist) and check_tor_onion() == false then --if true then block ip
										--Block IP
										if localized.resty_redis == 1 then
											localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime))
											localized.blocked_addr:expire(secure_storage(2, ip), block_duration)
										else
											localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime), block_duration)
										end
										if localized.anti_ddos_table()[i][32] ~= nil and localized.anti_ddos_table()[i][32] ~= "" then
											if #localized.anti_ddos_table()[i][32] > 0 then
												for o=1,#localized.anti_ddos_table()[i][32] do
													check_system(o, localized.anti_ddos_table()[i][32][o], localized.anti_ddos_table()[i][7], ip)
												end
											end
										end
										localized.blocked_address_check_count = localized.blocked_address_check_count+2
									end
									local incr = localized.ddos_counter:get(secure_storage(0, "blocked_ip")) or nil
									if incr == nil or incr == localized.ngx.null then
										if localized.resty_redis == 1 then
											localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, 1))
											localized.ddos_counter:expire(secure_storage(2, "blocked_ip"), block_duration)
										else
											localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, 1), block_duration)
										end
									else
										local incr = localized.ddos_counter:get(secure_storage(0, "blocked_ip"))
										if localized.resty_redis == 1 then
											localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, incr+1))
											if localized.anti_ddos_table()[i][45] == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
												--localized.ddos_counter:expire(secure_storage(2, "blocked_ip"), localized.ddos_counter:ttl(secure_storage(3, "blocked_ip"))) --no support for ttl yet ?
												localized.ddos_counter:expire(secure_storage(2, "blocked_ip"), block_duration)
											else
												localized.ddos_counter:expire(secure_storage(2, "blocked_ip"), block_duration)
											end
										else
											if localized.anti_ddos_table()[i][45] == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
												if localized.resty_memcached == 1 then
													localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, incr+1), block_duration)
												elseif localized.resty_lrucache == 1 then
													localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, incr+1), block_duration)
												else
													localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, incr+1), localized.ddos_counter:ttl(secure_storage(3, "blocked_ip")))
												end
											else
												localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, incr+1), block_duration)
											end
										end
									end
									if localized.anti_ddos_table()[i][7] == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, log_message .. count .. " - " .. ip)
									end
								end
							end
						end
					else
						if ip_whitelist_flood_checks(localized.ip_whitelist) and check_tor_onion() == false then --if true then block ip
							--Block IP
							if localized.resty_redis == 1 then
								localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime))
								localized.blocked_addr:expire(secure_storage(2, ip), block_duration)
							else
								localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime), block_duration)
							end
							if localized.anti_ddos_table()[i][32] ~= nil and localized.anti_ddos_table()[i][32] ~= "" then
								if #localized.anti_ddos_table()[i][32] > 0 then
									for o=1,#localized.anti_ddos_table()[i][32] do
										check_system(o, localized.anti_ddos_table()[i][32][o], localized.anti_ddos_table()[i][7], ip)
									end
								end
							end
							localized.blocked_address_check_count = localized.blocked_address_check_count+2
						end
						local incr = localized.ddos_counter:get(secure_storage(0, "blocked_ip")) or nil
						if incr == nil or incr == localized.ngx.null then
							if localized.resty_redis == 1 then
								localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, 1))
								localized.ddos_counter:expire(secure_storage(2, "blocked_ip"), block_duration)
							else
								localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, 1), block_duration)
							end
						else
							local incr = localized.ddos_counter:get(secure_storage(0, "blocked_ip"))
							if localized.resty_redis == 1 then
								localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, incr+1))
								if localized.anti_ddos_table()[i][45] == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
									--localized.ddos_counter:expire(secure_storage(2, "blocked_ip"), localized.ddos_counter:ttl(secure_storage(3, "blocked_ip"))) --no support for ttl yet ?
									localized.ddos_counter:expire(secure_storage(2, "blocked_ip"), block_duration)
								else
									localized.ddos_counter:expire(secure_storage(2, "blocked_ip"), block_duration)
								end
							else
								if localized.anti_ddos_table()[i][45] == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
									if localized.resty_memcached == 1 then
										localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, incr+1), block_duration)
									elseif localized.resty_lrucache == 1 then
										localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, incr+1), block_duration)
									else
										localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, incr+1), localized.ddos_counter:ttl(secure_storage(3, "blocked_ip")))
									end
								else
									localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, incr+1), block_duration)
								end
							end
						end
						if localized.anti_ddos_table()[i][7] == 1 then
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
	--local shdict = localized.pcall(localized.require, "resty.core.shdict") --check if resty core shdict function exists will be true or false

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
		local request_time = localized.ngx.now()-localized.ngx.req.start_time() --localized.ngx.var.request_time
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
					if localized.ngx_var_http_internal == nil then --1st layer
						WAF_Checks() --run WAF checks first
					end
					get_resp_content_type() --grab content-type incase does not exist
				end
				if localized.content_type_fix == false or localized.ngx.header["content-type"] then --the content type that the user is requesting to use a range header on
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
											if localized.string_find(localized.ngx.header["content-type"], range_table[i][x]) then
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
						if localized.ngx_var_http_internal == nil then --1st layer
							WAF_Checks() --run WAF checks first
						end
						get_resp_content_type() --grab content-type incase does not exist
					end
					if localized.content_type_fix == false or localized.ngx.header["content-type"] then --the content type that the user is requesting to use a range header on
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
												if localized.string_find(localized.ngx.header["content-type"], range_table[i][x]) then
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
	local function check_rate_limit(ip, rate_limit_window, rate_limit_requests, block_duration, request_limit, ddos_counter, logging, ip_extend)
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

			count = localized.request_limit:get(secure_storage(0, key)) or nil
			if count == nil or count == localized.ngx.null then
				if localized.resty_redis == 1 then
					localized.request_limit:set(secure_storage(1, key), secure_storage(4, 1))
					localized.request_limit:expire(secure_storage(2, key), rate_limit_window)
				else
					localized.request_limit:set(secure_storage(1, key), secure_storage(4, 1), rate_limit_window)
				end
				return false
			else
				count = localized.request_limit:get(secure_storage(0, key))
				if localized.resty_redis == 1 then
					localized.request_limit:set(secure_storage(1, key), secure_storage(4, count+1))
					if ip_extend == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
						--localized.request_limit:expire(secure_storage(2, key), localized.request_limit:ttl(secure_storage(3, key))) --no support for ttl yet ?
						localized.request_limit:expire(secure_storage(2, key), rate_limit_window)
					else
						localized.request_limit:expire(secure_storage(2, key), rate_limit_window)
					end
				else
					if ip_extend == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
						if localized.resty_memcached == 1 then
							localized.request_limit:set(secure_storage(1, key), secure_storage(4, count+1), rate_limit_window)
						elseif localized.resty_lrucache == 1 then
							localized.request_limit:set(secure_storage(1, key), secure_storage(4, count+1), rate_limit_window)
						else
							localized.request_limit:set(secure_storage(1, key), secure_storage(4, count+1), localized.request_limit:ttl(secure_storage(3, key)))
						end
					else
						localized.request_limit:set(secure_storage(1, key), secure_storage(4, count+1), rate_limit_window)
					end
				end
				count = localized.request_limit:get(secure_storage(0, key))
			end
		--end
		if count ~= nil then
			count = localized.tonumber(count)
		end

		--Rate limit check
		if count > rate_limit_requests then
			if logging == 1 then
				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Rate limit exceeded by IP: " .. ip .. " Max requests = " .. rate_limit_requests.. " client has made " .. count .. " requests")
			end

			--if shdict then --backwards compatibility for lua
				--local incr, err = localized.ddos_counter:incr("blocked_ip", 1, 0, block_duration)
				--if not incr then
					--if logging == 1 then
						--localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] TOTAL IN SHARED error: " .. err)
					--end
				--end
			--else --older lua version

				--stats total blocked addresses in the duration window
				local incr = localized.ddos_counter:get(secure_storage(0, "blocked_ip")) or nil
				if incr == nil or incr == localized.ngx.null then
					if localized.resty_redis == 1 then
						localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, 1))
						localized.ddos_counter:expire(secure_storage(2, "blocked_ip"), block_duration)
					else
						localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, 1), block_duration)
					end
				else
					local incr = localized.ddos_counter:get(secure_storage(0, "blocked_ip"))
					if localized.resty_redis == 1 then
						localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, incr+1))
						if ip_extend == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
							--localized.ddos_counter:expire(secure_storage(2, "blocked_ip"), localized.ddos_counter:ttl(secure_storage(3, "blocked_ip"))) --no support for ttl yet ?
							localized.ddos_counter:expire(secure_storage(2, "blocked_ip"), block_duration)
						else
							localized.ddos_counter:expire(secure_storage(2, "blocked_ip"), block_duration)
						end
					else
						if ip_extend == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
							if localized.resty_memcached == 1 then
								localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, incr+1), block_duration)
							elseif localized.resty_lrucache == 1 then
								localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, incr+1), block_duration)
							else
								localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, incr+1), localized.ddos_counter:ttl(secure_storage(3, "blocked_ip")))
							end
						else
							localized.ddos_counter:set(secure_storage(1, "blocked_ip"), secure_storage(4, incr+1), block_duration)
						end
					end
				end

				--stats total blocked requests in rate limit window
				local incr = localized.ddos_counter:get(secure_storage(0, "blocked_total_traffic")) or nil
				if incr == nil or incr == localized.ngx.null then
					if localized.resty_redis == 1 then
						localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, count))
						localized.ddos_counter:expire(secure_storage(2, "blocked_total_traffic"), rate_limit_window)
					else
						localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, count), rate_limit_window)
					end
				else
					local incr = localized.ddos_counter:get(secure_storage(0, "blocked_total_traffic"))
					if localized.resty_redis == 1 then
						localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, incr+count))
						if ip_extend == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
							--localized.ddos_counter:expire(secure_storage(2, "blocked_total_traffic"), localized.ddos_counter:ttl(secure_storage(3, "blocked_total_traffic"))) --no support for ttl yet ?
							localized.ddos_counter:expire(secure_storage(2, "blocked_total_traffic"), rate_limit_window)
						else
							localized.ddos_counter:expire(secure_storage(2, "blocked_total_traffic"), rate_limit_window)
						end
					else
						if ip_extend == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
							if localized.resty_memcached == 1 then
								localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, incr+count), rate_limit_window)
							elseif localized.resty_lrucache == 1 then
								localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, incr+count), rate_limit_window)
							else
								localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, incr+count), localized.ddos_counter:ttl(secure_storage(3, "blocked_total_traffic")))
							end
						else
							localized.ddos_counter:set(secure_storage(1, "blocked_total_traffic"), secure_storage(4, incr+count), rate_limit_window)
						end
					end
				end

			--end

			return true
		else

			--stats total requests in the rate limit window
			local incr = localized.ddos_counter:get(secure_storage(0, "total_traffic")) or nil
			if incr == nil or incr == localized.ngx.null then
				if localized.resty_redis == 1 then
					localized.ddos_counter:set(secure_storage(1, "total_traffic"), secure_storage(4, 1))
					localized.ddos_counter:expire(secure_storage(2, "total_traffic"), rate_limit_window)
				else
					localized.ddos_counter:set(secure_storage(1, "total_traffic"), secure_storage(4, 1), rate_limit_window)
				end
			else
				local incr = localized.ddos_counter:get(secure_storage(0, "total_traffic"))
				if localized.resty_redis == 1 then
					localized.ddos_counter:set(secure_storage(1, "total_traffic"), secure_storage(4, incr+1))
					if ip_extend == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
						--localized.ddos_counter:expire(secure_storage(2, "total_traffic"), localized.ddos_counter:ttl(secure_storage(3, "total_traffic"))) --no support for ttl yet ?
						localized.ddos_counter:expire(secure_storage(2, "total_traffic"), rate_limit_window)
					else
						localized.ddos_counter:expire(secure_storage(2, "total_traffic"), rate_limit_window)
					end
				else
					if ip_extend == 0 and localized.ngx.config.ngx_lua_version ~= nil and localized.ngx.config.ngx_lua_version >= 10011 then --v0.10.11 --:ttl introduced
						if localized.resty_memcached == 1 then
							localized.ddos_counter:set(secure_storage(1, "total_traffic"), secure_storage(4, incr+1), rate_limit_window)
						elseif localized.resty_lrucache == 1 then
							localized.ddos_counter:set(secure_storage(1, "total_traffic"), secure_storage(4, incr+1), rate_limit_window)
						else
							localized.ddos_counter:set(secure_storage(1, "total_traffic"), secure_storage(4, incr+1), localized.ddos_counter:ttl(secure_storage(3, "total_traffic")))
						end
					else
						localized.ddos_counter:set(secure_storage(1, "total_traffic"), secure_storage(4, incr+1), rate_limit_window)
					end
				end
				--if incr ~= nil then
				--	incr = localized.tonumber(incr)
				--end
				--localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] total traffic of all users requests in rate limit window excluding blocked traffic = " .. incr)
			end

		end

		return false
	end

	if localized.anti_ddos_table() ~= nil and #localized.anti_ddos_table() > 0 then
		for i=1,#localized.anti_ddos_table() do --for each host/path in our table
			local v = localized.anti_ddos_table()[i]
			if faster_than_match(v[1]) or localized.string_find(localized.URL(), v[1]) then --if our host matches one in the table
				if localized.request_limit == nil then
					localized.request_limit = remote_cache(v[19], v[7])
					--localized.request_limit = v[19] or nil --What ever memory space your server has set / defined for this to use
				end
				if localized.blocked_addr == nil then
					localized.blocked_addr = remote_cache(v[20], v[7])
					--localized.blocked_addr = v[20] or nil
				end
				if localized.ddos_counter == nil then
					localized.ddos_counter = remote_cache(v[21], v[7])
					--localized.ddos_counter = v[21] or nil
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

					local total_requests = localized.ddos_counter:get(secure_storage(0, "blocked_ip")) or 0
					if total_requests == nil or total_requests == localized.ngx.null then
						total_requests = 0
					end
					if v[33] == 1 then
						if total_requests > v[24] then --Automatically enable I am Under Attack Mode so disable logging
							v[7] = 0 --disable logging to prevent denial of service from excessive log file writes using up disk I/O
						end
					end

					if ip == "auto" then
						--localized.ngx_log(localized.ngx_LOG_TYPE, "Proxy IP found in whitelist - " .. localized.tostring(proxy_header_ip_check(localized.proxy_header_table)) .. " http_internal = " .. localized.tostring(localized.ngx_var_http_internal) )
						if localized.ngx_var_http_cf_connecting_ip() ~= nil then
							if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
								ip = localized.ngx_var_http_cf_connecting_ip()
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
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) internal call to bypass IP Block : " .. localized.ngx_var_remote_addr())
									end
								end
								ip = localized.ngx_var_remote_addr()
							end
						elseif localized.ngx_var_http_x_forwarded_for() ~= nil then
							if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
								ip = localized.ngx_var_http_x_forwarded_for()
							else
								if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
									if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
										blocked_address_check("[Anti-DDoS] (1) Blocked IP for attempting to impersonate proxy via header X-Forwarded-For : ")
									end
								else
									if localized.ngx_var_http_internal_log == 1 and localized.ngx_var_http_internal ~= nil then --2nd layer
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (1) internal call to bypass IP Block : " .. localized.ngx_var_remote_addr())
									end
								end
								ip = localized.ngx_var_remote_addr()
							end
						else
							ip = localized.ngx_var_remote_addr()
						end
					end
					if check_tor_onion() then
						v[23] = 0 --enable or disable automatic under attack
						--v[24] = 0 --number of ips to enable automatic under attack
						ip = localized.tor_remote_addr() --set ip as what the user wants the tor IP to be
						if localized.tor_remote_addr() == "auto" then
							ip = localized.ngx_var_remote_addr()
						end
					end

					--[[ --dev test to show to log file each users request count
					local incr = localized.ddos_counter:get(secure_storage(0, "blocked_ip")) or 0
					if incr ~= nil and incr ~= localized.ngx.null then
						local incr = localized.ddos_counter:get(secure_storage(0, "blocked_ip"))
						localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Total number of IP's in block list : " .. incr)
					end
					]]

					if localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
						local blocked_time = localized.blocked_addr:get(secure_storage(0, ip))
						if blocked_time and blocked_time ~= localized.ngx.null then
							if v[7] == 1 then
								if v[23] == 1 then
									if total_requests < v[24] then --Less than required amount to trigger Automatically enable I am Under Attack Mode so enable logging
										--localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (2) Blocked IP attempt: " .. ip .. " - URL : " .. localized.URL() )
										if v[44] ~= nil and v[44] == 1 then
											localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (2) Blocked IP attempt: " .. ip .. " - URL : " .. localized.URL() .. " - Ban extended/ends on : " .. localized.ngx_cookie_time(blocked_time+block_duration) ) --ngx_cookie_time can be slow dont use this under attack
										else
											localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (2) Blocked IP attempt: " .. ip .. " - URL : " .. localized.URL() .. " - Ban ends on : " .. localized.ngx_cookie_time(blocked_time+block_duration) ) --ngx_cookie_time can be slow dont use this under attack
										end
									end
								end
							end
							if v[44] ~= nil and v[44] == 1 then
								if localized.resty_redis == 1 then
									localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime))
									localized.blocked_addr:expire(secure_storage(2, ip), block_duration)
								else
									localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime), block_duration) --update with current time to extend ban duration
								end
							end
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
							close_connection()
							return localized.ngx_exit(rate_limit_exit_status)
						end

						if ip_whitelist_flood_checks(localized.ip_whitelist) and check_tor_onion() == false then --if true then block ip
							if check_rate_limit(ip, rate_limit_window, rate_limit_requests, block_duration, request_limit, ddos_counter, v[7], v[45]) then
								--Block IP
								if localized.resty_redis == 1 then
									localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime))
									localized.blocked_addr:expire(secure_storage(2, ip), block_duration)
								else
									localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime), block_duration)
								end
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
								close_connection()
								return localized.ngx_exit(rate_limit_exit_status)
							end
						end

						if ip_whitelist_flood_checks(localized.ip_whitelist) and check_tor_onion() == false then --if true then block ip
							if check_slowhttp(content_limit, timeout, connection_header_timeout, connection_header_max_conns, range_whitelist_blacklist, range_table, v[7]) then
								--Block IP
								if localized.resty_redis == 1 then
									localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime))
									localized.blocked_addr:expire(secure_storage(2, ip), block_duration)
								else
									localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime), block_duration)
								end
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
								close_connection()
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
													if localized.resty_redis == 1 then
														localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime))
														localized.blocked_addr:expire(secure_storage(2, ip), block_duration)
													else
														localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime), block_duration)
													end
												end
											end
											if v[25][i][3] ~= 444 and v[25][i][3] ~= 204 then --no point with gzip on these
												localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
											end
											close_connection()
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
														if localized.resty_redis == 1 then
															localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime))
															localized.blocked_addr:expire(secure_storage(2, ip), block_duration)
														else
															localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime), block_duration)
														end
													end
												end
												if v[25][i][3] ~= 444 and v[25][i][3] ~= 204 then --no point with gzip on these
													localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
												end
												close_connection()
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
							if localized.string_lower(localized.ngx.req.get_method()) == localized.string_lower(v[26][i][1]) then
								if v[26][i][3] > 0 then
									if ip_whitelist_flood_checks(localized.ip_whitelist) and check_tor_onion() == false then --if true then block ip
										if v[7] == 1 then
											localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Blocked using prohibited Request Method : " .. localized.ngx.req.get_method() .. " - " .. ip)
										end
										--Block IP
										if localized.resty_redis == 1 then
											localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime))
											localized.blocked_addr:expire(secure_storage(2, ip), block_duration)
										else
											localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime), block_duration)
										end
									end
								end
								if v[26][i][2] ~= 444 and v[26][i][2] ~= 204 then --no point with gzip on these
									localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
								end
								close_connection()
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

					if v[34] ~= nil then
						local req_headers = localized.ngx_req_get_headers()
						local counter = 0
						for key, value in localized.next, req_headers do
							if localized.type(value) == "table" then
								for i=1, #value do
									counter=counter+1
								end
							else
								counter=counter+1
							end
						end
						if counter >= v[34] then
							if ip_whitelist_flood_checks(localized.ip_whitelist) and check_tor_onion() == false then --if true then block ip
								if v[36] > 0 then
									if v[7] == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Max number of headers exceeds allowed = " .. v[34] .. " - total client sent = " .. counter .. " - " .. ip)
									end
									--Block IP
									if localized.resty_redis == 1 then
										localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime))
										localized.blocked_addr:expire(secure_storage(2, ip), block_duration)
									else
										localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime), block_duration)
									end
								end
							end
							if v[35] ~= 444 and v[35] ~= 204 then --no point with gzip on these
								localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
							end
							close_connection()
							localized.ngx_exit(v[35])
						end
					end

					if v[37] ~= nil then
						local args = localized.ngx_req_get_uri_args()
						local counter = 0
						for key, value in localized.next, args do
							if localized.type(value) == "table" then
								for i=1, #value do
									counter=counter+1
								end
							else
								counter=counter+1
							end
						end
						if counter >= v[37] then
							if ip_whitelist_flood_checks(localized.ip_whitelist) and check_tor_onion() == false then --if true then block ip
								if v[39] > 0 then
									if v[7] == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Max number of request URI args exceeds allowed = " .. v[37] .. " - total client sent = " .. counter .. " - " .. ip)
									end
									--Block IP
									if localized.resty_redis == 1 then
										localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime))
										localized.blocked_addr:expire(secure_storage(2, ip), block_duration)
									else
										localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime), block_duration)
									end
								end
							end
							if v[38] ~= 444 and v[38] ~= 204 then --no point with gzip on these
								localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
							end
							close_connection()
							localized.ngx_exit(v[38])
						end
					end

					if v[40] ~= nil then
						if #localized.request_uri() >= v[40] then
							if ip_whitelist_flood_checks(localized.ip_whitelist) and check_tor_onion() == false then --if true then block ip
								if v[42] > 0 then
									if v[7] == 1 then
										localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Max request URI length exceeds allowed = " .. v[40] .. " - total client URI length = " .. #localized.request_uri() .. " - " .. ip)
									end
									--Block IP
									if localized.resty_redis == 1 then
										localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime))
										localized.blocked_addr:expire(secure_storage(2, ip), block_duration)
									else
										localized.blocked_addr:set(secure_storage(1, ip), secure_storage(4, localized.currenttime), block_duration)
									end
								end
							end
							if v[41] ~= 444 and v[41] ~= 204 then --no point with gzip on these
								localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
							end
							close_connection()
							localized.ngx_exit(v[41])
						end
					end

					--ordering ngx_var checks last
					if localized.ngx_var_connection_requests == nil then
						localized.ngx_var_connection_requests = localized.ngx.var.connection_requests or 0 --default timeout per connection in nginx is 60 seconds unless you have changed your timeout configs
					end
					if localized.ngx_var_request_length == nil then
						localized.ngx_var_request_length = localized.ngx.var.request_length or 0
					end
					if v[2] >= 1 then --limit keep alive ip
						if localized.tonumber(localized.ngx_var_connection_requests) >= v[2] then
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE,"[Anti-DDoS] Exceeded Number of keepalive conns from IP " .. localized.ngx_var_connection_requests )
							end
							close_connection()
							localized.ngx_exit(v[3])
						end
					end
					if v[4] >= 1 then --limit request size smaller than
						if localized.tonumber(localized.ngx_var_request_length) <= v[4] then --1000 bytes = 1kb
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE,"[Anti-DDoS] Request Smaller than allowed LENGTH in bytes " .. localized.ngx_var_request_length )
							end
							close_connection()
							localized.ngx_exit(v[6])
						end
					end
					if v[5] >= 1 then --limit request size greater than
						if localized.tonumber(localized.ngx_var_request_length) >= v[5] then --1000 bytes = 1kb
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE,"[Anti-DDoS] Request Larger than allowed LENGTH in bytes " .. localized.ngx_var_request_length )
							end
							close_connection()
							localized.ngx_exit(v[6])
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

					if ip == "auto" then
						--localized.ngx_log(localized.ngx_LOG_TYPE, "Proxy IP found in whitelist - " .. localized.tostring(proxy_header_ip_check(localized.proxy_header_table)) .. " http_internal = " .. localized.tostring(localized.ngx_var_http_internal) )
						if localized.ngx_var_http_cf_connecting_ip() ~= nil then
							if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
								ip = localized.ngx_var_http_cf_connecting_ip()
							else --you are not really cloudflare dont pretend you are to bypass flood protection
								ip = localized.ngx_var_remote_addr()
							end
						elseif localized.ngx_var_http_x_forwarded_for() ~= nil then
							if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
								ip = localized.ngx_var_http_x_forwarded_for()
							else
								ip = localized.ngx_var_remote_addr()
							end
						else
							ip = localized.ngx_var_remote_addr()
						end
					end
					if check_tor_onion() then
						v[23] = 0
						v[24] = 0
						ip = localized.tor_remote_addr() --set ip as what the user wants the tor IP to be
						if localized.tor_remote_addr() == "auto" then
							ip = localized.ngx_var_remote_addr()
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
							close_connection()
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
											close_connection()
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
												close_connection()
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
							if localized.string_lower(localized.ngx.req.get_method()) == localized.string_lower(v[26][i][1]) then
								if v[7] == 1 then
									localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Blocked using prohibited Request Method : " .. localized.ngx.req.get_method() .. " - " .. ip)
								end
								if v[26][i][2] ~= 444 and v[26][i][2] ~= 204 then --no point with gzip on these
									localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
								end
								close_connection()
								localized.ngx_exit(v[26][i][2])
							end
						end
					end

					if v[27] < 1 then --disable gzip option
						localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
					end

					if v[34] ~= nil then
						local req_headers = localized.ngx_req_get_headers()
						local counter = 0
						for key, value in localized.next, req_headers do
							if localized.type(value) == "table" then
								for i=1, #value do
									counter=counter+1
								end
							else
								counter=counter+1
							end
						end
						if counter >= v[34] then
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Max number of headers exceeds allowed = " .. v[34] .. " - total client sent = " .. counter .. " - " .. ip)
							end
							if v[35] ~= 444 and v[35] ~= 204 then --no point with gzip on these
								localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
							end
							close_connection()
							localized.ngx_exit(v[35])
						end
					end

					if v[37] ~= nil then
						local args = localized.ngx_req_get_uri_args()
						local counter = 0
						for key, value in localized.next, args do
							if localized.type(value) == "table" then
								for i=1, #value do
									counter=counter+1
								end
							else
								counter=counter+1
							end
						end
						if counter >= v[37] then
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Max number of request URI args exceeds allowed = " .. v[37] .. " - total client sent = " .. counter .. " - " .. ip)
							end
							if v[38] ~= 444 and v[38] ~= 204 then --no point with gzip on these
								localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
							end
							close_connection()
							localized.ngx_exit(v[38])
						end
					end

					if v[40] ~= nil then
						if #localized.request_uri() >= v[40] then
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] Max request URI length exceeds allowed = " .. v[40] .. " - total client URI length = " .. #localized.request_uri() .. " - " .. ip)
							end
							if v[41] ~= 444 and v[41] ~= 204 then --no point with gzip on these
								localized.ngx_req_set_header("Accept-Encoding", "") --disable gzip
							end
							close_connection()
							localized.ngx_exit(v[41])
						end
					end

					--ordering ngx_var checks last
					if localized.ngx_var_connection_requests == nil then
						localized.ngx_var_connection_requests = localized.ngx.var.connection_requests or 0 --default timeout per connection in nginx is 60 seconds unless you have changed your timeout configs
					end
					if localized.ngx_var_request_length == nil then
						localized.ngx_var_request_length = localized.ngx.var.request_length or 0
					end
					if v[2] >= 1 then --limit keep alive ip
						if localized.tonumber(localized.ngx_var_connection_requests) >= v[2] then
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE,"[Anti-DDoS] Exceeded Number of keepalive conns from IP " .. localized.ngx_var_connection_requests )
							end
							close_connection()
							localized.ngx_exit(v[3])
						end
					end
					if v[4] >= 1 then --limit request size smaller than
						if localized.tonumber(localized.ngx_var_request_length) <= v[4] then --1000 bytes = 1kb
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE,"[Anti-DDoS] Request Smaller than allowed LENGTH in bytes " .. localized.ngx_var_request_length )
							end
							close_connection()
							localized.ngx_exit(v[6])
						end
					end
					if v[5] >= 1 then --limit request size greater than
						if localized.tonumber(localized.ngx_var_request_length) >= v[5] then --1000 bytes = 1kb
							if v[7] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE,"[Anti-DDoS] Request Larger than allowed LENGTH in bytes " .. localized.ngx_var_request_length )
							end
							close_connection()
							localized.ngx_exit(v[6])
						end
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
	-- FIX: Self-initializing short-circuit evaluation prevents any runtime nil crashes
	local counter = (localized.seed_counter or 0) + 1
	localized.seed_counter = counter

	local time_bytes = localized.ngx and localized.ngx.now() or os.time()
	local bxor = localized.bit_bxor
	local rshift = localized.bit_rshift

	-- Mix floating-point microsecond resolution noise with our call register counter
	local hash = (localized.math_floor(time_bytes * 1000000) + counter) % 4294967296

	-- MurmurHash3 Finalizer (Avalanche Phase) running purely inside CPU hardware registers
	hash = bxor(hash, rshift(hash, 16))
	hash = (hash * 0x85ebca6b) % 4294967296
	hash = bxor(hash, rshift(hash, 13))
	hash = (hash * 0xc2b2ae35) % 4294967296
	hash = bxor(hash, rshift(hash, 16))

	return hash
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
			if faster_than_match(v[1]) or localized.string_find(localized.URL(), v[1]) then --if our host matches one in the table
				for first=1,#v[2] do --for each arg in our table
					local value1 = v[2][first][1]
					local value2 = v[2][first][2]
					if value1 ~= nil and value2 ~= nil then
						localized.ngx.header[value1] = value2
					end
					if value2 == nil then
						localized.ngx.header[value1] = nil --remove the header
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
if localized.remote_addr() == "auto" then
	if localized.ngx_var_http_cf_connecting_ip() ~= nil then
		if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
			localized.remote_addr = function() return localized.ngx_var_http_cf_connecting_ip() end
		else --you are not really cloudflare dont pretend you are to bypass flood protection
			if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
				if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
					blocked_address_check("[Anti-DDoS] (2) Blocked IP for attempting to impersonate cloudflare via header CF-Connecting-IP : ")
				end
			end
			localized.remote_addr = function() return localized.ngx_var_remote_addr() end
		end
	elseif localized.ngx_var_http_x_forwarded_for() ~= nil then
		if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
			localized.remote_addr = function() return localized.ngx_var_http_x_forwarded_for() end
		else
			if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
				if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
					blocked_address_check("[Anti-DDoS] (2) Blocked IP for attempting to impersonate proxy via header X-Forwarded-For : ")
				end
			end
			localized.remote_addr = function() return localized.ngx_var_remote_addr() end
		end
	else
		localized.remote_addr = function() return localized.ngx_var_remote_addr() end
	end
end
if localized.ip_whitelist_remote_addr() == "auto" then
	if localized.ngx_var_http_cf_connecting_ip() ~= nil then
		if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
			localized.ip_whitelist_remote_addr = function() return localized.ngx_var_http_cf_connecting_ip() end
		else --you are not really cloudflare dont pretend you are to bypass flood protection
			if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
				if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
					blocked_address_check("[Anti-DDoS] (3) Blocked IP for attempting to impersonate cloudflare via header CF-Connecting-IP : ")
				end
			end
			localized.ip_whitelist_remote_addr = function() return localized.ngx_var_remote_addr() end
		end
	elseif localized.ngx_var_http_x_forwarded_for() ~= nil then
		if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
			localized.ip_whitelist_remote_addr = function() return localized.ngx_var_http_x_forwarded_for() end
		else
			if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
				if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
					blocked_address_check("[Anti-DDoS] (3) Blocked IP for attempting to impersonate proxy via header X-Forwarded-For : ")
				end
			end
			localized.ip_whitelist_remote_addr = function() return localized.ngx_var_remote_addr() end
		end
	else
		localized.ip_whitelist_remote_addr = function() return localized.ngx_var_remote_addr() end
	end
end
if localized.ip_blacklist_remote_addr() == "auto" then
	if localized.ngx_var_http_cf_connecting_ip() ~= nil then
		if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
			localized.ip_blacklist_remote_addr = function() return localized.ngx_var_http_cf_connecting_ip() end
		else --you are not really cloudflare dont pretend you are to bypass flood protection
			if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
				if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
					blocked_address_check("[Anti-DDoS] (4) Blocked IP for attempting to impersonate cloudflare via header CF-Connecting-IP : ")
				end
			end
			localized.ip_blacklist_remote_addr = function() return localized.ngx_var_remote_addr() end
		end
	elseif localized.ngx_var_http_x_forwarded_for() ~= nil then
		if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
			localized.ip_blacklist_remote_addr = function() return localized.ngx_var_http_x_forwarded_for() end
		else
			if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
				if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
					blocked_address_check("[Anti-DDoS] (4) Blocked IP for attempting to impersonate proxy via header X-Forwarded-For : ")
				end
			end
			localized.ip_blacklist_remote_addr = function() return localized.ngx_var_remote_addr() end
		end
	else
		localized.ip_blacklist_remote_addr = function() return localized.ngx_var_remote_addr() end
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
			if faster_than_match(v[1]) or localized.string_find(localized.URL(), v[1]) then --if our host matches one in the table
				for first=1,#v[2] do --for each arg in our table
					local value1 = v[2][first][1]
					if localized.ngx_var_http_internal ~= "1" and value1 ~= nil then
						localized.ngx_req_set_header(value1, localized.remote_addr())
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
		localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS] (2) Internal call back again : ")
	end
	if localized.ngx_var_http_internal_header_name ~= nil then
		localized.ngx_req_set_header(localized.ngx_var_http_internal_header_name, nil) --remove internal header
	end
end
--[[
End headers to restore original visitor IP addresses at your origin web server
]]

--if host of site is a tor website connecting clients will be tor network clients
if localized.remote_addr() == "tor" then
	localized.remote_addr = function() return localized.tor_remote_addr() end
	if localized.tor_remote_addr() == "auto" then
		localized.remote_addr = function() return localized.ngx_var_remote_addr() end
		localized.tor_remote_addr = function() return localized.ngx_var_remote_addr() end
	end
end
if check_tor_onion() then
	localized.remote_addr = function() return localized.tor_remote_addr() end --set ip as what the user wants the tor IP to be
	if localized.tor_remote_addr() == "auto" then
		localized.remote_addr = function() return localized.ngx_var_remote_addr() end
		localized.tor_remote_addr = function() return localized.ngx_var_remote_addr() end
	end
end
if localized.tor_remote_addr() == "auto" then
	localized.tor_remote_addr = function() return localized.ngx_var_remote_addr() end
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
			if faster_than_match(v[1]) or localized.string_find(localized.URL(), v[1]) then --if our host matches one in the table
				for i=1,#v[2] do --for each arg in our table
					local value = v[2][i]
					args[value] = nil --remove the arguement from the args table
					modified = 1 --set args as modified
				end
				break --break out of the for each loop pointless to keep searching the rest since we matched our host
			end
		end
		if modified == 1 then --need to set our args as our new modified one
			localized.ngx_req_set_uri_args(args) --set the args on the server as our new ordered args check localized.ngx.var.args
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
			if faster_than_match(v[1]) or localized.string_find(localized.URL(), v[1]) then --if our host matches one in the table
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
			localized.ngx_req_set_uri_args(args) --set the args on the server as our new ordered args check localized.ngx.var.args
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
			if faster_than_match(v[1]) or localized.string_find(localized.URL(), v[1]) then --if our host matches one in the table
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
			localized.ngx_req_set_uri_args(args) --set the args on the server as our new ordered args check localized.ngx.var.args
		else --allow_site was 1
			return --carry on script functions
		end
	end
end
query_string_sort()
--[[
End Query String Sort
]]

if localized.ngx_var_http_internal == nil then --1st layer
WAF_Checks() --run WAF checks first
end

local function check_ips()
	--function to check if ip address is whitelisted to bypass our auth
	local function check_ip_whitelist(ip_table)
		if ip_table ~= nil and #ip_table > 0 then
			if localized.static_exact_map == nil then
				localized.static_exact_map = {}
			end
			if localized.dynamic_cidr_rules == nil then
				localized.dynamic_cidr_rules = {}
			end
			if localized.dynamic_cidr_seen == nil then
				localized.dynamic_cidr_seen = {}
			end
			local rules_array = localized.dynamic_cidr_rules
			local rules_idx = #rules_array
			for i = 1, #ip_table do
				local v = ip_table[i]
				if not localized.dynamic_cidr_seen[v] then
					localized.dynamic_cidr_seen[v] = true
					if not localized.string_find(v, "/", 1, true) then
						localized.static_exact_map[v] = true
					else
						local rule = compile_cidr(v)
						if rule then
							rules_idx = rules_idx + 1
							rules_array[rules_idx] = rule
						else
							localized.dynamic_cidr_seen[v] = nil
						end
					end
				end
			end
			if ip_address_in_range(localized.ip_whitelist_remote_addr()) then
				return master_exit() --Go to content
			end
			if localized.ip_whitelist_block_mode == 1 then --ip address not matched the above
				blocked_address_check("[Anti-DDoS] Blocked IP attempt for not being in whitelist : ")
				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked IP not in whitelist IP : " .. localized.ip_whitelist_remote_addr())
				close_connection()
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
			if localized.static_exact_map == nil then
				localized.static_exact_map = {}
			end
			if localized.dynamic_cidr_rules == nil then
				localized.dynamic_cidr_rules = {}
			end
			if localized.dynamic_cidr_seen == nil then
				localized.dynamic_cidr_seen = {}
			end
			local rules_array = localized.dynamic_cidr_rules
			local rules_idx = #rules_array
			for i = 1, #ip_table do
				local v = ip_table[i]
				if not localized.dynamic_cidr_seen[v] then
					localized.dynamic_cidr_seen[v] = true
					if not localized.string_find(v, "/", 1, true) then
						localized.static_exact_map[v] = true
					else
						local rule = compile_cidr(v)
						if rule then
							rules_idx = rules_idx + 1
							rules_array[rules_idx] = rule
						else
							localized.dynamic_cidr_seen[v] = nil
						end
					end
				end
			end
			if ip_address_in_range(localized.ip_blacklist_remote_addr()) then
				blocked_address_check("[Anti-DDoS] Blocked IP attempt for being in blacklist : ")
				localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] Blocked IP in blacklist - IP : " .. localized.ip_blacklist_remote_addr())
				close_connection()
				return localized.ngx_exit(localized.ngx_HTTP_CLOSE) --deny user access
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
							localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] User-Agent Blocked - " .. user_agent_blacklist_var .. " -" .. " IP : " .. localized.remote_addr())
							close_connection()
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
								localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][WAF] User-Agent Blocked - " .. user_agent_blacklist_var[x] .. " -" .. " IP : " .. localized.remote_addr())
								close_connection()
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
Calculate answer Function
]]
if localized.ffi and not localized.ffi_b64_table then
	-- Map the standard Base64 encoding alphabet directly into a fast C array pointer
	localized.ffi_b64_table = localized.ffi.new("const char[64]", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
	localized.uint8_ptr_t = localized.ffi.typeof("uint8_t*")
	localized.char_array_t = localized.ffi.typeof("char[?]")
end

-- Persistent state cache to hold the signature constants for the current day
localized.signature_cache = localized.signature_cache or { last_date = "", key = 0, shift = 0 }

local function calculateAnswer(client_signature)
	local len = #client_signature
	if len == 0 then return "" end

	-- 1. Day-level caching guard path
	local sig_cache = localized.signature_cache
	local current_date = localized.os_date("%Y%m%d", localized.os_time_saved)

	if sig_cache.last_date ~= current_date then
		sig_cache.last_date = current_date
		local seed = localized.math_floor(localized.math_sin(localized.tonumber(current_date)) * 1000)
		sig_cache.key = seed % 256
		sig_cache.shift = localized.math_floor((seed * localized.math_sin(seed)) % 10) + 1
	end

	local base_key = sig_cache.key
	local shiftAmount = sig_cache.shift
	local ffi_lib = localized.ffi

	-- Safe fallback check to an unrolled pure Lua loop if the FFI layer is absent
	if not ffi_lib then
		local band = localized.bit_band
		local bxor = localized.bit_bxor
		local str_byte = localized.string_byte
		local str_char = localized.string_char
		local t_concat = localized.table_concat
		local t = {}
		local k = base_key
		for i = 1, len do
			t[i] = str_char(band(bxor(str_byte(client_signature, i), k) + shiftAmount, 255))
			k = band(k + 1, 255)
		end
		return localized.ngx_encode_base64(t_concat(t))
	end

	-- 2. Mathematical allocation sizing for Base64 blocks
	-- Instantly defines the final output string size without dynamic padding guesses
	local b64_len = localized.math_floor((len + 2) / 3) * 4
	local buffer = localized.char_array_t(b64_len)

	local src = ffi_lib.cast(localized.uint8_ptr_t, client_signature)
	local dst = ffi_lib.cast(localized.uint8_ptr_t, buffer)
	local b64 = localized.ffi_b64_table

	local band = localized.bit_band
	local bxor = localized.bit_bxor
	local rshift = localized.bit_rshift
	local lshift = localized.bit_lshift

	local src_idx = 0
	local dst_idx = 0
	local k = base_key

	-- 3. 3-Byte Vectorized Streaming Chunk Pass
	-- Pulls 3 input characters, converts them inline, and writes 4 Base64 bytes at once
	while src_idx <= len - 3 do
		-- Process all 3 bytes inline with their sequential dynamic keys and shifts
		local b0 = band(bxor(src[src_idx], k) + shiftAmount, 255)
		local b1 = band(bxor(src[src_idx + 1], band(k + 1, 255)) + shiftAmount, 255)
		local b2 = band(bxor(src[src_idx + 2], band(k + 2, 255)) + shiftAmount, 255)

		-- Pack the processed bytes straight into high-speed 6-bit Base64 index positions
		dst[dst_idx]     = b64[rshift(b0, 2)]
		dst[dst_idx + 1] = b64[band(lshift(b0, 4) + rshift(b1, 4), 63)]
		dst[dst_idx + 2] = b64[band(lshift(b1, 2) + rshift(b2, 6), 63)]
		dst[dst_idx + 3] = b64[band(b2, 63)]

		k = band(k + 3, 255)
		src_idx = src_idx + 3
		dst_idx = dst_idx + 4
	end

	-- 4. Clean up any remaining trailing bytes and apply precise Base64 padding '='
	if src_idx < len then
		local b0 = band(bxor(src[src_idx], k) + shiftAmount, 255)
		dst[dst_idx] = b64[rshift(b0, 2)]

		if src_idx + 1 < len then
			local b1 = band(bxor(src[src_idx + 1], band(k + 1, 255)) + shiftAmount, 255)
			dst[dst_idx + 1] = b64[band(lshift(b0, 4) + rshift(b1, 4), 63)]
			dst[dst_idx + 2] = b64[band(lshift(b1, 2), 63)]
			dst[dst_idx + 3] = 61 -- Ascii for '='
		else
			dst[dst_idx + 1] = b64[band(lshift(b0, 4), 63)]
			dst[dst_idx + 2] = 61 -- Ascii for '='
			dst[dst_idx + 3] = 61 -- Ascii for '='
		end
	end

	-- 5. Expose the pre-compiled buffer back to Lua in exactly ONE string allocation
	return ffi_lib.string(buffer, b64_len)
end
--[[
End Calculate answer Function
]]

--function to encrypt strings with our secret key / password provided
local function calculate_signature(str)
	if localized.cs ~= nil and localized.cs[str] ~= nil then
		return localized.cs[str] --cached calculate signature output
	end
	local output = nil
	if localized.secret_encryption == nil or localized.secret_encryption == 1 then
		output = localized.ngx_hmac_sha1(localized.secret, str)
	else
		output = xor_crypt(str, localized.secret)
	end
	output = localized.ngx_encode_base64(output) --wrap our encrypted output in base64
	output = localized.string_gsub(output, "[+/=]", "") --Remove +/=
	if localized.cs == nil then
		localized.cs = {}
	end
	localized.cs[str] = output --cache output
	return output
end
--calculate_signature(str)

if localized.ffi and not localized.ffi_random_charset then
	localized.char_array_t = localized.ffi.typeof("char[?]")
	localized.ffi_random_charset = localized.char_array_t(12, "0123456789_")
	localized.uint8_ptr_t = localized.ffi.typeof("uint8_t*")

	localized.ffi_variable_buffer = localized.ffi.new(localized.char_array_t, 64)
end

-- O(1) Fast Tracking Dictionary Set to prevent duplicates instantly
localized.stringrandom_seen = localized.stringrandom_seen or {}

-- Fallback: Pure Lua map if FFI is absent
if not localized.ffi and not localized.random_charset then
	localized.random_charset = {"0","1","2","3","4","5","6","7","8","9","_"}
end

-- Seed the fast-path bitwise PRNG state register using current time if unset
if localized.prng_state == nil then
	local boot_time = localized.ngx and localized.ngx.time() or 123456789
	-- FIX: Forces the initial seed to be structured as a 32-bit integer register instantly
	localized.prng_state = localized.bit_band(boot_time, 0xFFFFFFFF)
end

local function stringrandom(length)
	if length <= 0 then return "" end

	local ffi_lib = localized.ffi
	-- Safe fallback path to the optimized flat Lua loop if FFI layer is absent
	if not ffi_lib or not localized.ffi_random_charset then
		local r_charset = localized.random_charset
		local r_set_len = #r_charset
		local rand = localized.math_random
		local seen_set = localized.stringrandom_seen
		local t, output = {}
		while true do
			for i=1, length do t[i] = r_charset[rand(1, r_set_len)] end
			output = localized.table_concat(t, "")
			if not seen_set[output] then seen_set[output] = true break end
		end
		return output
	end

	-- --- ULTIMATE FAST FFI + PRNG PATH ---
	local c_charset = localized.ffi_random_charset
	local seen_set = localized.stringrandom_seen

	-- Localize fast bitwise methods to skip math_random call layers
	local bxor = localized.bit_bxor
	local lshift = localized.bit_lshift
	local rshift = localized.bit_rshift
	local state = localized.prng_state

	local buffer = (length <= 64) and localized.ffi_variable_buffer or ffi_lib.new(localized.char_array_t, length)
	local dst = ffi_lib.cast(localized.uint8_ptr_t, buffer)
	local output

	while true do
		-- Stream characters natively using hardware shifting logic
		for i=0, length - 1 do
			-- Xorshift32 PRNG logic execution (Runs completely inside CPU registers)
			state = bxor(state, lshift(state, 13))
			state = bxor(state, rshift(state, 17))
			state = bxor(state, lshift(state, 5))

			-- Keep the internal state safely bounded to 32-bit unsigned spaces
			state = state % 4294967296

			-- Map register value cleanly into the index constraints (0 to 10)
			dst[i] = c_charset[state % 11]
		end

		-- Convert raw memory block to standard Lua string in a single operation
		output = ffi_lib.string(buffer, length)

		-- Instant O(1) tracking confirmation lookup
		if not seen_set[output] then
			seen_set[output] = true
			break
		end
	end

	-- Update the persistent global seed pointer for subsequent calls
	localized.prng_state = state
	return output
end

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

-- Allocate a flat character buffer map for all 256 byte variations sequentially
if localized.ffi and not localized.ffi_hex_map then
	localized.uint8_ptr_t = localized.ffi.typeof("uint8_t*")
	localized.char_array_t = localized.ffi.typeof("char[?]")

	-- FIX: Declared as an array type 'const char*' so it accepts a string literal properly
	localized.ffi_hex_map = localized.ffi.cast("const char*", 
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" ..
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F" ..
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F" ..
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F" ..
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F" ..
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF" ..
		"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF" ..
		"E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
	)
end

-- Fallback: Pure Lua map if FFI is absent
if not localized.ffi and not localized.hex_dump_map then
	localized.hex_dump_map = {}
	for i=0, 255 do
		localized.hex_dump_map[i] = localized.string_format("%02X", i)
	end
end

local function stringtohex(str)
	local len = #str
	if len == 0 then return "" end

	local ffi_lib = localized.ffi
	-- Safe fallback check to the 4-way unrolled pure Lua loop if FFI initialization failed
	if not ffi_lib or not localized.ffi_hex_map then
		local hex_map = localized.hex_dump_map
		local str_byte = localized.string_byte
		local t = {}
		local left = len % 4
		for i = 1, len - left, 4 do
			t[i]     = hex_map[str_byte(str, i)]
			t[i + 1] = hex_map[str_byte(str, i + 1)]
			t[i + 2] = hex_map[str_byte(str, i + 2)]
			t[i + 3] = hex_map[str_byte(str, i + 3)]
		end
		for i = len - left + 1, len do
			t[i] = hex_map[str_byte(str, i)]
		end
		return localized.table_concat(t)
	end

	-- Pre-allocate exactly the right number of bytes in raw memory buffer space
	local hex_len = len * 2
	local buffer = localized.char_array_t(hex_len)

	-- Cast pointers to allow ultra-fast sequential byte increments
	local src = ffi_lib.cast(localized.uint8_ptr_t, str)
	local dst = ffi_lib.cast(localized.uint8_ptr_t, buffer)
	local c_map = localized.ffi_hex_map

	local dst_idx = 0
	for i=0, len - 1 do
		-- Extract byte integer, calculate structural offset multiplier
		local offset = src[i] * 2

		-- Pull individual high/low characters out of the flat C character buffer matrix
		dst[dst_idx]     = c_map[offset]
		dst[dst_idx + 1] = c_map[offset + 1]

		dst_idx = dst_idx + 2
	end

	return ffi_lib.string(buffer, hex_len)
end

local function sep(str, patt, re)
	local step = (patt == ".") and 1 or ((patt == "..") and 2 or nil)

	if not step then
		local t, idx = {}, 1
		for m in localized.string_gmatch(str, patt) do
			t[idx] = m
			t[idx + 1] = re
			idx = idx + 2
		end
		if idx > 1 then
			t[idx - 1] = nil
			return localized.table_concat(t)
		end
		return str
	end

	local len = #str
	if len <= step then return str end

	local t, idx = {}, 1
	local str_sub = localized.string_sub

	for i=1, len, step do
		t[idx] = str_sub(str, i, i + step - 1)
		t[idx + 1] = re
		idx = idx + 2
	end

	t[idx - 1] = nil 
	return localized.table_concat(t)
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

		if localized.ffi and not localized.ffi_scrambler_buffer then
			localized.char_array_t = localized.ffi.typeof("char[?]")
			localized.uint8_ptr_t = localized.ffi.typeof("uint8_t*")
			localized.const_char_ptr_array_t = localized.ffi.typeof("const char*[8192]") -- Explicit array bounds safety allocation

			-- Pre-allocate all hardware structural memory blocks once at boot phase
			localized.ffi_scrambler_buffer = localized.ffi.new(localized.char_array_t, 524288)
			localized.ffi_name_order_array = localized.ffi.new(localized.const_char_ptr_array_t)

			localized.ffi.cdef[[
				typedef struct {
					uint32_t offset;
					uint32_t size;
					const char* name;
				} ffi_chunk_coord_t;
			]]

			localized.ffi_coord_array = localized.ffi.new("ffi_chunk_coord_t[8192]") -- Explicit array bounds safety allocation
		end

		local function scramble_javascript_payload(string1, stringrandom_length)
			local base64_javascript = localized.ngx_encode_base64(string1)
			local b64_len = #base64_javascript
			if b64_len == 0 then return "" end

			local ffi_lib = localized.ffi
			-- Safe fallback check if the FFI allocation layer is absent
			if not ffi_lib or not localized.ffi_scrambler_buffer then
				local counter = 0
				local chunks, chunks_order = {}, {}
				while counter < b64_len do
					local r = localized.math_random(1, b64_len)
					local random_var = stringrandom(stringrandom_length)
					chunks_order[#chunks_order+1] = "_" .. random_var
					chunks[#chunks+1] = 'var _' .. random_var .. '="' .. localized.string_sub(base64_javascript, counter + 1, counter + r + 1) .. '";'
					counter = counter + r + 1
				end
				shuffle(chunks)
				local output = localized.table_concat(chunks, "")
				return output .. "eval(decodeURIComponent(escape(window.atob(" .. localized.table_concat(chunks_order, " + ") .. "))));"
			end

			-- Hardware Registers Tracking Layout
			local coords = localized.ffi_coord_array
			local order_names = localized.ffi_name_order_array
			local rand = localized.math_random

			local chunk_count = 0
			local b64_idx = 0

			-- First Pass: Map the chunks as pure C primitives and cache original names order
			while b64_idx < b64_len do
				-- FIX: Calculate a fresh dynamic random stride on every pass inside the loop block
				local r = rand(1, b64_len)
				local current_chunk_size = (b64_idx + r + 1 > b64_len) and (b64_len - b64_idx) or (r + 1)
				local random_var = stringrandom(stringrandom_length)

				-- Write straight into flat memory pools with zero object creation allocations
				local chunk = coords[chunk_count]
				chunk.offset = b64_idx
				chunk.size = current_chunk_size
				chunk.name = random_var

				-- Track original name sequence order flawlessly with zero overhead
				order_names[chunk_count] = random_var

				chunk_count = chunk_count + 1
				b64_idx = b64_idx + current_chunk_size
			end

			-- Bare-Metal Random Shuffling: Swaps memory entries inside the fixed C array
			for i = chunk_count - 1, 1, -1 do
				local j = rand(0, i)
				local t_offset, t_size, t_name = coords[i].offset, coords[i].size, coords[i].name
				coords[i].offset, coords[i].size, coords[i].name = coords[j].offset, coords[j].size, coords[j].name
				coords[j].offset, coords[j].size, coords[j].name = t_offset, t_size, t_name
			end

			-- Second Pass: Stream the scrambled variables natively into the destination buffer arena
			local src = ffi_lib.cast(localized.uint8_ptr_t, base64_javascript)
			local dst = ffi_lib.cast(localized.uint8_ptr_t, localized.ffi_scrambler_buffer)
			local dst_idx = 0

			for i = 0, chunk_count - 1 do
				local chunk = coords[i]
				local name = chunk.name

				-- Inline write layout characters directly: 'var _'
				dst[dst_idx] = 118; dst[dst_idx + 1] = 97; dst[dst_idx + 2] = 114; dst[dst_idx + 3] = 32; dst[dst_idx + 4] = 95
				dst_idx = dst_idx + 5

				-- Write the pre-generated variable name directly into memory
				ffi_lib.copy(dst + dst_idx, name, stringrandom_length)
				dst_idx = dst_idx + stringrandom_length

				-- Inline write layout characters directly: '="'
				dst[dst_idx] = 61; dst[dst_idx + 1] = 34
				dst_idx = dst_idx + 2

				-- Direct Address Memory Copy from the Base64 source string
				ffi_lib.copy(dst + dst_idx, src + chunk.offset, chunk.size)
				dst_idx = dst_idx + chunk.size

				-- Inline write layout characters directly: '";'
				dst[dst_idx] = 34; dst[dst_idx + 1] = 59
				dst_idx = dst_idx + 2
			end

			-- Third Pass: Inline compile the 'eval(decodeURIComponent(escape(window.atob(_var1 + _var2))))' layout
			local tail_literal = "eval(decodeURIComponent(escape(window.atob("
			local tail_len = #tail_literal
			ffi_lib.copy(dst + dst_idx, tail_literal, tail_len)
			dst_idx = dst_idx + tail_len

			-- Stream the original ordered variable names directly into the tail block buffer
			for i = 0, chunk_count - 1 do
				if i > 0 then
					dst[dst_idx] = 32; dst[dst_idx + 1] = 43; dst[dst_idx + 2] = 32 -- ASCII for ' + '
					dst_idx = dst_idx + 3
				end

				dst[dst_idx] = 95 -- ASCII for '_'
				dst_idx = dst_idx + 1

				-- Pull the original name instantly out of the parallel ordered array cache map
				ffi_lib.copy(dst + dst_idx, order_names[i], stringrandom_length)
				dst_idx = dst_idx + stringrandom_length
			end

			-- Close out the JavaScript command block wrapper string layout
			dst[dst_idx] = 41; dst[dst_idx + 1] = 41; dst[dst_idx + 2] = 41; dst[dst_idx + 3] = 41; dst[dst_idx + 4] = 59 -- ASCII for '))));'
			dst_idx = dst_idx + 5

			-- Expose the completed scrambled payload sequence back to Lua in exactly ONE string allocation
			return ffi_lib.string(dst, dst_idx)
		end		
		output = scramble_javascript_payload(string1, localized.math_random(1, #string1))

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
if localized.ngx_var_http_cf_connecting_ip() ~= nil then
	authentication_page_status_output = localized.ngx_HTTP_OK --(200) cloudflare may not like a 503 status code response so send them a 200 instead
elseif localized.ngx_var_http_x_forwarded_for() ~= nil then
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
	localized.x_tor_header_name = calculate_signature(localized.tor_remote_addr() .. localized.x_tor_header_name .. localized.currentdate) --make the header unique to the client and for todays date encrypted so every 24 hours this will change and can't be guessed by bots gsub because header bug with underscores so underscore needs to be removed
	localized.x_tor_header_name = localized.string_gsub(localized.x_tor_header_name, "_", "") --replace underscore with nothing
	localized.x_tor_header_name_allowed = calculate_signature(localized.tor_remote_addr() .. localized.x_tor_header_name_allowed .. localized.currentdate) --make the header unique to the client and for todays date encrypted so every 24 hours this will change and can't be guessed by bots gsub because header bug with underscores so underscore needs to be removed
	localized.x_tor_header_name_allowed = localized.string_gsub(localized.x_tor_header_name_allowed, "_", "") --replace underscore with nothing
	localized.x_tor_header_name_blocked = calculate_signature(localized.tor_remote_addr() .. localized.x_tor_header_name_blocked .. localized.currentdate) --make the header unique to the client and for todays date encrypted so every 24 hours this will change and can't be guessed by bots gsub because header bug with underscores so underscore needs to be removed
	localized.x_tor_header_name_blocked = localized.string_gsub(localized.x_tor_header_name_blocked, "_", "") --replace underscore with nothing
end

if localized.encrypt_anti_ddos_cookies == 2 then --if Anti-DDoS Cookies are to be encrypted
	localized.cookie_tor = calculate_signature(localized.tor_remote_addr() .. localized.cookie_tor .. localized.currentdate) --encrypt our tor cookie name
	localized.cookie_tor_value_allow = calculate_signature(localized.tor_remote_addr() .. localized.cookie_tor_value_allow .. localized.currentdate) --encrypt our tor cookie value for allow
	localized.cookie_tor_value_block = calculate_signature(localized.tor_remote_addr() .. localized.cookie_tor_value_block .. localized.currentdate) --encrypt our tor cookie value for block
end

--block tor function to block traffic from tor users
local function blocktor()
	close_connection()
	return localized.ngx_exit(localized.ngx_HTTP_FORBIDDEN) --deny user access
end

--check the connecting client to see if they have our required matching tor cookie name in their request
local tor_cookie_name = "cookie_" .. localized.cookie_tor
local tor_cookie_value = localized.ngx.var[tor_cookie_name] or ""

if tor_cookie_value == localized.cookie_tor_value_allow then --if their cookie value matches the value we expect
	if localized.tor == 2 then --perform check if tor users should be allowed or blocked if tor users already browsing your site have been granted access and you change this setting you want them to be blocked now so this makes sure they are denied any further access before their cookie expires
		blocktor()
	end
	localized.remote_addr = function() return localized.tor_remote_addr() end --set the localized.remote_addr() as the localized.tor_remote_addr() value
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
	localized.authorization_cookie = calculate_signature(localized.remote_addr() .. localized.authorization_cookie .. localized.currentdate) --encrypt our auth box session cookie name
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
		localized.remote_addr = function() return localized.tor_remote_addr() end --set for compatibility with Tor Clients
	end

	local expected_cookie_value = nil
	if localized.authorization == 2 then --Cookie sessions
		local cookie_name = "cookie_" .. localized.authorization_cookie
		local cookie_value = localized.ngx.var[cookie_name] or ""
		expected_cookie_value = calculate_signature(localized.remote_addr() .. "authenticate" .. localized.currentdate) --encrypt our expected cookie value
		if cookie_value == expected_cookie_value then --cookie value client gave us matches what we expect it to be
			master_exit() --Go to content
		end
	end

	local allow_site = nil
	local authorization_display_user_details = nil
	if localized.authorization_paths ~= nil and #localized.authorization_paths > 0 then
		for i=1,#localized.authorization_paths do --for each host in our table
			local v = localized.authorization_paths[i]
			if faster_than_match(v[2]) or localized.string_find(localized.URL(), v[2]) then --if our host matches one in the table
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
						localized.ngx.header["Set-Cookie"] = localized.set_cookies --send client a cookie for their session to be valid
					end
					allow_access = 1 --grant access
					break --break out foreach loop since our user and pass was correct
				end
			end
		end
	end
	if authorization_dynamic == 1 then --dynamic
		authorization_username = calculate_signature(localized.remote_addr() .. "username" .. localized.currentdate) --encrypt username
		authorization_password = calculate_signature(localized.remote_addr() .. "password" .. localized.currentdate) --encrypt password
		authorization_username = localized.string_sub(authorization_username, 1, localized.authorization_dynamic_length) --change username to set length
		authorization_password = localized.string_sub(authorization_password, 1, localized.authorization_dynamic_length) --change password to set length

		local base64_expected = authorization_username .. ":" .. authorization_password --convert to browser format
		base64_expected = localized.ngx_encode_base64(base64_expected) --base64 encode like browser format
		local authroization_user_pass = "Basic " .. base64_expected --append Basic to start like browser header does
		if req_headers["Authorization"] == authroization_user_pass then --if the details match what we expect
			if localized.authorization == 2 then --Cookie sessions
				localized.set_cookie1 = localized.authorization_cookie.."="..expected_cookie_value.."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";"
				localized.set_cookies = {localized.set_cookie1}
				localized.ngx.header["Set-Cookie"] = localized.set_cookies --send client a cookie for their session to be valid
			end
			allow_access = 1 --grant access
		end
	end

	if allow_access == 1 then
		master_exit() --Go to content
	else
		localized.ngx_status = localized.ngx_HTTP_UNAUTHORIZED --send client unathorized header
		if authorization_display_user_details == 0 then
			localized.ngx.header['WWW-Authenticate'] = 'Basic realm="' .. localized.authorization_message .. '", charset="' .. localized.default_charset .. '"' --send client a box to input required username and password fields
		else
			localized.ngx.header['WWW-Authenticate'] = 'Basic realm="' .. localized.authorization_message .. ' ' .. localized.authorization_username_message .. ' ' .. authorization_username .. ' ' .. localized.authorization_password_message .. ' ' .. authorization_password .. '", charset="' .. localized.default_charset .. '"' --send client a box to input required username and password fields
		end
		close_connection()
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
				if faster_than_match(v[2]) or localized.string_find(localized.URL(), v[2]) then --if our host matches one in the table
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

local answer = calculate_signature(localized.remote_addr()) --create our encrypted unique identification for the user visiting the website.
local JsPuzzleAnswer = calculateAnswer(answer) -- Localize the answer to be used further

if localized.x_auth_header == 2 then --if x-auth-header is dynamic
	localized.x_auth_header_name = calculate_signature(localized.remote_addr() .. localized.x_auth_header_name .. localized.currentdate) --make the header unique to the client and for todays date encrypted so every 24 hours this will change and can't be guessed by bots gsub because header bug with underscores so underscore needs to be removed
	localized.x_auth_header_name = localized.string_gsub(localized.x_auth_header_name, "_", "") --replace underscore with nothing
end

if localized.encrypt_anti_ddos_cookies == 2 then --if Anti-DDoS Cookies are to be encrypted
	--make the cookies unique to the client and for todays date encrypted so every 24 hours this will change and can't be guessed by bots
	localized.challenge = calculate_signature(localized.remote_addr() .. localized.challenge .. localized.currentdate)
	localized.cookie_name_start_date = calculate_signature(localized.remote_addr() .. localized.cookie_name_start_date .. localized.currentdate)
	localized.cookie_name_end_date = calculate_signature(localized.remote_addr() .. localized.cookie_name_end_date .. localized.currentdate)
	localized.cookie_name_encrypted_start_and_end_date = calculate_signature(localized.remote_addr() .. localized.cookie_name_encrypted_start_and_end_date .. localized.currentdate)
end

--[[
Grant access function to either grant or deny user access to our website
]]
local function grant_access()
	--our uid cookie
	local cookie_name = "cookie_" .. localized.challenge
	local cookie_value = localized.ngx.var[cookie_name] or ""
	--our start date cookie
	local cookie_name_start_date_name = "cookie_" .. localized.cookie_name_start_date
	local cookie_name_start_date_value = localized.ngx.var[cookie_name_start_date_name] or "0" --Added a 0, since a missing 'cookie_name_start_date_name' value in ngx_var resulted in 502
	local cookie_name_start_date_value_unix = localized.tonumber(cookie_name_start_date_value) or 0
	--our end date cookie
	local cookie_name_end_date_name = "cookie_" .. localized.cookie_name_end_date
	local cookie_name_end_date_value = localized.ngx.var[cookie_name_end_date_name] or "0" --Just to make sure it doesnt fail somewhere
	--our start date and end date combined to a unique id
	local cookie_name_encrypted_start_and_end_date_name = "cookie_" .. localized.cookie_name_encrypted_start_and_end_date
	local cookie_name_encrypted_start_and_end_date_value = localized.ngx.var[cookie_name_encrypted_start_and_end_date_name] or ""

	if cookie_value ~= answer then --if cookie value not equal to or matching our expected cookie they should be giving us
		return --return to refresh the page so it tries again
	end

	--if x-auth-answer is correct to the user unique id time stamps etc meaning browser figured it out then set a new cookie that grants access without needed these checks
	local req_headers = localized.ngx_req_get_headers() --get all request headers
	if req_headers["x-requested-with"] == "XMLHttpRequest" then --if request header matches request type of XMLHttpRequest
		if req_headers[localized.x_tor_header_name] == x_tor_header_name_value and req_headers[localized.x_auth_header_name] == JsPuzzleAnswer then --if the header and value are what we expect then the client is legitimate
			localized.remote_addr = function() return localized.tor_remote_addr() end --set as our defined static tor variable to use
			
			localized.challenge = calculate_signature(localized.remote_addr() .. challenge_original .. localized.currentdate) --create our encrypted unique identification for the user visiting the website again. (Stops a double page refresh loop)
			answer = calculate_signature(localized.remote_addr()) --create our answer again under the new localized.remote_addr() (Stops a double page refresh loop)
			localized.cookie_name_start_date = calculate_signature(localized.remote_addr() .. cookie_name_start_date_original .. localized.currentdate) --create our localized.cookie_name_start_date again under the new localized.remote_addr() (Stops a double page refresh loop)
			localized.cookie_name_end_date = calculate_signature(localized.remote_addr() .. cookie_name_end_date_original .. localized.currentdate) --create our localized.cookie_name_end_date again under the new localized.remote_addr() (Stops a double page refresh loop)
			localized.cookie_name_encrypted_start_and_end_date = calculate_signature(localized.remote_addr() .. cookie_name_encrypted_start_and_end_date_original .. localized.currentdate) --create our localized.cookie_name_encrypted_start_and_end_date again under the new localized.remote_addr() (Stops a double page refresh loop)

			localized.set_cookie1 = localized.challenge.."="..answer.."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --apply our uid cookie incase javascript setting this cookies time stamp correctly has issues
			localized.set_cookie2 = localized.cookie_name_start_date.."="..localized.currenttime.."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --start date cookie
			localized.set_cookie3 = localized.cookie_name_end_date.."="..(localized.currenttime+localized.expire_time).."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --end date cookie
			localized.set_cookie4 = localized.cookie_name_encrypted_start_and_end_date.."="..calculate_signature(localized.remote_addr() .. localized.currenttime .. (localized.currenttime+localized.expire_time) ).."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --start and end date combined to unique id
			localized.set_cookie5 = localized.cookie_tor.."="..cookie_tor_value.."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --create our tor cookie to identify the client as a tor user

			localized.set_cookies = {localized.set_cookie1 , localized.set_cookie2 , localized.set_cookie3 , localized.set_cookie4, localized.set_cookie5}
			localized.ngx.header["Set-Cookie"] = localized.set_cookies
			localized.ngx.header["X-Content-Type-Options"] = "nosniff"
			localized.ngx.header["X-Frame-Options"] = "SAMEORIGIN"
			localized.ngx.header["X-XSS-Protection"] = "1; mode=block"
			localized.ngx.header["Cache-Control"] = "public, max-age=0 no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
			localized.ngx.header["Pragma"] = "no-cache"
			localized.ngx.header["Expires"] = "0"
			localized.ngx.header.content_type = "text/html; charset=" .. localized.default_charset
			localized.ngx_status = expected_header_status
			close_connection()
			localized.ngx_exit(expected_header_status)
		end
		if req_headers[localized.x_auth_header_name] == JsPuzzleAnswer then --if the answer header provided by the browser Javascript matches what our Javascript puzzle answer should be
			localized.set_cookie1 = localized.challenge.."="..cookie_value.."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --apply our uid cookie incase javascript setting this cookies time stamp correctly has issues
			localized.set_cookie2 = localized.cookie_name_start_date.."="..localized.currenttime.."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --start date cookie
			localized.set_cookie3 = localized.cookie_name_end_date.."="..(localized.currenttime+localized.expire_time).."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --end date cookie
			localized.set_cookie4 = localized.cookie_name_encrypted_start_and_end_date.."="..calculate_signature(localized.remote_addr() .. localized.currenttime .. (localized.currenttime+localized.expire_time) ).."; path=/; expires=" .. localized.ngx_cookie_time(localized.currenttime+localized.expire_time) .. "; Max-Age=" .. localized.expire_time .. ";" --start and end date combined to unique id

			localized.set_cookies = {localized.set_cookie1 , localized.set_cookie2 , localized.set_cookie3 , localized.set_cookie4}
			localized.ngx.header["Set-Cookie"] = localized.set_cookies
			localized.ngx.header["X-Content-Type-Options"] = "nosniff"
			localized.ngx.header["X-Frame-Options"] = "SAMEORIGIN"
			localized.ngx.header["X-XSS-Protection"] = "1; mode=block"
			localized.ngx.header["Cache-Control"] = "public, max-age=0 no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
			localized.ngx.header["Pragma"] = "no-cache"
			localized.ngx.header["Expires"] = "0"
			localized.ngx.header.content_type = "text/html; charset=" .. localized.default_charset
			localized.ngx_status = expected_header_status
			close_connection()
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
		if cookie_name_encrypted_start_and_end_date_value ~= calculate_signature(localized.remote_addr() .. cookie_name_start_date_value_unix .. cookie_name_end_date_value_unix) then --if users authentication encrypted cookie not equal to or matching our expected cookie they should be giving us
			return --return to refresh the page so it tries again
		end
	end
	--else all checks passed bypass our firewall and show page content

	if localized.log_users_granted_access == 1 then
		localized.ngx_log(localized.ngx_LOG_TYPE, localized.log_on_granted_text_start .. localized.remote_addr() .. localized.log_on_granted_text_end)
	end
	if localized.os_clock ~= nil then
		localized.ngx_log(localized.ngx_LOG_TYPE, " Grant Elapsed time is: " .. os.clock()-localized.os_clock)
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
	localized.ngx_log(localized.ngx_LOG_TYPE, localized.log_on_puzzle_text_start .. localized.remote_addr() .. localized.log_on_puzzle_text_end)
end

--Fix localized.remote_addr() output as what ever IP address the Client is using
if localized.ngx_var_http_cf_connecting_ip() ~= nil then
	if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really cloudflare
		localized.remote_addr = function() return localized.ngx_var_http_cf_connecting_ip() end
	else --you are not really cloudflare dont pretend you are to bypass flood protection
		if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
			if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
				blocked_address_check("[Anti-DDoS] (5) Blocked IP for attempting to impersonate cloudflare via header CF-Connecting-IP : ")
			end
		end
		localized.remote_addr = function() return localized.ngx_var_remote_addr() end
	end
elseif localized.ngx_var_http_x_forwarded_for() ~= nil then
	if proxy_header_ip_check(localized.proxy_header_table) == true then --you are really our expected proxy ip
		localized.remote_addr = function() return localized.ngx_var_http_x_forwarded_for() end
	else
		if localized.tostring(localized.ngx_var_http_internal) ~= localized.ngx_var_http_internal_string then
			if localized.ngx_var_http_internal_header_name ~= nil and localized.ngx_var_http_internal == nil then --1st layer only do blocking on 1st layer not the internal
				blocked_address_check("[Anti-DDoS] (5) Blocked IP for attempting to impersonate proxy via header X-Forwarded-For : ")
			end
		end
		localized.remote_addr = function() return localized.ngx_var_remote_addr() end
	end
else
	localized.remote_addr = function() return localized.ngx_var_remote_addr() end
end

if check_tor_onion() == false then
blocked_address_check("[Anti-DDoS] Blocked IP for exceeding puzzle fail attempt : ", 1)
end

--[[
Build HTML Template
]]

localized.title = localized.host() .. [[ | Anti-DDoS Flood Protection and Firewall]]

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
			xhttp.open("]] .. localized.javascript_REQUEST_TYPE .. [[", "]] .. localized.request_uri() .. [[", true);
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

localized.HTML_ENTITIES = {
	["&"] = "&amp;",
	["<"] = "&lt;",
	[">"] = "&gt;",
	['"'] = "&quot;",
	["'"] = "&#39;",
	["/"] = "&#x2F;"
}
local function escape_html(input)
	if not input then return "" end

	-- PRE-FLIGHT CHECK: Fast plain search for ANY dangerous characters.
	if not localized.string_find(input, "&", 1, true) and
	   not localized.string_find(input, "<", 1, true) and
	   not localized.string_find(input, ">", 1, true) and
	   not localized.string_find(input, '"', 1, true) and
	   not localized.string_find(input, "'", 1, true) and
	   not localized.string_find(input, "/", 1, true) then
		return input
	end

	-- FALLBACK: Single-pass, byte-by-byte lookups via gmatch.
	local fragments = {}
	local count = 0

	for char in localized.string_gmatch(input, ".") do
		count = count + 1
		fragments[count] = localized.HTML_ENTITIES[char] or char
	end

	return localized.table_concat(fragments)
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
IP address : ]] .. escape_html(localized.remote_addr()) .. [[
<br>
Request URL : ]] .. escape_html(localized.URL()) .. [[
<br>
User-Agent : ]] .. escape_html(localized.ngx_var_http_user_agent()) .. [[
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
localized.ngx.header["Set-Cookie"] = localized.set_cookies
localized.ngx.header["X-Content-Type-Options"] = "nosniff"
localized.ngx.header["X-Frame-Options"] = "SAMEORIGIN"
localized.ngx.header["X-XSS-Protection"] = "1; mode=block"
localized.ngx.header["Cache-Control"] = "public, max-age=0 no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
localized.ngx.header["Pragma"] = "no-cache"
localized.ngx.header["Expires"] = "0"
if localized.credits == 1 then
localized.ngx.header["X-Anti-DDoS"] = "Conor McKnight | facebook.com/C0nw0nk"
end
localized.ngx.header.content_type = "text/html; charset=" .. localized.default_charset
localized.ngx_status = authentication_page_status_output
localized.ngx_say(localized.anti_ddos_html_output)
if localized.os_clock ~= nil then
localized.ngx_log(localized.ngx_LOG_TYPE, " Puzzle Elapsed time is: " .. os.clock()-localized.os_clock)
end
close_connection()
localized.ngx_exit(authentication_page_status_output)

end
run_checks() --nest function to prevent function at line 1 has more than 200 local variables and function at line X has more than X upvalues just my way of putting locals inside functions to get around the 200 limit

if localized.content_cache() == nil or #localized.content_cache() == 0 then
	--localized.ngx_log(localized.ngx_LOG_TYPE, " resp_content_type before " .. get_resp_content_type() )
	if localized.content_type_fix then
		get_resp_content_type(1) --fix for random bug where content-type output is application/octet-stream on text/html seems to only happen on a / directory not a /index.html
	end
	--localized.ngx_log(localized.ngx_LOG_TYPE, " resp_content_type after " .. get_resp_content_type() )
	if localized.exit_status then
		close_connection()
		localized.ngx_exit(localized.ngx_OK) --Go to content
	end
end

if localized.content_cache() ~= nil and #localized.content_cache() > 0 then

local function minification(content_type_list)

	local COOKIE_PAIR_PATTERN = "([^=;%s]+)%s*=%s*([^;%s]+)"
	local function grab_cookies(cookie_name_pattern, cookie_value_pattern, guest_value)
		local cookie_match = 0
		local guest_or_logged_in = 0

		local req_headers = localized.ngx_req_get_headers()
		local cookies = req_headers["cookie"]
		if not cookies then
			return cookie_match, guest_or_logged_in
		end

		-- Check if search targets contain pattern characters. If not, use plain byte-matching.
		local plain_name = not localized.string_find(cookie_name_pattern, "[%.%*%-%+%?%^%$%%%[%]]")
		local plain_value = not localized.string_find(cookie_value_pattern, "[%.%*%-%+%?%^%$%%%[%]]")

		if localized.type(cookies) == "table" then
			for i = 1, #cookies do
				for c_name, c_val in localized.string_gmatch(cookies[i], COOKIE_PAIR_PATTERN) do
					if localized.string_find(c_name, cookie_name_pattern, 1, plain_name) and 
						localized.string_find(c_val, cookie_value_pattern, 1, plain_value) then
						cookie_match = 1
						if guest_value == 1 then
							guest_or_logged_in = 1
						end
						return cookie_match, guest_or_logged_in
					end
				end
			end
		else
			for c_name, c_val in localized.string_gmatch(cookies, COOKIE_PAIR_PATTERN) do
				if localized.string_find(c_name, cookie_name_pattern, 1, plain_name) and 
					localized.string_find(c_val, cookie_value_pattern, 1, plain_value) then
					cookie_match = 1
					if guest_value == 1 then
						guest_or_logged_in = 1
					end
					return cookie_match, guest_or_logged_in
				end
			end
		end
		return cookie_match, guest_or_logged_in
	end

	for i=1,#content_type_list do
		if faster_than_match(content_type_list[i][1]) or localized.string_find(localized.URL(), content_type_list[i][1]) then --if our host matches one in the table
			if content_type_list[i][10] == 1 then
				localized.ngx.header["X-Cache-Status"] = "MISS"
			end

			local request_method_match = 0
			local cookie_match = 0
			local guest_or_logged_in = 0
			local request_uri_match = 0
			if content_type_list[i][7] ~= "" then
				for a=1, #content_type_list[i][7] do
					if localized.ngx.req.get_method() == content_type_list[i][7][a] then
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
			if content_type_list[i][19] ~= "" and content_type_list[i][19] ~= nil then
				for a=1, #content_type_list[i][19] do
					local cookie_name = content_type_list[i][19][a][1]
					local cookie_value = content_type_list[i][19][a][2]
					cookie_match, guest_or_logged_in = grab_cookies(cookie_name, cookie_value, content_type_list[i][19][a][3])
				end
				--localized.ngx_log(localized.ngx_LOG_TYPE, "cookie_match " .. cookie_match .. " GUEST_or_logged_in " .. guest_or_logged_in )
				if cookie_match == 1 then
					cookie_match = 0
				else
					cookie_match = 1
				end
			end
			local ip_extend = nil
			if content_type_list[i][20] ~= "" and content_type_list[i][20] ~= nil then
				ip_extend = content_type_list[i][20]
			end
			if content_type_list[i][9] ~= "" and content_type_list[i][9] ~= nil then
				for a=1, #content_type_list[i][9] do
					if faster_than_match(content_type_list[i][9][a]) or localized.string_find(localized.request_uri(), content_type_list[i][9][a] ) then
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

				-- Extract the query string arguments directly to pass them into the subrequest
				local query_args = localized.ngx_var_args()

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
					local function check_ngx_io()
						if localized.cached_ngx_io ~= nil then
							return localized.cached_ngx_io
						end
						localized.cached_ngx_io = localized.pcall(localized.require, "ngx.io") --check if ngx.io library exists will be true or false
						return localized.cached_ngx_io
					end
					if check_ngx_io() and localized.read_file == nil then
						local read_file = localized.require("ngx.io")
						localized.read_file = read_file.open
					end
					if not check_ngx_io() and localized.read_file == nil then
						localized.read_file = io.open
					end
					local fh, err = localized.read_file(request_body_file, "r")
					if err then
						localized.ngx_status = localized.ngx_HTTP_INTERNAL_SERVER_ERROR
						localized.ngx_log(localized.ngx_LOG_TYPE, "error reading request_body_file:", err)
						return
						--goto end_for_loop
					end
					request_body = fh:read("*a")
					fh:close()
				end
				if request_body == nil then
					request_body = "" --set to empty string
				end

				local req_headers = localized.ngx_req_get_headers() --get all request headers

				local function check_resty_http()
					if localized.cached_restyhttp ~= nil then
						return localized.cached_restyhttp
					end
					localized.cached_restyhttp = localized.pcall(localized.require, "resty.http") --check if resty http library exists will be true or false
					return localized.cached_restyhttp
				end

				local cached = remote_cache(content_type_list[i][3], content_type_list[i][5])
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

					local key = localized.ngx.req.get_method() .. localized.scheme() .. "://" .. localized.host() .. content_type_list[i][12] .. cookie_string .. request_body --fastcgi_cache_key / proxy_cache_key - GET - https - :// - localized.host() - localized.request_uri() - request_header["cookie"] - request_body
					--localized.ngx_log(localized.ngx_LOG_TYPE, " full cache key is " .. key)

					local content_type_cache = cached:get(secure_storage(0, "content-type"..key)) or nil

					if content_type_cache == nil or content_type_cache == localized.ngx.null then
						if #content_type_list[i][6] > 0 then

							if content_type_list[i][13] and check_resty_http() then
								local httpc = localized.require("resty.http").new()
								local res = httpc:request_uri(content_type_list[i][12], {
									method = map[localized.ngx.req.get_method()],
									body = request_body, --localized.ngx.var.request_body,
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
														if content_type_list[i][2] == "" or content_type_list[i][2] == nil then
															content_type_header_match = 0
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
													localized.ngx.header.content_type = content_type_list[i][2]
													if content_type_list[i][10] == 1 then
														localized.ngx.header["X-Cache-Status"] = "UPDATING"
													end
													if localized.resty_redis == 1 then
														cached:set(secure_storage(1, key), secure_storage(4, output_minified))
														cached:expire(secure_storage(2, key), ttl)
														cached:set(secure_storage(1, "s"..key), secure_storage(4, res.status))
														cached:expire(secure_storage(2, "s"..key), ttl)
													else
														cached:set(secure_storage(1, key), secure_storage(4, output_minified), ttl)
														cached:set(secure_storage(1, "s"..key), secure_storage(4, res.status), ttl)
													end
													if res.headers ~= nil and localized.type(res.headers) == "table" then
														for headerName, header in localized.next, res.headers do
															local header_original = headerName --so we do not make the header all lower case on insert
															if content_type_list[i][17] ~= "" or #content_type_list[i][17] > 0 then
																for a=1, #content_type_list[i][17] do
																	if localized.string_lower(localized.tostring(header_original)) == localized.string_lower(content_type_list[i][17][a]) then
																		if localized.resty_redis == 1 then
																			cached:set(secure_storage(1, localized.string_lower(localized.tostring(header_original))..key), secure_storage(4, header))
																			cached:expire(secure_storage(2, localized.string_lower(localized.tostring(header_original))..key), ttl)
																		else
																			cached:set(secure_storage(1, localized.string_lower(localized.tostring(header_original))..key), secure_storage(4, header), ttl)
																		end
																	end
																end
															end
															--localized.ngx_log(localized.ngx_LOG_TYPE, " header name" .. headerName .. " value " .. header )
															localized.ngx.header[headerName] = header
														end
													end
													if content_type_list[i][11] == 1 or content_type_list[i][11] == 3 and guest_or_logged_in == 0 then
														localized.ngx.header["Set-Cookie"] = nil
													end
													localized.ngx.header["Content-Length"] = #output_minified
													--localized.ngx_status = res.status
													localized.ngx_status = response_status_match(res.status)
													localized.ngx_say(output_minified)
													close_connection(1)
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
								method = map[localized.ngx.req.get_method()],
								body = request_body, --localized.ngx.var.request_body,
								args = query_args,
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
														if content_type_list[i][2] == "" or content_type_list[i][2] == nil then
															content_type_header_match = 0
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
													localized.ngx.header.content_type = content_type_list[i][2]
													if content_type_list[i][10] == 1 then
														localized.ngx.header["X-Cache-Status"] = "UPDATING"
													end
													if localized.resty_redis == 1 then
														cached:set(secure_storage(1, key), secure_storage(4, output_minified))
														cached:expire(secure_storage(2, key), ttl)
														cached:set(secure_storage(1, "s"..key), secure_storage(4, res.status))
														cached:expire(secure_storage(2, "s"..key), ttl)
													else
														cached:set(secure_storage(1, key), secure_storage(4, output_minified), ttl)
														cached:set(secure_storage(1, "s"..key), secure_storage(4, res.status), ttl)
													end
													if res.header ~= nil and localized.type(res.header) == "table" then
														for headerName, header in localized.next, res.header do
															local header_original = headerName --so we do not make the header all lower case on insert
															if content_type_list[i][17] ~= "" or #content_type_list[i][17] > 0 then
																for a=1, #content_type_list[i][17] do
																	if localized.string_lower(localized.tostring(header_original)) == localized.string_lower(content_type_list[i][17][a]) then
																		if localized.resty_redis == 1 then
																				cached:set(secure_storage(1, localized.string_lower(localized.tostring(header_original))..key), secure_storage(4, header))
																				cached:expire(secure_storage(2, localized.string_lower(localized.tostring(header_original))..key), ttl)
																		else
																			cached:set(secure_storage(1, localized.string_lower(localized.tostring(header_original))..key), secure_storage(4, header), ttl)
																		end
																	end
																end
															end
															--localized.ngx_log(localized.ngx_LOG_TYPE, " header name" .. headerName .. " value " .. header )
															localized.ngx.header[headerName] = header
														end
													end
													if content_type_list[i][11] == 1 or content_type_list[i][11] == 3 and guest_or_logged_in == 0 then
														localized.ngx.header["Set-Cookie"] = nil
													end
													localized.ngx.header["Content-Length"] = #output_minified
													--localized.ngx_status = res.status
													localized.ngx_status = response_status_match(res.status)
													localized.ngx_say(output_minified)
													close_connection(1)
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

						content_type_cache = secure_storage(0, content_type_cache, 2) --get was encrypted this should decrypt it
						if content_type_cache and (content_type_list[i][2] == "" or content_type_list[i][2] == nil or localized.string_find(content_type_cache, content_type_list[i][2])) then
						--if content_type_cache and localized.string_find(content_type_cache, content_type_list[i][2]) then
							localized.get_resp_content_type_counter = localized.get_resp_content_type_counter+2 --make sure we dont run again

							if content_type_list[i][5] == 1 then
								localized.ngx_log(localized.ngx_LOG_TYPE, "[Anti-DDoS][Cache] Served from cache key : " .. key )
							end

							local output_minified = cached:get(secure_storage(0, key))
							output_minified = secure_storage(0, output_minified, 2) --get was encrypted this should decrypt it
							local res_status = cached:get(secure_storage(0, "s"..key))
							res_status = secure_storage(0, res_status, 2) --numeric data is not encrypted

							if ip_extend == 1 then
								if localized.resty_redis == 1 then
									cached:set(secure_storage(1, "content-type"..key), cached:get(secure_storage(0, "content-type"..key)))
									cached:expire(secure_storage(2, "content-type"..key), ttl)
									cached:set(secure_storage(1, key), cached:get(secure_storage(0, key)))
									cached:expire(secure_storage(2, key), ttl)
									cached:set(secure_storage(1, "s"..key), cached:get(secure_storage(0, "s"..key)))
									cached:expire(secure_storage(2, "s"..key), ttl)
								else
									cached:set(secure_storage(1, "content-type"..key), cached:get(secure_storage(0, "content-type"..key)), ttl) --content_type_cache
									cached:set(secure_storage(1, key), cached:get(secure_storage(0, key)), ttl) --output_minified
									cached:set(secure_storage(1, "s"..key), cached:get(secure_storage(0, "s"..key)), ttl) --res_status
								end
							end

							--localized.ngx.header.content_type = content_type_list[i][2]
							if content_type_list[i][10] == 1 then
								localized.ngx.header["X-Cache-Status"] = "HIT"
							end
							if content_type_list[i][17] ~= "" or #content_type_list[i][17] > 0 then
								for a=1, #content_type_list[i][17] do
									local header_name = localized.string_lower(content_type_list[i][17][a])
									local check_header = cached:get(secure_storage(0, header_name..key)) or nil
									if check_header ~= nil and check_header ~= localized.ngx.null then
										--if header_name ~= "content-length" then
										check_header = secure_storage(0, check_header, 2) --get was encrypted this should decrypt it
										--end
										if ip_extend == 1 then
											if localized.resty_redis == 1 then
												cached:set(secure_storage(1, header_name..key), cached:get(secure_storage(0, header_name..key)))
												cached:expire(secure_storage(2, header_name..key), ttl)
											else
												cached:set(secure_storage(1, header_name..key), cached:get(secure_storage(0, header_name..key)), ttl)
											end
										end
										--localized.ngx_log(localized.ngx_LOG_TYPE, " check_header " .. check_header .. " - header_name - " .. header_name)
										localized.ngx.header[header_name] = check_header
									end
								end
							end
							if content_type_list[i][11] == 1 or content_type_list[i][11] == 2 and guest_or_logged_in == 0 or guest_or_logged_in == 1 then
								localized.ngx.header["Set-Cookie"] = nil
							end
							localized.ngx.header["Content-Length"] = #output_minified
							--localized.ngx_status = res_status
							localized.ngx_status = response_status_match(res_status)
							localized.ngx_say(output_minified)
							close_connection(1)
							localized.ngx_exit(localized.tonumber(response_status_match(res_status)))
							--localized.ngx_exit(res_status)

						end
					end --if content_type_cache == nil then

				else --shared mem zone not specified
					if #content_type_list[i][6] > 0 then
						--[[]]
						if content_type_list[i][13] and check_resty_http() then
							local httpc = localized.require("resty.http").new()
							local res = httpc:request_uri(content_type_list[i][12], {
								method = map[localized.ngx.req.get_method()],
								body = request_body, --localized.ngx.var.request_body,
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
													if content_type_list[i][2] == "" or content_type_list[i][2] == nil then
														content_type_header_match = 0
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
														localized.ngx.header[headerName] = header
													end
												end
												--if content_type_list[i][11] == 1 or content_type_list[i][11] == 3 and guest_or_logged_in == 0 then
													--localized.ngx.header["Set-Cookie"] = nil
												--end
												localized.ngx.header["Content-Length"] = #output_minified
												--localized.ngx_status = res.status
												localized.ngx_status = response_status_match(res.status)
												localized.ngx_say(output_minified)
												close_connection(1)
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
							method = map[localized.ngx.req.get_method()],
							body = request_body, --localized.ngx.var.request_body,
							args = query_args,
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
													if content_type_list[i][2] == "" or content_type_list[i][2] == nil then
														content_type_header_match = 0
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
														localized.ngx.header[headerName] = header
													end
												end
												--if content_type_list[i][11] == 1 or content_type_list[i][11] == 3 and guest_or_logged_in == 0 then
													--localized.ngx.header["Set-Cookie"] = nil
												--end
												localized.ngx.header["Content-Length"] = #output_minified
												--localized.ngx_status = res.status
												localized.ngx_status = response_status_match(res.status)
												localized.ngx_say(output_minified)
												close_connection(1)
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
			--localized.ngx_log(localized.ngx_LOG_TYPE, "count is " .. i .. " " .. localized.get_resp_content_type_counter .. " resp_content_type before " .. get_resp_content_type() .. " and " .. localized.ngx.header["Content-Type"] )
			if localized.content_type_fix then
				get_resp_content_type(1) --fix for random bug where content-type output is application/octet-stream on text/html seems to only happen on a / directory not a /index.html
			end
			--localized.ngx_log(localized.ngx_LOG_TYPE, localized.get_resp_content_type_counter .. " resp_content_type after " .. get_resp_content_type() )
		end

	end --end content_type foreach mime type table check
end --end minification function

minification(localized.content_cache())
end

if localized.anti_ddos_table() ~= nil and #localized.anti_ddos_table() > 0 then
close_connection()
end
if localized.content_cache() ~= nil and #localized.content_cache() > 0 then
close_connection(1)
end
