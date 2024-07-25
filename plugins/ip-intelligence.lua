---
--- Generated by UUSEC(https://www.uusec.com/)
--- Created by Safe3.
--- DateTime: 2024/7/25 11:11
---
local ngx = ngx
local ngx_exit = ngx.exit
local ngx_log = ngx.log
local ngx_err = ngx.ERR
local ngx_today = ngx.today
local ngx_kv = ngx.shared
local http = require("resty.http")
local ipmatcher = require("resty.ipmatcher")
local resty_lock = require("resty.lock")
local util = require("waf.util")

local _M = {
    version = 0.1,
    name = "ip-intelligence"
}

local matcher, today

local function init_matcher()
    local http_client = http.new()
    local res, err = http_client:request_uri("https://waf.uusec.com/ip-intelligence-feed.json")
    if not res then
        ngx_log(ngx_err, "get ip intelligence failed: ", err)
        return
    end
    res, err = util.jsonDecode(res.body)
    if not res then
        ngx_log(ngx_err, "decode ip intelligence feed failed: ", err)
        return
    end
    matcher = ipmatcher.new_with_value(res)
end

function _M.req_post_filter(waf)
    local lock, err, ok

    if (not today) or today ~= ngx_today() then
        matcher = nil
        today = ngx_today()
    end

    if not matcher then
        lock, err = resty_lock:new("lock")
        if not lock then
            ngx_log(ngx_err, "create ip_threat_lock failed: ", err)
            return nil
        end

        ok, err = lock:lock("ip_threat_lock")
        if not ok then
            return
        end

        if not matcher then
            init_matcher()
        end

        ok, err = lock:unlock()
        if not ok then
            ngx_log(ngx_err, "unlock ip_threat_lock failed: ", err)
        end
    end

    if matcher then
        local level = matcher:match(waf.ip)
        if level then
            waf.msg = "ip threat level: " .. level
            waf.rule_id = 10000
            waf.deny = true
            ngx_kv.ipBlock:incr(waf.ip, 1, 0)
            return ngx_exit(403)
        end
    end
end

return _M