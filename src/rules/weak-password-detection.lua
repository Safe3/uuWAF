--[[
Rule name: Weak password detection
Filtering stage: Request phase
Threat level: Medium
Rule description: Detecting weak password issues on common login pages
--]]


local check = waf.plugins.weakPwdDetection.check
local toLower = waf.toLower
local has = waf.contains

local form = waf.form
local uri = toLower(waf.uri)
if form and (has(uri, "login") or has(uri, "logon") or has(uri, "signin")) then
    local f = form["FORM"]
    if f then
        for k, v in pairs(f) do
            k = toLower(k)
            if (k == "pass" or has(k, "pwd") or has(k, "passwd") or has(k, "password")) and check(v) then
                return true, form["RAW"], false
            end
        end
    end
end

return false