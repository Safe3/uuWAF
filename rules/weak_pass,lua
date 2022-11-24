--[[
规则名称: 弱口令检测
过滤阶段: 请求阶段
危险等级: 中危
规则描述: 检测常见登录页面的弱口令问题
--]]


local check = waf.plugins.weakPwdDetection.check
local toLower = waf.toLower
local has = waf.contains

local form = waf.form
local uri = toLower(waf.reqUri)
if form and (has(uri, "login") or has(uri, "logon") or has(uri, "signin")) then
    local f = form["FORM"]
    if f then
        for k, v in pairs(f) do
            k = toLower(k)
            if (k == "pass" or has(k, "pwd") or has(k, "passwd") or has(k, "password")) and check(v) then
                return true, form["RAW"], true
            end
        end
    end
end

return false
