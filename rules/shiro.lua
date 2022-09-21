--[[
规则名称: shiro反序列化
过滤阶段: 请求阶段
危险等级: 高危
规则描述: shiro反序列化利用过程中得猜解利用链过程将会出现长Cookie，在平常业务中很难遇到。
--]]


local rgx = waf.rgxMatch
local kvFilter = waf.kvFilter

local function rMatch(v)
    local m =  rgx(v, "[^\\;\\n]{2000,}?(\\;|$|\\n)", "jo")
    if m then
        return m, v
    end
    return false
end

local cookies = waf.cookies
if cookies then
    local m, d = kvFilter(cookies, rMatch, true)
    if m then
        return m, d, true
    end
end
return false
