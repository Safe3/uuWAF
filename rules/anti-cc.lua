--[[
规则名称: anti cc

过滤阶段: 请求阶段

危险等级: 中危

规则描述: 当一分钟访问/api/路径频率超过360次，则在5分钟内拦截该ip访问
--]]


if not waf.startWith(waf.toLower(waf.uri), "/api/") then
    return false
end

local sh = ngx.shared.ipCache
local c, f = sh:get(waf.ip)
if not c then
    sh:set("cc" .. waf.ip, 0, 60, 1)
else
    if f == 2 then
        return ngx.exit(403)
    end
    sh:incr('cc-' .. waf.ip, 1)
    if c >= 360 then
        sh:set("cc" .. waf.ip, c, 300, 2)
    end
end

return false
