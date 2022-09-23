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
local ccIp = 'cc-' .. waf.ip
local c, f = sh:get(ccIp)
if not c then
    sh:set(ccIp, 1, 60, 1)  -- 设置1分钟也就是60秒访问计数时间
else
    if f == 2 then
        return waf.block(true)
    end
    sh:incr(ccIp, 1)
    if c + 1 >= 360 then
        sh:set(ccIp, c, 300, 2)  -- 设置5分钟也就是300秒拦截时间
    end
end

return false
