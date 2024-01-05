--[[
规则名称: anti cc

过滤阶段: 请求阶段

危险等级: 中危

规则描述: 当一分钟访问/api/路径频率超过360次，则在5分钟内拦截该ip访问
--]]


if not waf.startWith(waf.toLower(waf.uri), "/api/") then
    return false
end

local sh = waf.ipCache
local ccIp = 'cc-' .. waf.ip
local c, f = sh:get(ccIp)
if not c then
    sh:set(ccIp, 1, 60, 1)           -- 设置1分钟也就是60秒访问计数时间
else
    if f == 2 then
        return waf.block(true)       -- 重置TCP连接，不记录日志
    end
    sh:incr(ccIp, 1)
    if c + 1 >= 360 then             -- 频率超过360次
        sh:set(ccIp, c + 1, 300, 2)  -- 设置5分钟也就是300秒拦截时间
        return true, ccIp, true      -- 返回参数，第一个true为是否检测到；第二个参数ccIp为日志记录内容；第三个参数true表示拦截，false表示只记录不拦截
    end
end

return false
