--[[
规则名称: 频繁触发攻击拦截的IP拉黑
过滤阶段: 请求阶段
危险等级: 高危
规则描述: 检查当前请求的客户端IP是否在最近10分钟内频繁触发（超过30次）WAF的拦截，如果是，则拉黑IP 1440分钟，并记录日志。
注意: 因为南墙WAF特性，此规则生效对规则ID有要求，需要将此规则与南墙自带规则的第一个规则交换位置才能生效。
]]

local sh = waf.ipCache  -- 键值存储库，用于存储拉黑状态
local ip_stats = waf.ipBlock  -- 查询最近被南墙拦截的IP统计，如社区版本默认存储时间为10分钟
local ip = waf.ip
local block_key = "blocked-" .. ip -- 用于记录IP拉黑状态的key

-- 如果IP已经被拉黑则直接拦截
local c, f = sh:get(block_key)
if c and f == 2 then
    return waf.block(true)  -- 重置TCP连接，不返回任何内容
end

-- 检查该IP在最近时间内是否频繁被拦截
local recent_count = ip_stats:get(ip)
if recent_count and recent_count > 30 then
    -- 如果超过30次，则拉黑IP，设置1440分钟（24小时）
    sh:set(block_key, 1, 86400, 2)  -- 第三个参数86400为1440分钟（单位为秒），第四个参数2表示拉黑状态
    return true, "IP频繁触发拦截，已被拉黑", true  -- 记录日志并拦截
end

return false
