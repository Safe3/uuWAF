--[[
规则名称: 高频错误防护
过滤阶段: 返回HTTP头阶段
危险等级: 中危
规则描述: 监测频繁返回40x、50x错误，当60秒内出现这些错误10次以上，则封禁1440分钟。
--]]

local function isCommonError(status)
    -- 检查是否为40x或50x错误
    return status >= 400 and status < 600
end

-- 配置参数
local threshold = 10     -- 错误次数阈值
local timeWindow = 60    -- 时间窗口，单位为秒
local banDuration = 1440 * 60 -- 封禁时间，1440分钟 = 86400秒

-- 获取客户端IP
local ip = waf.ip

-- 获取返回的HTTP状态码
local status = waf.status

-- 检查当前请求是否是40x或者50x错误，不是则直接返回false
if not isCommonError(status) then
    return false
end

-- 使用 waf.ipCache 记录当前 IP 的错误次数
local errorCache = waf.ipCache
local errorKey = "error:" .. ip  -- 定义记录错误次数的键值，以 IP 为基础区分

local errorCount, flag = errorCache:get(errorKey)

-- 若当前记录不存在，初始化记录
if not errorCount then
    errorCache:set(errorKey, 1, timeWindow) -- 初始错误计数设置为1，并设置为60秒过期
else
    if flag == 2 then
        -- 标志为2表示该IP已被封禁，直接拦截，即刻终止
        return waf.block(true)
    end

    -- 累加错误计数
    errorCache:incr(errorKey, 1)
    if errorCount + 1 >= threshold then
        -- 达到错误频率阈值，标记当前IP为封禁状态
        errorCache:set(errorKey, errorCount + 1, banDuration, 2)
        return true, "高频错误触发，IP已被封禁", true
    end
end

return false
