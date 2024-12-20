--[[
规则名称: 防止爆破登录
过滤阶段: 请求阶段
危险等级: 高危
规则描述: 针对路径中包含登录、注册等关键词的URL特征，如果5分钟(300秒)内请求次数超过10次，则封禁该IP 1440分钟（24小时）
--]]

local sh = waf.ipCache
local bruteForceKey = 'brute-force-login:' .. waf.ip  -- 使用独立前缀标识，避免与其他规则冲突

-- 定义特征路径关键词列表
local targetPaths = { "login", "signin", "signup", "register", "reset", "passwd", "account", "user" }

-- 判断URI是否包含特征关键词
if not waf.pmMatch(waf.toLower(waf.uri), targetPaths) then
    return false -- 如果路径中不包含任何特征关键词，则跳过检测
end

-- 获取缓存中的数据
local requestCount, flag = sh:get(bruteForceKey)
if not requestCount then
    -- 初始化计数，设置5分钟（300秒）的时间窗口
    sh:set(bruteForceKey, 1, 300, 1)
else
    -- 如果标志已经为2，则IP处于封禁状态，直接拦截
    if flag == 2 then
        return waf.block(true)  -- 阻断请求，返回403响应
    end

    -- 增加非法请求次数
    sh:incr(bruteForceKey, 1)
    if requestCount + 1 > 10 then
        -- 达到爆破攻击检测阈值，标记为封禁状态，封禁时间为1440分钟（24小时）
        sh:set(bruteForceKey, requestCount + 1, 86400, 2)
        return true, "检测到登录接口发生爆破攻击，已封禁IP", true -- 日志载荷改为中文
    end
end

return false
