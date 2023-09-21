--[[
规则名称: IP block

过滤阶段: 请求阶段

危险等级: 低危

规则描述: 手动添加对恶意IP进行封禁，类似IP黑名单
--]]


local ip = waf.ip
 
if waf.contains(ip,"10.20.11.193") then
       return waf.block(true)     -- 重置TCP连接，不记录日志
 end

return false
