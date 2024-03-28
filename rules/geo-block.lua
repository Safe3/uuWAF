--[[
规则名称: 区域访问限制

过滤阶段: 请求阶段

危险等级: 低危

规则描述: 限制非中国地区访问网站
--]]


local country, province, city = waf.ip2loc(waf.ip)
if country and country ~= "中国" then
    return true, "限制非中国地区访问", true
end
return false
