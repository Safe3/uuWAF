--[[
规则名称: http重定向https

过滤阶段: 请求阶段

危险等级: 低危

规则描述: 将不安全的http请求重定向到https
--]]


if waf.scheme == "http" then
    return waf.redirect("https://" .. waf.host)
end
return false