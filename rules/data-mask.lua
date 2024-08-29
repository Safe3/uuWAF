--[[
规则名称: 数据脱敏
过滤阶段: 返回页面阶段
危险等级: 中危
规则描述: 对返回页面中的身份证和手机号进行*替换脱敏
--]]


if waf.respContentLength == 0 or waf.respContentLength >= 2097152 then
    return
end

-- 只保留身份证号前2位和后2位
local newstr, _, err = waf.rgxGsub(waf.respBody, [[\b((1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5]|[7-9]1)\d{4}(18|19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx])\b]], function(m)
    return m[0]:sub(1, 2) .. "**************" .. m[0]:sub(-2)
end, "jos")
if not newstr then
    waf.errLog("error: ", err)
    return
end
waf.respBody = newstr
-- 只保留手机号前3位和后4位
newstr, _, err = waf.rgxGsub(waf.respBody, [[\b1(?:(((3[0-9])|(4[5-9])|(5[0-35-9])|(6[2,5-7])|(7[0135-8])|(8[0-9])|(9[0-35-9]))[ -]?\d{4}[ -]?\d{4})|((74)[ -]?[0-5]\d{3}[ -]?\d{4}))\b]], function(m)
    return m[0]:sub(1, 3) .. "****" .. m[0]:sub(-4)
end, "jos")
if not newstr then
    waf.errLog("error: ", err)
    return
end
waf.respBody = newstr
-- 通知南墙进行数据替换
waf.replaceFilter = true