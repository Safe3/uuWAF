--[[
Rule Name: Data Mask
Filtering stage: Response body phase
Threat level: Medium
Rule description: Replace and desensitize the ID card and phone number with * on the response page
--]]


if waf.respContentLength == 0 or waf.respContentLength >= 2097152 then
    return
end

-- Only the first two digits and the last two digits of the ID number number are reserved
local newstr, n, err = waf.rgxGsub(waf.respBody, [[\b((1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5]|[7-9]1)\d{4}(18|19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx])\b]], function(m)
    return m[0]:sub(1, 2) .. "**************" .. m[0]:sub(-2)
end, "jos")
if not newstr then
    waf.errLog("error: ", err)
    return
end
if n > 0 then
    waf.respBody = newstr
    -- Notify the UUSEC WAF to replace the data
    waf.replaceFilter = true
end

-- Only retain the first 3 and last 4 digits of the phone number
newstr, n, err = waf.rgxGsub(waf.respBody, [[\b1(?:(((3[0-9])|(4[5-9])|(5[0-35-9])|(6[2,5-7])|(7[0135-8])|(8[0-9])|(9[0-35-9]))[ -]?\d{4}[ -]?\d{4})|((74)[ -]?[0-5]\d{3}[ -]?\d{4}))\b]], function(m)
    return m[0]:sub(1, 3) .. "****" .. m[0]:sub(-4)
end, "jos")
if not newstr then
    waf.errLog("error: ", err)
    return
end
if n > 0 then
    waf.respBody = newstr
    waf.replaceFilter = true
end