--[[
Rule name: Abnormal character encoding requests
Filtering stage: Request phase
Threat level: High
Rule description: Hackers typically use an exception charset in the Content Type header to define character set encoding to bypass WAF protection, such as IBM037, IBM500, cp875, etc
--]]


local rct = waf.reqContentType
local has = waf.contains
local counter = waf.strCounter
local rgx = waf.rgxMatch
if rct then
    rct = waf.toLower(rct)
    if has(rct, "charset") and (not rgx(rct, "charset\\s*=\\s*(utf\\-8|gbk|gb2312|iso\\-8859\\-1|iso\\-8859\\-15|windows\\-1252)","jo") or counter(rct, "charset") > 1) then
        return true, rct, true
    end
end
return false