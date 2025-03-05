--[[
Rule name: Request body size limit
Filtering stage: Request phase
Threat level: Medium
Rule description: Limit the request body size to below 8M, hackers will attempt to bypass WAF filtering for large data packets
--]]


if waf.reqContentLength>8388608 then
    return true,"reqBody length is "..waf.reqContentLength ,true
end
return false