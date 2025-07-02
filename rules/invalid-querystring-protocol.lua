--[[
Rule name: Invalid querystring protocol
Filtering stage: Request phase
Threat level: High
Rule description: Too many querystring parameters
--]]


if waf.queryString == nil then
     return true,waf.qErr,true
end

return false