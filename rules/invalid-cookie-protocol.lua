--[[
Rule name: Invalid cookie protocol
Filtering stage: Request phase
Threat level: High
Rule description: Too many cookie parameters
--]]


if waf.cookies == nil then
     return true,waf.cErr,true
end

return false