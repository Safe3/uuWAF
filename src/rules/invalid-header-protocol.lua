--[[
Rule name: Invalid protocol
Filtering stage: Request phase
Threat level: Critical
Rule description: There are too many request headers, exceeding 64.
--]]


if waf.hErr and waf.hErr == "truncated" then
     return true,waf.hErr,true
end
return false