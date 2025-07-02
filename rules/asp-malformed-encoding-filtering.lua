--[[
Rule name: ASP malformed encoding filtering
Filtering stage: Request phase
Threat level: Critical
Rule description: Abnormal encoding of Unicode in ASP can cause WAF bypass hazards
--]]


if waf.rgxMatch(waf.reqUri,"%u00(?:aa|ba|d0|de|e2|f0|fe)","i") then
   return true,waf.reqUri,true
end

return false