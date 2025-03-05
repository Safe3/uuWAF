--[[
Rule name: Invalid post protocol
Filtering stage: Request phase
Threat level: Critical
Rule description: Illegal Post Protocol
--]]


if waf.fErr then
    if waf.fErr == "unknown" then
        return false
    end
    return true, waf.fErr, true
end

return false