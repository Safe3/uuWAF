--[[
Rule name: JSON command injection detection
Filtering stage: Request phase
Threat level: Critical
Rule description: Parse the JSON content in the request body and detect command injection attacks. The RCE semantic detection engine can be used to check various deformations, such as: cat$IFS/etc/os-release or c$()at /e??/p????? , etc.
--]]


local function rMatch(v)
    if waf.checkRCE(v) then
        return true, v
    end
    return false
end

local form = waf.form
if form then
    local m, d = waf.jsonFilter(form["RAW"], rMatch, false, true)
    if m then
        return m, d, true
    end
end

return false