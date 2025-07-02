--[[
Rule name: HTTP Splitting
Filtering stage: Request phase
Threat level: Critical
Rule description: This rule detects \n or \r in the request file name. reference resources: https://www.owasp.org/index.php/Testing_for_HTTP_Splitting/Smuggling_(OTG-INPVAL-016)
--]]


local rgx = waf.rgxMatch
local function fMatch(v)
    local m = rgx(v, "[\\n\\r]", "jo")
    if m then
        return m, v
    end
    return false
end
local m, d = fMatch(waf.uri)
if m then
    return m, d, true
end

return false