--[[
Rule name: JSON SQL injection detection
Filtering stage: Request phase
Threat level: Critical
Rule description: Parse the JSON content in the request body and detect SQL injection attacks. Using SQL semantic detection engine can reduce false positives.
--]]


local function rMatch(v)
    if waf.checkSQLI(v, 2) then
        return true, v
    end
    return false
end

local form = waf.form
if form then
    local m, d = waf.jsonFilter(form["RAW"], rMatch, false)
    if m then
        return m, d, true
    end
end

return false