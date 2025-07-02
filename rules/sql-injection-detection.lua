--[[
Rule name: SQL injection detection
Filtering stage: Request phase
Threat level: Critical
Rule description: Detect SQL injection attacks in URLs, cookies, forms, and headers. Using SQL semantic detection engine can reduce false positives.
--]]


local checkSQLI = waf.checkSQLI
local kvFilter = waf.kvFilter

local function match(v)
    if checkSQLI(v) then
        return true, v
    end
    return false
end

local function sMatch(v)
    if checkSQLI(v, 3) then
        return true, v
    end
    return false
end

local form = waf.form
if form then
    local m, d = kvFilter(form["FORM"], sMatch, true)
    if m then
        return m, d, true
    end
end

local queryString = waf.queryString
if queryString then
    local m, d = kvFilter(queryString, sMatch)
    if m then
        return m, d, true
    end
end

local cookies = waf.cookies
if cookies then
    local m, d = kvFilter(cookies, sMatch)
    if m then
        return m, d, true
    end
end

local m, d = kvFilter(waf.reqHeaders, match)
if m then
    return m, d, true
end

return false