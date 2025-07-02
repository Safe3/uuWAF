--[[
Rule name: HTTP Response Splitting
Filtering stage: Request phase
Threat level: Critical
Rule description: This rule searches for carriage return (CR) %0d and line break (LF) %0a characters. If data is returned in the response header, these characters may cause issues and may be interpreted by intermediate proxy servers as two separate responses. reference resources: http://projects.webappsec.org/HTTP-Response-Splitting
--]]


local kvFilter = waf.kvFilter
local rgx = waf.rgxMatch
local htmlEntityDecode = waf.htmlEntityDecode

local function rMatch(v)
    local m = rgx(v, "[\\r\\n]\\W*?(?:content-(?:type|length)|set-cookie|location):\\s*\\w", "josi")
    if m then
        return m, v
    end
    return false
end

local form = waf.form
if form then
    local m, d = kvFilter(form["FORM"], rMatch)
    if m then
        return m, d, true
    end
end

local queryString = waf.queryString
if queryString then
    local m, d = kvFilter(queryString, rMatch)
    if m then
        return m, d, true
    end
end

local cookies = waf.cookies
if cookies then
    local m, d = kvFilter(cookies, rMatch)
    if m then
        return m, d, true
    end
end

return false