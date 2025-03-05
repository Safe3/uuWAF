--[[
Rule name: HTTP Request Smuggling
Filtering stage: Request phase
Threat level: Critical
Rule description: This rule searches for HTTP/WEBDAV method names that combine with the words HTTP/\d or CR/LF characters. This will point to an attempt to inject a second request into the request in order to bypass testing performed on the main request, such as the CVE9-20372 (Nginx<1.17.7 request smuggling vulnerability). reference resources: http://projects.webappsec.org/HTTP-Request-Smuggling
--]]


local kvFilter = waf.kvFilter
local rgx = waf.rgxMatch
local htmlEntityDecode = waf.htmlEntityDecode

local function rMatch(v)
    local m = rgx(htmlEntityDecode(v), "(?:get|post|head|options|connect|put|delete|trace|track|patch|propfind|propatch|mkcol|copy|move|lock|unlock)\\s+[^\\s]+\\s+http/\\d", "josi")
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
    m, d = rMatch(form["RAW"])
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