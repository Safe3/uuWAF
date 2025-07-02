--[[
Rule name: Java Security Rule Set
Filtering stage: Request phase
Threat level: Critical
Rule description: Detecting security vulnerabilities related to Spring, Struts, Java serialization, etc
--]]


local kvFilter = waf.kvFilter
local rgx = waf.rgxMatch
local check = waf.plugins.javaClassDetection.check

local function sMatch(v)
    local m = rgx(v, "(?:\\$\\{)+(?:j(?:n|\\$\\{)|\\$\\{(?:\\w*:)+)", "joi")
    if m then
        return m, "Potential Log4j / Log4shell Attack: " .. v
    end
    m = rgx(v, "^\\xac\\xed\\x00\\x05|\\b(?:aced0005|rO0AB[XQ]|KztAAU|Cs7QAF)", "jo")
    if m then
        return m, "Magic bytes Detected, probable java serialization Attack: " .. v
    end
    m = rgx(v, "[#\\.]\\s*context\\s*\\.\\s*[a-zA-Z]{3,}", "jos")
    if m then
        return m, "Spring Framework RCE: " .. v
    end
    m = check(v)
    if m then
        return m, "Potential dangerous java class: " .. v
    end
    return false
end

local function sMatch1(v)
    local m = rgx(v, "^\\s*\\{\\{.+\\}\\}\\s*$", "jos")
    if m then
        return m, "SSTI: " .. v
    end
    v = waf.base64Decode(v)
    if not v then
        return false
    end
    m = rgx(v, "^\\s*\\{\\{.+\\}\\}\\s*$", "jos")
    if m then
        return m, "SSTI: " .. v
    end
    m = rgx(v, "[#\\.]\\s*context\\s*\\.\\s*[a-zA-Z]{3,}", "jos")
    if m then
        return m, "Spring Framework RCE: " .. v
    end
    m = check(v)
    if m then
        return m, "Potential dangerous java class: " .. v
    end
    return false
end

if sMatch(waf.urlDecode(waf.reqUri)) then
    return true, waf.reqUri, true
end

local form = waf.form
if form then
    local m, d = kvFilter(form["FORM"], sMatch)
    if m then
        return m, d, true
    end
    local raw = form["RAW"]
    m = rgx(raw, "^\\xac\\xed\\x00\\x05|\\b(?:aced0005|rO0AB[XQ]|KztAAU|Cs7QAF)", "jo")
    if m then
        return m, raw, true
    end
    m = check(raw)
    if m then
        return m, raw, true
    end
end

local queryString = waf.queryString
if queryString then
    local m, d = kvFilter(queryString, sMatch)
    if m then
        return m, d, true
    end
    m, d = kvFilter(queryString, sMatch1)
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

local m, d = kvFilter(waf.reqHeaders, sMatch)
if m then
    return m, d, true
end

return false