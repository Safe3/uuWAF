--[[
Rule name: LDAP Injection
Filtering stage: Request phase
Threat level: Critical
Rule description: Intercept LDAP injection attacks
--]]


local kvFilter = waf.kvFilter
local rgx = waf.rgxMatch
local htmlEntityDecode = waf.htmlEntityDecode

local function rMatch(v)
    local m = rgx(htmlEntityDecode(v), "^[^:\\(\\)\\&\\|\\!\\<\\>\\~]*\\)\\s*(?:\\((?:[^,\\(\\)\\=\\&\\|\\!\\<\\>\\~]+[><~]?=|\\s*[&!|]\\s*(?:\\)|\\()?\\s*)|\\)\\s*\\(\\s*[\\&\\|\\!]\\s*|[&!|]\\s*\\([^\\(\\)\\=\\&\\|\\!\\<\\>\\~]+[><~]?=[^:\\(\\)\\&\\|\\!\\<\\>\\~]*)", "jos")
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