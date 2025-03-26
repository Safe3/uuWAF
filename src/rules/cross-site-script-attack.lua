--[[
Rule name: Cross Site Script Attack
Filtering stage: Request phase
Threat level: Critical
Rule description: Attackers typically insert JavaScript, VBScript, ActiveX, or Flash into vulnerable programs to deceive users. Once successful, they can steal user accounts, modify user settings, steal/contaminate cookies, create false advertising, and more
--]]


local kvFilter = waf.kvFilter
local checkXSS = waf.checkXSS

local function sMatch(v)
    local m = checkXSS(v) or waf.rgxMatch(v,"\\b(?:parent|frames|window|this|self|globalThis|top)\\s*(?:/\\*|\\[\\s*['/\"\\(])|\\.\\s*(?:constructor|getPrototypeOf)\\s*\\(","jos")
    if m then
        return m, v
    end
    return false
end

local form = waf.form
if form then
    local m, d = kvFilter(form["FORM"], sMatch)
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

local m, d = sMatch(waf.userAgent)
if m then
    return m, d, true
end

m, d = sMatch(waf.urlDecode(waf.referer))
if m then
    return m, d, true
end

return false