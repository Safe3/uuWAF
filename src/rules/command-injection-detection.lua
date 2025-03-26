--[[
Rule name: Command injection detection
Filtering stage: Request phase
Threat level: Critical
Rule description: Detect shell command injection attacks in URLs, cookies, and forms. The RCE semantic detection engine can be used to detect various deformations, such as cat$IFS/etc/os-release or c$()at /e??/p?????, etc.
--]]


local checkRCE = waf.checkRCE
local kvFilter = waf.kvFilter

local function rMatch(v)
    if checkRCE(v, 1) then
        return true, v
    end
    return false
end

local function rMatch1(v)
    if checkRCE(v, 0) then
        return true, v
    end
    return false
end

local function rMatch2(v)
    if checkRCE(v, 2) then
        return true, v
    end
    return false
end

local form = waf.form
if form then
    local m, d = kvFilter(form["FORM"], rMatch, true)
    if m then
        return m, d, true
    end
end

local queryString = waf.queryString
if queryString then
    local m, d = kvFilter(queryString, rMatch2)
    if m then
        return m, d, true
    end
end

local cookies = waf.cookies
if cookies then
    local m, d = kvFilter(cookies, rMatch1, true)
    if m then
        return m, d, true
    end
end

local m, d = kvFilter(waf.reqHeaders, rMatch)
if m then
    return m, d, true
end
return false