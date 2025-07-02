--[[
Rule name: Path traversal attack
Filtering stage: Request phase
Threat level: High
Rule description: Detect path traversal attacks in URLs, uploaded files, or parameters. Using LFI semantic detection engine, it can check for examples such as: /////..\\..\\etc///passwd
--]]


local checkPT = waf.checkPT
local kvFilter = waf.kvFilter

local function ptMatch(v)
    local m = checkPT(v)
    if m then
        return m, v
    end
    return false
end

local function ptMatch1(v)
    local m = checkPT(v)
    if m then
        return m, v
    end
    m = checkPT(waf.base64Decode(v))
    if m then
        return m, v
    end
    return false
end

if checkPT(waf.uri) then
    return true, waf.uri, true
end

local form = waf.form
if form then
    local m, d = kvFilter(form["FORM"], ptMatch)
    if m then
        return m, d, true
    end
    m, d = waf.knFilter(waf.form["FILES"], ptMatch, 1)
    if m then
        return m, d, true
    end
end

local queryString = waf.queryString
if queryString then
    local m, d = kvFilter(queryString, ptMatch1)
    if m then
        return m, d, true
    end
end

local m, d = kvFilter(waf.reqHeaders, ptMatch)
if m then
    return m, d, true
end

return false