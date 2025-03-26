--[[
Rule name: Remote File Inclusion (RFI)
Filtering stage: Request phase
Threat level: Critical
Rule description: The File Inclusion vulnerability allows an attacker to include a file, usually exploiting a "dynamic file inclusion" mechanisms implemented in the target application
--]]


local kvFilter = waf.kvFilter
local rgx = waf.rgxMatch
local host = waf.host
local counter = waf.strCounter
local str_find = string.find
local str_sub = string.sub

local function rMatch(v)
    local m = rgx(v, "^\\s*(?:(?:url|jar):)?(file|ftps?|gopher|ldap)://", "joi")
    if m then
        local i, j = str_find(v, waf.getRootDomain(host), 1, true)
        if i then
            if counter(str_sub(v, 1, j), "/") == 2 then
                return false
            end
        end
    end
    return m, v
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

return false