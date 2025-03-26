--[[
Rule name: PHP Security Rule Set
Filtering stage: Request phase
Threat level: High
Rule description: Detecting vulnerabilities related to object serialization in PHP
--]]


local kvFilter = waf.kvFilter
local rgx = waf.rgxMatch

local function sMatch(v)
    local m = rgx(v, "php://(?:std(?:in|out|err)|(?:in|out)put|fd|memory|temp|filter)|(?:ssh2(?:.(?:s(?:(?:ft|c)p|hell)|tunnel|exec))?|z(?:lib|ip)|(?:ph|r)ar|expect|bzip2|glob|ogg)://|\\bphpinfo\\s*\\(\\s*\\)", "joi")
    if m then
        return m, v
    end
    m = rgx(v, "[oOcC]:\\d+:\"\\w+\":\\d+:{.*?}", "jos")
    if m then
        return m, v
    end
    return false
end

local function fileContentMatch(v)
    local m = rgx(v, "<\\?.+?\\$_(?:GET|POST|COOKIE|REQUEST|SERVER|FILES|SESSION)|<\\?php", "jos")
    if m then
        return m, v
    end
    return false
end

if rgx(waf.uri, "\\.php\\.", "joi") then
    return true, waf.uri, true
end

local form = waf.form
if form then
    local m, d = kvFilter(form["FORM"], sMatch)
    if m then
        return m, d, true
    end
    m, d = waf.knFilter(form["FILES"], fileContentMatch, 0)
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

local m, d = kvFilter(waf.reqHeaders, sMatch)
if m then
    return m, d, true
end
return false