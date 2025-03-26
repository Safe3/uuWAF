--[[
Rule name: Universal attack
Filtering stage: Request phase
Threat level: High
Rule description: This rule intercepts Ruby, Node, JS, Perl injection, and SSRF attacks
--]]


local kvFilter = waf.kvFilter
local rgx = waf.rgxMatch

local function sMatch(v)
    local m = rgx(v, "Process\\s*\\.\\s*spawn\\s*\\(", "jos")
    if m then
        return m, "Ruby Injection Attack: "..v
    end
    m = rgx(v, "t(?:his\\.constructor|runcateSync\\s*\\()|\\b(?:spawn|eval)\\s*\\(|_(?:\\$\\$ND_FUNC\\$\\$_|_js_function)|String\\s*\\.\\s*fromCharCode", "jos")
    if m then
        return m, "Node.js Injection Attack: "..v
    end
    m = rgx(v, "__proto__|constructor\\s*(?:\\.|\\[)\\s*prototype", "jos")
    if m then
        return m, "JavaScript Prototype Pollution: "..v
    end
    m = rgx(v, "(?:s(?:sh(?:2(?:.(?:s(?:(?:ft|c)p|hell)|tunnel|exec))?)?|m(?:[bs]|tps?)|vn(?:\\+ssh)?|n(?:ews|mp)|ips?|ftp|3)|p(?:op(?:3s?|2)|r(?:oxy|es)|h(?:ar|p)|aparazzi|syc)|c(?:ompress.(?:bzip2|zlib)|a(?:llto|p)|id|vs)|t(?:e(?:amspeak|lnet)|urns?|ftp)|f(?:i(?:nger|sh)|(?:ee)?d|tps?)|i(?:rc[6s]?|maps?|pps?|cap|ax)|d(?:a(?:ta|v)|n(?:tp|s)|ict)|m(?:a(?:ilto|ven)|umble|ms)|n(?:e(?:tdoc|ws)|ntps?|fs)|r(?:tm(?:f?p)?|sync|ar|mi)|v(?:iew-source|entrilo|nc)|a(?:ttachment|f[ps]|cap)|b(?:eshare|itcoin|lob)|g(?:o(?:pher)?|lob|it)|u(?:nreal|t2004|dp)|e(?:xpect|d2k)|h(?:ttps?|323)|w(?:ebcal|s?s)|ja(?:bbe)?r|x(?:mpp|ri)|ldap[is]?|ogg|zip):\\/\\/(?:(?:[\\d.]{0,11}(?:(?:\\xe2(?:\\x92(?:[\\x9c\\x9d\\x9e\\x9f\\xa0\\xa1\\xa2\\xa3\\xa4\\xa5\\xa6\\xa7\\xa8\\xa9\\xaa\\xab\\xac\\xad\\xae\\xaf\\xb0\\xb1\\xb2\\xb3\\xb4\\xb5]|[\\x88\\x89\\x8a\\x8b\\x8c\\x8d\\x8e\\x8f\\x90\\x91\\x92\\x93\\x94\\x95\\x96\\x97\\x98\\x99\\x9a\\x9b]|[\\xb6\\xb7\\xb8\\xb9\\xba\\xbb\\xbc\\xbd\\xbe\\xbf]|[\\x80\\x81\\x82\\x83\\x84\\x85\\x86\\x87])|\\x93(?:[\\x80\\x81\\x82\\x83\\x84\\x85\\x86\\x87\\x88\\x89\\x8a\\x8b\\x8c\\x8d\\x8e\\x8f]|[\\x9c\\x9d\\x9e\\x9f\\xa0\\xa1\\xa2\\xa3\\xa4\\xa5\\xa6\\xa7\\xa8\\xa9]|[\\x90\\x91\\x92\\x93\\x94\\x95\\x96\\x97\\x98\\x99\\x9a\\x9b]|[\\xbf\\xb5\\xb6\\xb7\\xb8\\xb9\\xba\\xbb\\xbc\\xbd\\xbe]|[\\xab\\xac\\xad\\xae\\xaf\\xb0\\xb1\\xb2\\xb3\\xb4])|\\x91(?:[\\xaa\\xa0\\xa1\\xa2\\xa3\\xa4\\xa5\\xa6\\xa7\\xa8\\xa9\\xaa\\xab\\xac\\xad\\xae\\xaf\\xb0\\xb1\\xb2\\xb3]|[\\xb4\\xb5\\xb6\\xb7\\xb8\\xb9\\xba\\xbb\\xbc\\xbd\\xbe\\xbf]))|\\xe3\\x80\\x82))+)|[a-z][\\w\\-\\.]{1,255}:\\d{1,5}(?:#?\\s*&?@(?:(?:\\d{1,3}\\.){3,3}\\d{1,3}|[a-z][\\w\\-\\.]{1,255}):\\d{1,5}\\/?)+|(?:0x[a-f0-9]{2}\\.){3}0x[a-f0-9]{2}|(?:0{1,4}\\d{1,3}\\.){3}0{1,4}\\d{1,3}|\\d{1,3}\\.(?:\\d{1,3}\\.\\d{5}|\\d{8})|0x(?:[a-f0-9]{16}|[a-f0-9]{8})|\\[[a-f\\d:]+(?:[\\d.]+|%\\w+)?\\]|(?:\\x5c\\x5c[a-z\\d-]\\.?_?)+|\\d{10})", "josi")
    if m then
        return m, "Possible Server Side Request Forgery (SSRF) Attack: "..v
    end
    m = rgx(v, "\\@\\{.*?\\}", "jos")
    if m then
        return m, "Perl Injection Attack: "..v
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

local m, d = kvFilter(waf.reqHeaders, sMatch)
if m then
    return m, d, true
end
return false
