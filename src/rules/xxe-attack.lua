--[[
Rule name: XXE attack
Filtering stage: Request phase
Threat level: Critical
Rule description: The XML External Entity injection vulnerability, abbreviated as XXE vulnerability. When external entities are allowed to be referenced, constructing malicious content can lead to the reading of arbitrary files, execution of system commands, detection of internal network ports, attacks on internal network websites, and other hazards.
--]]


if waf.form and waf.form["RAW"] then
    local m = waf.rgxMatch(waf.form["RAW"], "<!(?:DOCTYPE|ENTITY)[^>]+?\\bSYSTEM\\b", "jos")
    if m then
        return m, waf.form["RAW"], true
    end
end

return false