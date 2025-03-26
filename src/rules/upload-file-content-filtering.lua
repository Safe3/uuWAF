--[[
Rule name: Upload file content filtering
Filtering stage: Request phase
Threat level: Critical
Rule description: Filter uploaded file content and intercept webshell uploads
--]]


local rgx = waf.rgxMatch
local function fileContentMatch(v)
    local m = rgx(v, "<\\?.+?\\$(?:GLOBALS|_(?:GET|POST|COOKIE|REQUEST|SERVER|FILES|SESSION|ENV))|<\\?php|<jsp:|<%(?i:!|\\s*@|.*?\\brequest\\s*(?:\\.|\\())", "jos")
    if m then
        return m, v
    end
    return false
end

if waf.form then
    local m, d = waf.knFilter(waf.form["FILES"], fileContentMatch, 0)
    return m, d, true
end

return false