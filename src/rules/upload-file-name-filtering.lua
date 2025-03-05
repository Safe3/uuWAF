--[[
Rule name: Upload file name filtering
Filtering stage: Request phase
Threat level: Critical
Rule description: Filter webpage script extensions in uploaded file names and block webshell uploads
--]]


local function fileNameMatch(v)
    v = waf.htmlEntityDecode(v)
    if v then
        local m =  waf.rgxMatch(v, "\\.(?:as|cer\\b|cdx|ph|jsp|war|class|exe|ht|env|user\\.ini)|php\\.ini", "joi")
        if m then
            return m, v
        end
    end
    return false
end
if waf.form then
    local m, d = waf.knFilter(waf.form["FILES"], fileNameMatch, 1)
    return m, d, true
end

return false