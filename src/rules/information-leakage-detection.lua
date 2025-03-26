--[[
Rule name: Information leakage detection
Filtering stage: Response body
Threat level: High
Rule description: Detecting list directory vulnerabilities and source code leaks from the return page
--]]


local rgx = waf.rgxMatch
local rb = waf.respBody

local m = rgx(rb, "<(?:TITLE>Index of.*?<H|title>Index of.*?<h)1>Index of|>\\[To Parent Directory\\]</[Aa]><br>", "jo")
if m then
    return m, "Directory Listing: " .. rb, true
end

m = rgx(rb, "^\\s*(?:#\\!\\s?/|<%|<\\?\\s*[^x]|<jsp:)", "jo")
if m then
    return m, "Source code leak: " .. rb, true
end

return false