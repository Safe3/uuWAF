--[[
Rule name: Request method enhancement
Filtering stage: Request phase
Threat level: Low
Rule description: Less commonly used HTTP request methods may have some security vulnerabilities, such as XSS related vulnerabilities in the Apache platform's TRACE request method in history
--]]


if not waf.rgxMatch(waf.method, "^(?:GET|HEAD|POST|PUT|DELETE|OPTIONS)$") then
    return true, waf.method, true
end 