--[[
Rule name: Abnormal Cookies
Filtering stage: Request phase
Threat level: Medium
Rule description: Block outdated cookie versions with support for $Version and double quotation mark values to prevent WAF from being bypassed and to attack websites.
--]]


local headers = waf.reqHeaders

if headers then
    local cookies = headers.cookie
    if type(cookies) == "table" then
        cookies = table.concat(cookies, "; ")
    end
    if cookies and waf.rgxMatch(cookies, [[\$Version\b\s*=|=\s*"]], "jos") then
        return true, cookies, true
    end
end

return false
