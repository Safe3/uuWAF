--[[
Rule name: PHP error detection
Filtering stage: Response body
Threat level: Low
Rule description: PHP errors returning to the page may leak sensitive server information
--]]


local check = waf.plugins.phpErrorDetection.check
local rb = waf.respBody

if waf.status == 500 then
    local m, d = check(rb)
    if m then
        return m, "php error: " .. d, true
    end
end

return false