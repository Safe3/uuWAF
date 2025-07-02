--[[
Rule name: Java error detection
Filtering stage: Response body
Threat level: Low
Rule description: Java error returning to the page may leak sensitive server information
--]]


local check = waf.plugins.javaErrorDetection.check
local rb = waf.respBody

if waf.status == 500 then
    local m,d = check(rb)
    if m then
        return m, "Java error: " .. d, true
    end
end

return false