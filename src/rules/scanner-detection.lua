--[[
Rule name: Scanner detection
Filtering stage: Request phase
Threat level: Medium
Rule description: Detecting common scanners such as awvs, sqlmap, nessus, appscan, nmap, etc., intercepting them can help reduce the risk of hackers discovering vulnerabilities
--]]


local m, d = waf.plugins.scannerDetection.check()
if m then
    return true, d, true
end

return false