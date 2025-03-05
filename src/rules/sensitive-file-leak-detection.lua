--[[
Rule name: Sensitive file leak detection
Filtering stage: Request phase
Threat level: Medium
Rule description: Detect the paths of various sensitive leaked files in URLs, such as svn, git, SQL, log, bak, etc., to prevent attackers from exploiting them
--]]


local m, d = waf.plugins.fileLeakDetection.check()
if m then
    return true, d, true
end

return false