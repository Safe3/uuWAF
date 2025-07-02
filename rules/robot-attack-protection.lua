--[[
Rule name: Robot Attack Protection
Filtering stage: Request phase
Threat level: Medium
Rule description: Intercept robot attacks such as vulnerability scanning, web crawling, CC attacks, and other automated attack behaviors by generating sliding rotation verification pictures, with a token validity period of 30 minutes
--]]


local sh = waf.ipCache
local robotIp = 'rb:' .. waf.ip
local c, f = sh:get(robotIp)

-- If it is a static page and no sliding rotation verification has been performed, return
if not (waf.isQueryString or waf.reqContentLength > 0) and f ~= 2 then
    return false
end

if not c then    
    sh:set(robotIp, 1, 60, 1)  -- Set 60 second access count time period
else
    if f == 2 then
        return waf.checkRobot(waf)     -- Start robot sliding rotation picture verification
    end
    sh:incr(robotIp, 1)
    if c + 1 >= 360 then
        -- Reached the threshold of requesting more than 360 times within 60 seconds and entered robot verification mode
        sh:set(robotIp, c + 1, 1800, 2)
        return true, robotIp, true
    end
end

return false
