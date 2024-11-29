--[[
Rule name: Force HTTPS
Filtering stage: Request phase
Threat level: Low
Rule description: Redirects insecure HTTP requests to HTTPS
--]]


if waf.scheme == "http" then
    return waf.redirect("https://" .. waf.host .. waf.reqUri)
end
return false