--[[
Rule name: Boundary exception interception
Filtering stage: Request phase
Threat level: Critical
Rule description: Intercept the abnormal boundary of multipart/form data in the content type header of the request, for example, PHP did not comply with the RFC specification when uploading and parsing the boundary, resulting in incorrect parsing of commas.
--]]


local ct = waf.reqContentType

if ct then
    if type(ct) ~= "string" then
        return true, "Malform Content-Type", true
    elseif waf.contains(ct, "boundary") and (waf.strCounter(ct, "boundary") > 1 or not waf.rgxMatch(ct, "boundary=[0-9A-Za-z\\-]+$", "jo")) then
        return true, ct, true
    end
end

return false