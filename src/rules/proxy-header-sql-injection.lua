--[[
Rule name: Proxy header SQL injection
Filtering stage: Request phase
Threat level: High
Rule description: Filter single quote SQL injection in X-Forwarded-For, X-Real-IP and Client-IP request headers in HTTP requests
--]]


local rip=waf.reqHeaders.x_forwarded_for
if rip then
	if type(rip) ~= "string" then
		return true,"Malform X-Forwarded-For",true
	elseif waf.contains(rip,"'") then
		return true,rip,true
	end
end
rip=waf.reqHeaders.client_ip
if rip then
	if type(rip) ~= "string" then
		return true,"Malform Client-IP",true
	elseif waf.contains(rip,"'") then
		return true,rip,true
	end
end
rip=waf.reqHeaders.x_real_ip
if rip then
	if type(rip) ~= "string" then
		return true,"Malform X-Real-IP",true
	elseif waf.contains(rip,"'") then
		return true,rip,true
	end
end

return false