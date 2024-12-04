--[[
Rule name: Turnstile challenge
Filtering stage: Request phase
Threat level: Low
Rule description: Use cloudflare turnstile challenge to deny robot, you should get free cloudflare turnstile sitekey and secret first, then set the values bellow.
--]]


local sitekey = ""
local secret = ""

if sitekey ~= "" and secret ~= "" then
      return waf.checkTurnstile(waf, sitekey, secret, 600, 18000)
end
return false
