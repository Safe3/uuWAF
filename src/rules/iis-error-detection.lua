--[[
Rule name: IIS error detection
Filtering stage: Response body
Threat level: Low
Rule description: The error message returned by IIS may leak sensitive server information
--]]


local rgx = waf.rgxMatch
local rb = waf.respBody

local m = rgx(rb, "[a-z]:\\x5cinetpub\\b", "jo")
if m then
    return m, rb, true
end

if waf.status == 500 then
    local m = rgx(rb, "Microsoft OLE DB Provider for SQL Server(?:</font>.{1,20}?error '800(?:04005|40e31)'.{1,40}?Timeout expired| \\(0x80040e31\\)<br>Timeout expired<br>)|<h1>internal server error</h1>.*?<h2>part of the server has crashed or it has a configuration error\\.</h2>|cannot connect to the server: timed out", "jo")
    if m then
        return m, rb, true
    end
    local m = rgx(rb, "\\b(?:A(?:DODB\\.Command\\b.{0,100}?\\b(?:Application uses a value of the wrong type for the current operation\\b|error')| trappable error occurred in an external object\\. The script cannot continue running\\b)|Microsoft VBScript (?:compilation (?:\\(0x8|error)|runtime (?:Error|\\(0x8))\\b|Object required: '|error '800)|<b>Version Information:</b>(?:&nbsp;|\\s)(?:Microsoft \\.NET Framework|ASP\\.NET) Version:|>error 'ASP\\b|An Error Has Occurred|>Syntax error in string in query expression|/[Ee]rror[Mm]essage\\.aspx?\\?[Ee]rror\\b", "jo")
    if m then
        return m, rb, true
    end
end

if waf.status == 404 then
    local m = rgx(rb, "\\bServer Error in.{0,50}?\\bApplication\\b", "jo")
    if m then
        return m, rb, true
    end
end

return false