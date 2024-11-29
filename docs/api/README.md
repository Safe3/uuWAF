
## :grapes: Rule

?> Here are some explanations of the variables and related functions used in the rules. For more rule writing methods, please refer to the numerous practical examples in rule management in the WAF management. The rule template can be found at: https://github.com/Safe3/uuWAF/blob/main/src/rules/anti-cc.lua A security rule against CC attacks. Welcome everyone to contribute  rules. For details, please refer to: https://uuwaf.uusec.com/#/guide/contribute .

### Example of Rules

```lua
--[[
Rule name: Anti CC
Filtering stage: Request phase
Threat level: Medium
Rule description: When the frequency of accessing /api/ path exceeds 360 times per minute, intercept the IP access within 5 minutes
--]]


if not waf.startWith(waf.toLower(waf.uri), "/api/") then
    return false
end

local sh = waf.ipCache
local ccIp = 'cc-' .. waf.ip
local c, f = sh:get(ccIp)
if not c then
    sh:set(ccIp, 1, 60, 1)            -- Set a 60 seconds access count time
else
    if f == 2 then
        return waf.block(true)       -- Reset TCP connection without logging
    end
    sh:incr(ccIp, 1)
    if c + 1 >= 360 then             -- Frequency exceeding 360 times
        sh:set(ccIp, c + 1, 300, 2)  -- Set a 300 second interception time
        return true, ccIp, true      -- Return parameter, the first 'true' is whether it has been detected; The second parameter 'ccIp' is the content of the log record; The third parameter 'true' indicates interception, while 'false' indicates only recording without interception
    end
end

return false
```




### Rule variables

#### Request phase variables
##### waf.ip
- Type: ``string``
- Value: ``Client IP``
- Usage: Read only, used to obtain client IP. The client IP source can be configured in WAF site management, and the retrieval method is the nth IP in reverse order in Socket, Header or X-Forwarded-For.

##### waf.scheme

- Type: ``string``
- Value: ``Request HTTP protocol, with values of string HTTP or HTTPS``
- Usage: Read only

##### waf.httpVersion

- Type: ``number``
- Value: ``HTTP protocol version, with values of 1.0, 1.1, 2.0, 3.0``
- Usage: Read only

##### waf.host

- Type: ``string``
- Value: ``HTTP host ``
- Usage: Read only

##### waf.ipBlock

- Type: ``table``
- Value: ``Key value store, used to store intercepted client IP addresses``
- Usage:  See [ngx.shared.DICT](https://github.com/openresty/lua-nginx-module?tab=readme-ov-file#ngxshareddict)

##### waf.ipCache

- Type: ``table``
- Value: ``Key value store, used to store client IP addresses``
- Usage: See [ngx.shared.DICT](https://github.com/openresty/lua-nginx-module?tab=readme-ov-file#ngxshareddict)

##### waf.requestLine

- Type: ``string``
- Value: ``Full original request line ``
- Usage: Read only

##### waf.uri

- Type: ``string``
- Value: ``Current URI in request, normalized``
- Usage: Read only

##### waf.method

- Type: ``string``
- Value: ``HTTP request method, usually “GET” or “POST”``
- Usage: Read only

##### waf.reqUri

- Type: ``string``
- Value: ``Full original request URI (with arguments)``
- Usage: Read only

##### waf.userAgent

- Type: ``string``
- Value: ``HTTP request User-Agent``
- Usage: Read only

##### waf.referer

- Type: ``string``
- Value: ``HTTP request Referer``
- Usage: Read only

##### waf.reqContentType

- Type: ``string``
- Value: ``HTTP request Content-Type``
- Usage: Read only

##### waf.XFF

- Type: ``string``
- Value: ``HTTP request X-Forwarded-For``
- Usage: Read only

##### waf.origin

- Type: ``string``
- Value: ``HTTP request Origin``
- Usage: Read only

##### waf.reqHeaders

- Type: ``table``
- Value: ``A Lua table holding all the current request headers``
- Usage: Read only

##### waf.hErr

- Type: ``string``
- Value: ``Request headers parsing error message``
- Usage: Read only

##### waf.isQueryString

- Type: ``bool``
- Value: ``true or false``
- Usage: Read only, is there a request parameter

##### waf.reqContentLength

- Type: ``number``
- Value: ``0``
- Usage: Read only, request body content length

##### waf.queryString

- Type: ``table``
- Value: ``Request URL parameters, key and value``
- Usage: Read only

##### waf.qErr

- Type: ``string``
- Value: ``Request query string parsing error message``
- Usage: Read only

##### waf.form

- Type: ``table``
- Value: ``Request body object``
- Usage: Read only

##### waf.form["RAW"]

- Type: ``string``
- Value: ``Request raw body data``
- Usage: Read only

##### waf.form["FORM"]

- Type: ``table``
- Value: ``Request post form parameters, key and value``
- Usage: Read only, value example: {uid="12",vid={[1]="select",[2]="a from b"}}

##### waf.form["FILES"]

- Type: ``table``
- Value: ``Upload files information in the parsed request body``
- Usage: Read only, value example:  {name={[1]="filename",[2]="file content"}}

##### waf.fErr

- Type: ``string``
- Value: ``Error message parsing request body``
- Usage: Read only, usually a malicious malformed request packet

##### waf.cookies

- Type: ``table``
- Value: ``Request cookie parameters, key and value``
- Usage: Read only

##### waf.cErr

- Type: ``string``
- Value: ``Error message parsing request cookie``
- Usage: Read only

#### Response header phase newly added variables

##### waf.status

- Type: ``number``
- Value: ``Presponse HTTP status, integer value``
- Usage: Read only

##### waf.respHeaders

- Type: ``table``
- Value: ``All headers responsed, including key and value``
- Usage: Read only

##### waf.respContentLength

- Type: ``number``
- Value: ``Response body content length``
- Usage: Read only

##### waf.respContentType

- Type: ``string``
- Value: ``Response body content type``
- Usage: Read only

####  Response body phase newly added variables

##### waf.respBody

- Type: ``string``
- Value: ``Response body``
- Usage: Read only

##### waf.replaceFilter

- Type: ``bool``
- Value: ``false``
- Usage: When the response content type is text/html, text/plain, json, or xml, notify the UUSEC WAF to replace the returned page content. Set waf.replaceFilter to true, which can be used in scenarios such as data anonymization and sensitive word replacement.

##### Rule example:

```lua
--[[
Rule Name: Data Mask
Filtering stage: Response body phase
Threat level: Medium
Rule description: Replace and desensitize the ID card and phone number with * on the response page
--]]


if waf.respContentLength == 0 or waf.respContentLength >= 2097152 then
    return
end

-- Only the first two digits and the last two digits of the ID number number are reserved
local newstr, n, err = waf.rgxGsub(waf.respBody, [[\b((1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5]|[7-9]1)\d{4}(18|19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx])\b]], function(m)
    return m[0]:sub(1, 2) .. "**************" .. m[0]:sub(-2)
end, "jos")
if not newstr then
    waf.errLog("error: ", err)
    return
end
if n > 0 then
    waf.respBody = newstr
    -- Notify the UUSEC WAF to replace the data
    waf.replaceFilter = true
end

-- Only retain the first 3 and last 4 digits of the phone number
newstr, n, err = waf.rgxGsub(waf.respBody, [[\b1(?:(((3[0-9])|(4[5-9])|(5[0-35-9])|(6[2,5-7])|(7[0135-8])|(8[0-9])|(9[0-35-9]))[ -]?\d{4}[ -]?\d{4})|((74)[ -]?[0-5]\d{3}[ -]?\d{4}))\b]], function(m)
    return m[0]:sub(1, 3) .. "****" .. m[0]:sub(-4)
end, "jos")
if not newstr then
    waf.errLog("error: ", err)
    return
end
if n > 0 then
    waf.respBody = newstr
    waf.replaceFilter = true
end
```



### Rule functions

#### Rule  API

##### waf.startWith(sstr,dstr)
- Parameters: ``sstr is the original string, dstr is the search string``
- Function: Determine whether the string sstr starts with dstr?
- Return values: ``true or false``

##### waf.endWith(sstr,dstr)

- Parameters: ``sstr is the original string, dstr is the search string``
- Function: Determine whether the string sstr ends with dstr?
- Return values: ``true or false``

##### waf.toLower(sstr)

- Parameters: ``sstr is the original string``
- Function: Convert string sstr to lowercase
- Return values: ``lowercase sstr``

##### waf.contains(sstr,dstr)

- Parameters: ``sstr is the original string, dstr is the search string``
- Function: Determine whether the string sstr is in the string dstr?
- Return values: ``true or false``

##### waf.regex(sstr,pat,ext)

- Parameters: ``sstr is the original string, pat is the regular expression, and ext is the regular attribute``
- Function: Match regular expression pat in string sstr, with the same usage as [ngx.re.match](https://github.com/openresty/lua-nginx-module?tab=readme-ov-file#ngxrematch)
- Return values: ``All matches, error``

##### waf.rgxMatch(sstr,pat,ext)

- Parameters: ``sstr is the original string, pat is the regular expression, and ext is the regular attribute``
- Function: Match regular expression pat in string sstr
- Return values: ``true or false``

##### waf.rgxGmatch(sstr,pat,ext)

- Parameters: ``sstr is the original string, pat is the regular expression, and ext is the regular attribute``
- Function: Match regular expression pat in string sstr, with the same usage as [ngx.re.gmatch](https://github.com/openresty/lua-nginx-module?tab=readme-ov-file#ngxregmatch)
- Return values: ``Iterator, error``

##### waf.rgxSub(subject, regex, replace, options?)

- Parameters: ``subject is the original string, regex is the regular expression, replace is the string to be replaced, options is the regular option``
- Function: Replace the content matched by the regular expression 'regex' in the string subject with 'replace', with the same usage as [ngx.re.sub](https://github.com/openresty/lua-nginx-module?tab=readme-ov-file#ngxresub)
- Return values: ``newstr, n, and err represent the new string, number of replacements, and error message, respectively``

##### waf.rgxGsub(subject, regex, replace, options?)

- Parameters: ``subject is the original string, regex is the regular expression, replace is the string to be replaced, options is the regular option``
- Function: Replace all contents matched by the regular expression 'regex' in the string 'subject' with 'replace', with the same usage as [ngx.re.gsub](https://github.com/openresty/lua-nginx-module?tab=readme-ov-file#ngxregsub)
- Return values: ``newstr, n, and err represent the new string, number of replacements, and error message, respectively``

##### waf.kvFilter(v,match,valOnly)

- Parameters: ``v is the object to be matched, match is the matching function, and valOnly is true to match only value``
- Function: Used to match cookie, query string, and other key value pairs of data, using the match function to match content in object v
- Return values: ``true, matches content or false, nil``

##### waf.knFilter(v,match,p)

- Parameters: ``v is the object to be matched, match is the matching function, when p is 1, match the uploaded file name, and when p is 0, match the file content``
- Function: Used to filter uploaded file information and match content in object v using the match function
- Return values: ``true, matches content or false, nil``

##### waf.jsonFilter(v, match,parsed,valOnly)

- Parameters: ``v is the object to be matched, match is the matching function, when parsed as false, the parsing type is string v value, when parsed as true, the parsing type is table v value, and when valOnly is true, only value is matched``
- Function: Used to traverse and filter JSON data in requests, and use the match function to match content in object v
- Return values: ``true, matches content or false, nil``

##### waf.base64Decode(str)

- Parameters: ``str is the base64 string to be decoded``
- Function: Used to decode base64 data into plaintext data
- Return values: ``plaintext or nil``

##### waf.checkSQLI(str, level?)

- Parameters: ``str is the string to be detected; level can be omitted, it is a strict level, the larger the value, the stricter it is, ranging from 0 to 3``
- Function: Detecting SQL injection attacks based on semantic engine
- Return values: ``true or false``

##### waf.checkRCE(str, level?)

- Parameters: ``str is the string to be detected; level can be omitted, it is a strict level, the larger the value, the stricter it is, ranging from 0 to 3``
- Function: Detecting command injection attacks based on semantic engine
- Return values: ``true or false``

##### waf.checkPT(str)

- Parameters: ``str is the string to be detected``
- Function: Detecting path traversal attacks based on semantic engine
- Return values: ``true or false``

##### waf.checkXSS(str)

- Parameters: ``str is the string to be detected``
- Function: Detecting XSS attacks based on semantic engine
- Return values: ``true or false``

##### waf.strCounter(sstr,dstr)

- Parameters: ``sstr is the original string, dstr is the search string``
- Function: Calculate the number of times the string dstr appears in sstr
- Return values: ``integer``

##### waf.trim(str)

- Parameters: ``sstr is the original string``
- Function: Remove spaces on both sides of the string str
- Return values: ``The string after removing the spaces on both sides``

##### waf.inArray(str,arr)

- Parameters: ``str is the original string, arr is the string array``
- Function: Determine whether the string str exists in the arr string array
- Return values: ``true or false``

##### waf.pmMatch(sstr,dict)

- Parameters: ``sstr is the original string, dict is the lookup dictionary, in the form of a Lua table, such as {"aaa", "bbb", "ccc"}``

- Function: Efficient multi-mode matching of multiple strings, returns immediately upon discovering one of the strings

- Return values: ``true, string in dictionary or false, nil``

##### waf.urlDecode(sstr)

- Parameters: ``sstr is the original string``
- Function: Decode the URL of sstr
- Return values: ``Decoded string``

##### waf.htmlEntityDecode(sstr)

- Parameters: ``sstr is the original string``
- Function: Decoding HTML entities from string sstr
- Return values: ``Decoded string``

##### waf.hexDecode(sstr)

- Parameters: ``sstr is the original string``
- Function: Decode the string sstr using hex decoding
- Return values: ``Decoded string``

##### waf.block(reset)

- Parameters: ``When reset to true, directly reset TCP without returning any content, otherwise return page 403``
- Function: Intercept client requests, directly reset client connection or return 403 page, used in conjunction with return

##### waf.checkRobot(waf, expireTime?, max?)

- Parameters: ``waf is a fixed lua object; After successful authentication, if the current IP time reaches expireTime (in seconds, default value of 600, does not expire when value is 0) or the number of requests reaches max (default value of 18000, unlimited when value is 0), the verification page will be displayed again``
- Function: Detect robot attacks such as data crawlers, scanning attacks, CC denial of service attacks, etc., and generate sliding and rotating image verification, which can be used in conjunction with returns

##### waf.checkTurnstile(waf, siteKey, secret, expireTime?, max?)

- Parameters: ``waf is a fixed lua object; siteKey and secret are configuration parameters for Cloudflare Turnstile; After successful authentication, if the current IP time reaches expireTime (in seconds, default value of 600, does not expire when value is 0) or the number of requests reaches max (default value of 18000, unlimited when value is 0), the verification page will be displayed again``
- Function: Use Cloudflare Turnstile for automatic human-machine verification, detect robot attacks such as data crawlers, scanning attacks, CC denial of service attacks, etc., and use it in conjunction with return

##### waf.redirect(uri, status?)

- Parameters: ``URI is the redirected link, status is the return HTTP status (optional), default is 302``
- Function: redirects client requests to a new link, used in conjunction with a return

##### waf.ip2loc(ip, lang?)

- Parameters: ``ip is the IP address to be queried, lang is the display language, such as en, zh-CN, etc. The default value is "en"``
- Function: Convert IP addresses into geographic location information for country, province, and city
- Return values: ``country、 province、 city``

##### waf.errLog(...)

- Parameters: ``One or more strings``
- Function: Record error logs to /uuwaf/logs/error. log
- Return values: ``None``




## :melon: Plugin

?>The UUSEC WAF supports powerful plugin extension functions, making it convenient for users to implement some unique features on their own. The plugin template can be found at: https://github.com/Safe3/uuWAF/blob/main/src/plugins/kafka-logger.lua , a Kafka logging plugin. Welcome everyone to contribute security plugins. For details, please refer to: https://uuwaf.uusec.com/#/guide/contribute .

### Plugin development

A standard plugin consists of the following parts, each of which can be omitted if there is no functional implementation. Each major stage is divided into two sub stages, pre and post, representing the pre execution and post execution of the UUSEC WAF logic processing, respectively.

```lua
local _M = {
    version = 0.1,          --  Plugin version
    name = "kafka-logger"   --  Plugin name
}

-- SSL pre phase filtering
function _M.ssl_pre_filter(waf)

end

-- SSL phase post filtering
function _M.ssl_post_filter(waf)

end

-- Pre request filtering phase
function _M.req_pre_filter(waf)

end

-- Post request filtering phase
function _M.req_post_filter(waf)

end

-- Filter before response header phase
function _M.resp_header_pre_filter(waf)

end

-- Filter after response header phase
function _M.resp_header_post_filter(waf)

end

-- Filter before response body phase
function _M.resp_body_pre_filter(waf)

end

-- Filter after response body phase
function _M.resp_body_post_filter(waf)

end

-- Filtering before the logging phase
function _M.log_pre_filter(waf)

end

-- Filtering after the logging phase
function _M.log_post_filter(waf)

end

return _M
```



- #### SSL phase filtering function

- This stage is used to obtain the domain name requested by the client and set the SSL certificate. The value of the "waf"  variable is nil.

- #### Request phase filtering function

- This stage is used to filter the request data sent by the client. The "waf" variable is consistent with the rule variable and can be implemented independently.

- #### Response header phase filtering function

- This stage is used to filter the header data returned by the server. The "waf" variable is consistent with the rule variable and can be implemented independently.

- #### Response body phase filtering function

- This stage is used to filter the body content data returned by the server. The "waf" variable is consistent with the rule variable and can be implemented independently.

- #### Logging phase filtering function

- This stage is used for log processing and push during the logging phase. The "waf" variable is consistent with the rule variable and can be implemented independently.



### Plugin usage

1. Place the plugin file, such as kafka-logger.lua, in the /uuwaf/waf/plugins/ directory and modify the file extension to kafka-logger.w

2. Modify the /uuwaf/conf/uuwaf.conf file and add a new line of `waf:use("plugin name")` under `waf = require("waf")` in the init_by_lua_block section. For example, an example of enabling the kafka-logger.w plugin is as follows:

   ```lua
   waf = require("waf")
   waf:use("kafka-logger")
   ```
   
3. Execute /uuwaf/waf-service -s restart to make the plugin effective. If there are any issues with the plugin code running, you can view detailed error information in /uuwaf/logs/error.log.



### Common functions

#### Data sharing at each phase

##### waf.ctx

Sometimes, in order to share the same data among executing functions, it is possible to assign values to waf.ctx, such as:

```lua
function _M.resp_body_pre_filter(waf)
	waf.ctx = "share"
end

function _M.log_pre_filter(waf)
	log.errLog(waf.ctx)
end
```



#### Record error logs

```lua
local log = require("waf.log")
```



##### log.errLog(...)

- Parameters: ``Variable parameter, of type string``
- Function: Write  error log to /uuwaf/logs/error. log
- Return values: ``None``

##### log.utf8(str)

- Parameters: ``string``
- Function: Convert str character encoding to UTF-8 encoding to prevent errors when writing data to the database or JSON encoding
- Return values: ``string``

##### log.getReq()

- Parameters: ``None``
- Function: Retrieve client HTTP request information
- Return values: ``string``

##### log.encodeJson(obj)

- Parameters: ``lua table``
- Function: Convert Lua table objects into JSON strings
- Return values: ``json string``

##### log.broker(func，...)

- Parameters: ``"func" is a function, and the mutable parameter is the parameter passed to the function "func"``
- Function: Proxy executes function "func" and passes parameters.
- Return values: ``None``

:smile: Other hidden function Easter eggs can be discovered by users themselves.