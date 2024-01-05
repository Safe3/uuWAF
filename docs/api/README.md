## :strawberry: 全局配置
### init_by_lua_block
- 类型: ``table``

- 默认值: ``{ host = "127.0.0.1", port = 3306, user = "root", password = "safe3.waf" }``

- 用法:

  ```lua
  local conf = { host = "127.0.0.1", port = 3306, user = "root", password = "safe3.waf" }
  ```

  local conf变量位于/uuwaf/conf/uuwaf.conf中，用于配置waf要读取配置的mysql数据库连接的ip、端口号、用户名和密码。
  
  


## :grapes: 规则

?>这里对规则所用到的一些变量和相关函数进行说明，更多规则编写方法请大家参照WAF管理后台中的规则管理当中的众多实际例子。规则模板见：https://github.com/Safe3/uuWAF/blob/main/rules/anti-cc.lua ，一条防cc攻击的安全规则。欢迎各位贡献安全规则，详情见：https://waf.uusec.com/#/guide/contribute 。

### 规则示例

```lua
--[[
规则名称: anti cc
过滤阶段: 请求阶段
危险等级: 中危
规则描述: 当一分钟访问/api/路径频率超过360次，则在5分钟内拦截该ip访问
--]]


if not waf.startWith(waf.toLower(waf.uri), "/api/") then
    return false
end

local sh = waf.ipCache
local ccIp = 'cc-' .. waf.ip
local c, f = sh:get(ccIp)
if not c then
    sh:set(ccIp, 1, 60, 1)           -- 设置1分钟也就是60秒访问计数时间
else
    if f == 2 then
        return waf.block(true)       -- 重置TCP连接，不记录日志
    end
    sh:incr(ccIp, 1)
    if c + 1 >= 360 then             -- 频率超过360次
        sh:set(ccIp, c + 1, 300, 2)  -- 设置5分钟也就是300秒拦截时间
        return true, ccIp, true      -- 返回参数，第一个true为是否检测到；第二个参数ccIp为日志记录内容；第三个参数true表示拦截，false表示只记录不拦截
    end
end

return false
```




### 规则变量

#### 请求阶段变量
##### waf.ip
- 类型: ``string``
- 默认值: ``客户端访问ip``
- 用法: 只读，用于获取客户端访问ip，可以在WAF后台站点管理中配置客户端ip来源，获取方式为Socket或X-Forwarded-For中的倒序第n个ip。

##### waf.scheme

- 类型: ``string``
- 默认值: ``客户端访问http协议，值为字符串http或https``
- 用法: 只读。

##### waf.httpVersion

- 类型: ``number``
- 默认值: ``http协议版本，值为1.0、1.1、2.0、3.0``
- 用法: 只读。

##### waf.host

- 类型: ``string``
- 默认值: ``客户端访问host头``
- 用法: 只读。

##### waf.ipBlock

- 类型: ``table``
- 默认值: ``键值存储库，用于存放已拦截的客户端ip``
- 用法: 见ngx.shared.DICT。

##### waf.ipCache

- 类型: ``table``
- 默认值: ``键值存储库，用于存放访问的客户端ip``
- 用法: 见ngx.shared.DICT。

##### waf.requestLine

- 类型: ``string``
- 默认值: ``原始的request line数据``
- 用法: 只读。

##### waf.uri

- 类型: ``string``
- 默认值: ``解码处理过的URI，不带参数``
- 用法: 只读。

##### waf.method

- 类型: ``string``
- 默认值: ``请求方法``
- 用法: 只读。

##### waf.reqUri

- 类型: ``string``
- 默认值: ``原始URI，带参数``
- 用法: 只读。

##### waf.userAgent

- 类型: ``string``
- 默认值: ``客户端请求的User-Agent头数据``
- 用法: 只读。

##### waf.referer

- 类型: ``string``
- 默认值: ``客户端请求的Referer头数据``
- 用法: 只读。

##### waf.reqContentType

- 类型: ``string``
- 默认值: ``客户端请求的Content-Type头数据``
- 用法: 只读。

##### waf.XFF

- 类型: ``string``
- 默认值: ``客户端请求的X-Forwarded-For头数据``
- 用法: 只读。

##### waf.origin

- 类型: ``string``
- 默认值: ``客户端请求的Origin头数据``
- 用法: 只读。

##### waf.reqHeaders

- 类型: ``table``
- 默认值: ``请求的所有header对象``
- 用法: 只读。

##### waf.hErr

- 类型: ``string``
- 默认值: ``请求header解析出错信息``
- 用法: 只读。

##### waf.isQueryString

- 类型: ``bool``
- 默认值: ``true或false``
- 用法: 只读，是否存在请求参数。

##### waf.reqContentLength

- 类型: ``number``
- 默认值: ``0``
- 用法: 只读，请求body内容长度，整数值。

##### waf.queryString

- 类型: ``table``
- 默认值: ``请求url参数，key、value``
- 用法: 只读。

##### waf.qErr

- 类型: ``string``
- 默认值: ``请求参数解析出错信息``
- 用法: 只读。

##### waf.form

- 类型: ``table``
- 默认值: ``请求body对象``
- 用法: 只读。

##### waf.form["RAW"]

- 类型: ``string``
- 默认值: ``请求body的原始数据``
- 用法: 只读。

##### waf.form["FORM"]

- 类型: ``table``
- 默认值: ``请求body参数，key、value``
- 用法: 只读，表单如: {uid="12",vid={[1]="select",[2]="a from b"}}。

##### waf.form["FILES"]

- 类型: ``table``
- 默认值: ``解析出的请求body中上传文件信息``
- 用法: 只读，文件信息如: {name={[1]="filename",[2]="file content"}}。

##### waf.fErr

- 类型: ``string``
- 默认值: ``解析请求body出错信息``
- 用法: 只读，一般是恶意畸形请求包。

##### waf.cookies

- 类型: ``table``
- 默认值: ``请求cookie参数，key、value``
- 用法: 只读。

##### waf.cErr

- 类型: ``string``
- 默认值: ``解析请求cookie出错信息``
- 用法: 只读。

#### 返回http头阶段新增变量

##### waf.status

- 类型: ``number``
- 默认值: ``返回http状态，整数值``
- 用法: 只读。

##### waf.respHeaders

- 类型: ``table``
- 默认值: ``返回的所有header对象，key、value``
- 用法: 只读。

##### waf.respContentLength

- 类型: ``number``
- 默认值: ``返回body内容长度，整数值``
- 用法: 只读。

##### waf.respContentType

- 类型: ``string``
- 默认值: ``服务端返回的Content-Type头数据``
- 用法: 只读。

####  返回页面阶段新增变量

##### waf.respBody

- 类型: ``string``
- 默认值: ``返回body页面内容``
- 用法: 只读。



### 规则 API

#### 规则通用 API

##### waf.startWith(sstr,dstr)
- 参数: ``sstr 为原字符串，dstr 为查找字符串``
- 功能: 判断字符串 sstr 是否以 dstr 开头
- 返回值: ``true 或 false``

##### waf.endWith(sstr,dstr)

- 参数: ``sstr 为原字符串，dstr 为查找字符串``
- 功能: 判断字符串 sstr 是否以 dstr 结尾
- 返回值: ``true 或 false``

##### waf.toLower(sstr)

- 参数: ``sstr 为原字符串``
- 功能: 将字符串 sstr 转化为小写
- 返回值: ``sstr 小写``

##### waf.contains(sstr,dstr)

- 参数: ``sstr 为原字符串，dstr 为查找字符串``
- 功能: 判断字符串 sstr 是否在字符串 dstr
- 返回值: ``true 或 false``

##### waf.regex(sstr,pat,ext)

- 参数: ``sstr 为原字符串，pat 为正则表达式，ext 为正则属性``
- 功能: 在字符串 sstr 中匹配正则表达式 pat，用法同ngx.re.match
- 返回值: ``所有匹配项、错误``

##### waf.rgxMatch(sstr,pat,ext)

- 参数: ``sstr 为原字符串，pat 为正则表达式，ext 为正则属性``
- 功能: 在字符串 sstr 中匹配正则表达式 pat
- 返回值: ``true 或 false``

##### waf.kvFilter(v,match,valOnly)

- 参数: ``v 为要匹配对象，match 为匹配函数,valOnly 为 true 则只匹配 value``
- 功能: 用于匹配 cookie、queryString 等 key，value 键值对数据，在对象 v 中用 match 函 数匹配内容
- 返回值: ``true,匹配内容或 false,nil``

##### waf.knFilter(v,match,p)

- 参数: ``v 为要匹配对象，match 为匹配函数，p 为 1 时匹配上传文件名，为 0 时文件内容``
- 功能: 用于过滤上传文件信息，在对象 v 中用 match 函数匹配内容
- 返回值: ``true,匹配内容或 false,nil``

##### waf.jsonFilter(v, match,parsed,valOnly)

- 参数: ``v 为要匹配对象，match 为匹配函数，parsed 为 false 时解析类型为字符串 v 值，为 true 时解析类型为 table 的 v 值, valOnly 为 true 则只匹配 value``
- 功能: 用于遍历过滤请求中的 json 数据，在对象 v 中用 match 函数匹配内容
- 返回值: ``true,匹配内容或 false,nil``

##### waf.base64Decode(str)

- 参数: ``str 为要解码的 base64 字符串``
- 功能: 用于解码 base64 数据为明文数据
- 返回值: ``明文字符串或 nil``

##### waf.checkSQLI(str)

- 参数: ``str 为要检测的字符串``
- 功能: 基于语义引擎检测 sql 注入攻击
- 返回值: ``true 或 false``

##### waf.checkRCE(str)

- 参数: ``str 为要检测的字符串``
- 功能: 基于语义引擎检测命令注入攻击
- 返回值: ``true 或 false``

##### waf.checkPT(str)

- 参数: ``str 为要检测的字符串``
- 功能: 基于语义引擎检测路径遍历攻击
- 返回值: ``true 或 false``

##### waf.strCounter(sstr,dstr)

- 参数: ``sstr 为原字符串，dstr 为查找字符串``
- 功能: 计算字符串 dstr 在 sstr 中出现的次数
- 返回值: ``整数``

##### waf.pmMatch(sstr,dict)

- 参数: ``sstr 为原字符串，dict 为查找字典，以 lua 表的形式，如：{“aaa”, “bbb”, “ccc”}``

- 功能: 高效多模匹配多个字符串，发现其中一个字符串立即返回

- 返回值: ``true，字典中的字符串或 false，nil``

##### waf.urlDecode(sstr)

- 参数: ``sstr 为原字符串``
- 功能: 将 sstr 进行 url 解码还原成字符串
- 返回值: ``解码后的字符串``

##### waf.htmlEntityDecode(sstr)

- 参数: ``sstr 为原字符串``
- 功能: 将字符串 sstr 进行 html 实体解码
- 返回值: ``解码后的字符串``

##### waf.hexDecode(sstr)

- 参数: ``sstr 为原字符串``
- 功能: 将字符串 sstr 进行 hex 解码
- 返回值: ``解码后的字符串``

##### waf.block(reset)

- 参数: ``reset 为true时直接重置tcp不返回任何内容，否则返回403页面``
- 功能: 拦截客户端请求，直接重置客户端连接或返回403页面，与return搭配使用

##### waf.checkRobot(waf)

- 参数: ``waf 为t固定waf对象，无需修改``
- 功能: 检测机器人攻击，如数据爬虫、扫描攻击、CC拒绝服务攻击等，并生成滑动旋转图片验证码，与return搭配使用

##### waf.redirect(uri, status?)

- 参数: ``uri为重定向的链接，status为返回http状态（可选），默认为302``
- 功能: 重定向客户端请求到新的链接，与return搭配使用




## :melon: 插件

?>南墙支持强大的插件扩展功能，方便用户自行实现一些特有功能。插件模板见：https://github.com/Safe3/uuWAF/blob/main/plugins/kafka-logger.lua ，一个kafka日志记录插件。欢迎各位贡献安全插件，详情见：https://waf.uusec.com/#/guide/contribute 。

### 插件编写

一个标准的插件包含以下几个部分，每个部分若无功能实现可省略。

```lua
local _M = {
    version = 0.1,          --  插件版本
    name = "kafka-logger"   --  插件名称
}

-- 请求阶段过滤函数
function _M.req_filter(waf)

end

-- 返回header阶段过滤函数
function _M.resp_header_filter(waf)

end

-- 返回body阶段过滤函数
function _M.resp_body_filter(waf)

end

-- 日志记录阶段执行函数
function _M.log(waf)

end

return _M
```



- #### 请求阶段过滤函数

- 该阶段用于过滤客户端发送的请求数据，waf变量同规则变量一致，可自行实现该函数功能。

- #### 返回header阶段过滤函数

- 该阶段用于过滤服务器返回的header头数据，waf变量同规则变量一致，可自行实现该函数功能。

- #### 返回body阶段过滤函数

- 该阶段用于过滤服务器返回的body内容数据，waf变量同规则变量一致，可自行实现该函数功能。

- #### 日志记录阶段执行函数

- 该阶段用于日志记录阶段做一些日志处理与推送，waf变量同规则变量一致，可自行实现该函数功能。



### 插件使用

1. 将插件文件如kafka-logger.lua 放于/uuwaf/waf/plugins/目录，并修改文件扩展名为kafka-logger.w。

2. 修改/uuwaf/conf/uuwaf.conf文件，在init_by_lua_block段中waf = require("waf")下新增一行waf:use("扩展文件名")，如启用kafka-logger.lua插件的示例如下：

   ```lua
   waf = require("waf")
   waf:use("kafka-logger")
   ```
   
3. 执行/uuwaf/waf-service -s restart使插件生效，如果插件代码运行有问题，可以在/uuwaf/logs/error.log中查看详细错误信息。



### 常用功能函数

#### 各阶段数据共享

##### waf.ctx

有时为了在各个执行函数间共享同一个数据，可以通过给waf.ctx赋值来实现，如：

```lua
function _M.resp_body_filter(waf)
	waf.ctx = "share"
end

function _M.log(waf)
	log.errLog(waf.ctx)
end
```



#### 记录错误日志

```lua
local log = require("waf.log")
```



##### log.errLog(...)

- 参数: ``可变参数，类型为字符串``
- 功能: 将信息写入错误日志/uuwaf/logs/error.log
- 返回值: ``无``

##### log.encodeJson(obj)

- 参数: ``lua table对象``
- 功能: 将lua table对象转化json字符串
- 返回值: ``json字符串``

##### log.broker(func，...)

- 参数: ``func为函数，可变参数为传给函数func的参数``
- 功能: 代理执行函数func，并传参。
- 返回值: ``无``

:smile: 其它隐藏功能彩蛋，由用户自行去发掘。