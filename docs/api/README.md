## 全局配置
### init_by_lua_block
- 类型: ``table``

- 默认值: ``{ host = "127.0.0.1", port = 3306, user = "root", password = "safe3.waf" }``

- 用法:

  ```lua
  local conf = { host = "127.0.0.1", port = 3306, user = "root", password = "safe3.waf" }
  ```

  local conf变量位于/uuwaf/conf/uuwaf.conf中，用于配置waf要读取配置的mysql数据库连接的ip、端口号、用户名和密码。
  
  


## 规则

这里对规则所用到的一些变量和相关函数进行说明，更多规则编写方法请大家参照WAF管理后台中的规则管理当中的众多实际例子。

### 规则变量

#### 请求阶段变量
##### waf.ip
- 类型: ``string``
- 默认值: ``客户端访问ip``
- 用法: 只读，用于获取客户端访问ip，可以在WAF后台站点管理中配置客户端ip来源，获取方式为Socket或X-Forwarded-For中的倒序第n个ip。

##### waf.host

- 类型: ``string``
- 默认值: ``客户端访问host头``
- 用法: 只读。

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
