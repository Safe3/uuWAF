## [2.5.1](https://github.com/Safe3/uuWAF/compare/v2.5.1...v2.4.1) (2023-07-04)


### 新增功能

* 新增查看攻击日志请求报文功能
* 优化tls传输兼容性，支持TLS v1
* 优化sql注入和命令执行语义引擎
* 优化系统备份功能



## [2.4.1](https://github.com/Safe3/uuWAF/compare/v2.4.1...v2.3.0) (2023-05-30)


### 新增功能

* 新增系统配置备份功能
* 新增一键解封被封禁的ip功能
* 新增南墙安全验证X-Waf-Token head头验证功能


### Bug 修复

* 修复使用waf.block函数后产生系统报错日志的问题
* 解决部分XSS检测误报的问题
* 解决Docker版南墙在某些系统出现Unix syslog delivery error错误不能运行的问题

  


## [2.3.0](https://github.com/Safe3/uuWAF/compare/v2.3.0...v2.2.0) (2023-04-28)


### 新增功能

* 新增CDN缓存加速功能，支持业内首创的高灵活度正则匹配任意条件实时缓存清理功能。




## [2.2.0](https://github.com/Safe3/uuWAF/compare/v2.2.0...v2.1.5) (2023-03-22)


### 新增功能

* 新增滑动旋转验证码功能，可用于各种拦截机器人攻击，如网络爬虫、业务风控、cc拒绝服务攻击等
* 新增安全日志、审计日志报表功能，可将日志导出为Excel报表
* 新增并优化多个安全规则，包括机器人攻击防御、http重定向https等
* 优化WAF配置，减少内存占用
* 优化WAF管理后台界面功能展示


### Bug 修复

* 修复某些网站返回http头过大导致的502、504问题
* 修复某些网站非utf-8编码且未设置Content-Type头导致网页乱码的问题




## [2.1.5](https://github.com/Safe3/uuWAF/compare/v2.1.5...v2.1.2) (2022-12-31)


### Bug 修复

* 修复某些情况下弱口令匹配不生效的问题
* 使用安装包进行安装时，对不支持的操作系统进行提示，如ubuntu或debian


### 新增变更

* 支持text/plain类型的POST请求和返回内容的安全过滤处理
* 支持UTF-8编码正则匹配
* 提升WAF性能，默认不再过滤base64内容，可以单独定义规则来支持





## [2.1.2](https://github.com/Safe3/uuWAF/compare/v2.1.2...v1.9.3) (2022-11-11)


### Bug 修复

* 修复日志管理功能Url过长时，日志显示不全的问题
* 修复在selinux开启时，WAF服务进程不能正常启动的问题


### 新增变更

* 增强默认安装初始化数据库密码、JWT密钥安全性，随机化生成
* 升级OpenSSL组件到最新1.1.1s版





## [1.9.3](https://github.com/Safe3/uuWAF/compare/v1.9.3...v1.9.0) (2022-10-10)


### Bug 修复

* 修复删除日志时，时间格式识别错误的问题
* 修复没有安全日志时，首页显示提示错误的问题


### 新增功能

* 支持更多RedHat系操作系统，如CentOS、AlmaLinux、Anolis、Rocky Linux等
* 增强安装稳定性和性能，数据库升级到8.x版本




## [1.9.0](https://github.com/Safe3/uuWAF/compare/v1.9.0...v1.8.1) (2022-09-22)


### Bug 修复

* 无


### 新增功能

* 支持WAF扩展插件