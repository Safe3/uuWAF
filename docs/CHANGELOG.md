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