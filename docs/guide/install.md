# 快速安装
南墙支持一键全自动安装，全程无需人工干预，给你带来极致体验 。



##  :hotsprings: 配置要求 <!-- {docsify-ignore} -->
?> 南墙对配置要求极低，详细如下：

  ```
  - 处理器：64位 1千兆赫(GHz)或更快。
  - 内存：大于1G
  - 磁盘空间：大于16G
  - 系统：CentOS Linux 7 x86_64
  ```

!> 注意：CentOS系统的时区请选择中国时区GMT+8，否则WAF管理后台会出现时间显示问题。



## :rocket: 一键安装 <!-- {docsify-ignore} -->
?> 南墙安装及其简便，通常在几分钟内即可安装完毕，具体耗时视网络下载情况而定。

!> 注意：请尽量选择一台纯净CentOS Linux 7 x86_64环境的服务器安装，因为安装过程会卸载旧的MySQL数据库并重新安装，如果没有备份，可造成旧的MySQL数据丢失。

bash环境下执行如下命令

```bash
wget https://waf.uusec.com/waf-install && chmod +x waf-install && ./waf-install
```

?> 安装成功后会显示 “ 恭喜您，安装完成！”

!> 注意：安装完成后请第一时间修改/uuwaf/web/conf/conf.yaml文件中的jwtKey登录认证加密密钥，然后执行如下命令使配置生效。

```bash
/uuwaf/waf-service -s restart
```