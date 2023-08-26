# 快速安装
南墙支持一键全自动安装（**Ubuntu或Debian系统请使用Docker版**），全程无需人工干预，给你带来极致体验 。



##  :hotsprings: 配置要求 <!-- {docsify-ignore} -->
?> 南墙对配置要求极低，详细如下：

  ```
  - 处理器：64位 1千兆赫(GHz)或更快。
  - 内存：不小于1G
  - 磁盘空间：不小于16G
  - 系统：RedHat 7及以上相关兼容x86_64系统，如CentOS 7、AlmaLinux、Anolis、Oracle、Rocky Linux等，其它请使用Docker版。
  ```



## :rocket: 一键安装 <!-- {docsify-ignore} -->
?> 南墙安装及其简便，通常在几分钟内即可安装完毕，具体耗时视网络下载情况而定。

!> 注意：请尽量选择一台纯净Linux x86_64环境的服务器安装，因为安装过程会卸载旧的MySQL数据库并重新安装，如果没有备份，可造成旧的MySQL数据丢失，并且南墙采用云WAF反向代理模式，默认需要使用80、443端口。

主机版安装方式如下：

```bash
sudo yum install -y ca-certificates
sudo rm -f ./waf-install && wget https://waf.uusec.com/waf-install && chmod +x waf-install && ./waf-install
```

?> 安装成功后会显示 “ 恭喜您，安装成功”

Docker版安装方式如下： 
```bash
sudo rm -f ./waf.tgz && wget https://waf.uusec.com/waf.tgz && tar -zxf waf.tgz && sh ./waf/uuwaf.sh
```

?> 快速入门：

1. 登录后台，访问https://wafip:4443，wafip为安装南墙的服务器ip，用户名admin，密码wafadmin
2. 添加站点，进入站点管理菜单，点击添加站点按钮，按提示添加站点域名与网站服务器ip
3. 添加证书，进入证书管理菜单，点击添加证书按钮，上传第二步中域名的https证书和私钥文件
4. 将域名DNS的ip指向改为南墙服务器ip地址
5. 访问站点域名查看网站是否能够访问