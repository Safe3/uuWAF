# 快速入门
南墙支持一键全自动安装（**Ubuntu或Debian系统请使用Docker版**），全程无需人工干预，给你带来极致体验 。



##  :hotsprings: 配置要求 <!-- {docsify-ignore} -->
?> 南墙对配置要求极低，详细如下：

  ```
  - 处理器：64位 1千兆赫(GHz)或更快。
  - 内存：不小于2G
  - 磁盘空间：不小于16G
  - 系统：RHEL 7及以上兼容x86_64系统，如CentOS、Rocky Linux、AlmaLinux等，其它请使用Docker版。
  ```



## :rocket: 一键安装 <!-- {docsify-ignore} -->
?> 南墙安装及其简便，通常在几分钟内即可安装完毕，具体耗时视网络下载情况而定。

!> 注意：请尽量选择一台纯净Linux x86_64环境的服务器安装，因为安装过程会卸载旧的MySQL数据库并重新安装，如果没有备份，可造成旧的MySQL数据丢失，并且南墙采用云WAF反向代理模式，默认需要使用80、443端口。

主机版安装方式如下：

```bash
sudo yum install -y ca-certificates
curl https://waf.uusec.com/waf-install -o waf-install && sudo bash ./waf-install && rm -f ./waf-install
```

?> 安装成功后会显示 “ 恭喜您，安装成功”

!> 主机版卸载方式如下：

```bash
sudo systemctl stop uuwaf && sudo /uuwaf/waf-service -s uninstall && sudo rm -rf /uuwaf
```

Docker版安装方式如下： 

- 软件依赖：Docker 20.10.14 版本以上，低版本会导致sql数据无法导入以致南墙后台无法登录
- 软件依赖：Docker Compose 2.0.0 版本以上

若遇到Docker无法安装，请使用阿里云或腾讯云的docker源安装，安装后参考 [https://docker.1panel.dev/](https://docker.1panel.dev/) 配置镜像加速。

```bash
curl https://waf.uusec.com/waf.tgz -o waf.tgz && tar -zxf waf.tgz && sudo bash ./waf/uuwaf.sh
```

?> 快速入门：

1. 登录后台：访问https://ip:4443 ，ip为安装南墙的服务器ip地址，用户名admin，密码Passw0rd!。
2. 添加站点：进入站点管理菜单，点击添加站点按钮，按提示添加站点域名与网站服务器ip。
3. 添加SSL证书：进入证书管理菜单，点击添加证书按钮，上传第二步中域名的https证书和私钥文件。若不添加SSL证书，则南墙会自动尝试申请Let's Encrypt免费SSL证书，并在证书到期前自动续期。
4. 修改域名DNS指向：到域名服务商管理后台把域名DNS A记录的ip地址改为南墙服务器ip地址。
5. 测试连通性：访问站点域名查看网站是否能够打开，查看返回的http header头server字段是否为uuWAF。