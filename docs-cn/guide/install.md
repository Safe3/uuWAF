# 快速入门
南墙支持一键全自动安装（**Ubuntu或Debian系统请使用Docker版**），全程无需人工干预，给你带来极致体验 。



## ♨️配置要求 <!-- {docsify-ignore} -->
?> 南墙对配置要求极低，详细如下：

  ```
  - 处理器：64位 1千兆赫(GHz)或更快。
  - 内存：不小于2G
  - 磁盘空间：不小于8G
  ```


## 🚀一键安装 <!-- {docsify-ignore} -->
?> 南墙安装及其简便，通常在几分钟内即可安装完毕，具体耗时视网络下载情况而定。

!> 注意：请尽量选择一台纯净Linux x86_64环境的服务器安装，因为安装过程会卸载旧的MySQL数据库并重新安装，如果没有备份，可造成旧的MySQL数据丢失，并且南墙采用云WAF反向代理模式，默认需要使用80、443端口。

**主机版安装方式如下：**

系统要求：RHEL 7及以上兼容x86_64系统，如Rocky Linux、AlmaLinux、Alibaba Cloud Linux、TencentOS等。

```bash
sudo yum install -y ca-certificates
curl https://waf.uusec.com/waf-install -o waf-install && sudo bash ./waf-install && rm -f ./waf-install
```

?> 安装成功后会显示 “ 恭喜您，安装成功”

主机版卸载方式如下：

```bash
sudo systemctl stop uuwaf && sudo /uuwaf/waf-service -s uninstall && sudo rm -rf /uuwaf
sudo rpm -qa | grep -ie ^percona | xargs yum -y erase
```

**容器版安装方式如下：** 

- 软件依赖：Docker 20.10.14 版本以上，Docker Compose 2.0.0 版本以上，低版本会导致sql数据无法导入以致南墙后台无法登录。

若遇到无法自动安装Docker Engine，请参考[阿里云](https://help.aliyun.com/zh/ecs/use-cases/install-and-use-docker-on-a-linux-ecs-instance)手动安装。

```bash
curl -fsSL https://waf.uusec.com/waf.tgz -o waf.tgz && tar -zxf waf.tgz && sudo bash ./waf/uuwaf.sh
```

后续可直接执行 `bash ./waf/uuwaf.sh` 来管理南墙容器，包括启动、停止、更新、卸载等。

**安装后快速使用入门：**

1. 登录后台：访问https://ip:4443 ，ip为安装南墙的服务器ip地址，用户名admin，密码Passw0rd!。
2. 添加站点：进入站点管理菜单，点击添加站点按钮，按提示添加站点域名与网站服务器ip。
3. 添加SSL证书：进入证书管理菜单，点击添加证书按钮，上传第二步中域名的https证书和私钥文件。若不添加SSL证书，则南墙会自动尝试申请Let's Encrypt免费SSL证书，并在证书到期前自动续期。
4. 修改域名DNS指向：到域名服务商管理后台把域名DNS A记录的ip地址改为南墙服务器ip地址。
5. 测试连通性：访问站点域名查看网站是否能够打开，查看返回的http header头server字段是否为uuWAF。

!> 更多使用过程中碰到问题的解决办法请参考[常见问题](https://waf.uusec.com/#/guide/problems)。