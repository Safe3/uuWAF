# 南墙简介

[![GitHub stars](https://img.shields.io/github/stars/Safe3/uuWAF.svg?label=关注&nbsp;南墙&style=for-the-badge)](https://github.com/Safe3/uuWAF)
[![Chat](https://img.shields.io/badge/Discuss-加入讨论组-7289da.svg?style=for-the-badge)](https://github.com/Safe3/uuWAF/discussions)

> **南墙**WEB应用防火墙（简称：`uuWAF`）一款社区驱动的免费、高性能、高扩展顶级Web应用安全防护产品。

![](http://waf.uusec.com/_media/waf.png)

🏠安装及使用请访问官网： https://waf.uusec.com/

:heavy_exclamation_mark:注意：南墙 暂不开源，直接下载编译好的二进制文件安装即可，github仓库内主要为社区贡献的规则，每次 uuWAF 发布将自动更新。



## :dart: 技术优势
- :libra: 先进语义引擎

  南墙采用业界领先的`SQL、XSS、RCE、LFI` 4种基于语义分析的检测引擎，结合多种深度解码引擎可对`base64、json、form-data`等HTTP内容真实还原，从而有效抵御各种绕过WAF的攻击方式，并且相比传统正则匹配具备准确率高、误报率低、效率高等特点，管理员无需维护庞杂的规则库，即可拦截多种攻击类型。

- :ophiuchus: 智能0day防御

  南墙创新性的运用机器学习技术，使用**异常检测算法**对http正常与攻击流量进行区分识别，并对正常流量进行白名单威胁建模。通过**机器学习算法**自动学习正常流量中的参数特征，并转化成对应的参数白名单规则库，可以在面对各种突发0day漏洞时，无需添加规则即可拦截攻击，免除网站管理者一出现漏洞就需挑灯夜战升级的痛苦。

- :gemini: 高级规则引擎

  南墙积极运用`nginx`和`luajit`的高性能、高灵活性特点，除了提供对普通用户友好性较好的传统规则创建模式，还提供了高扩展性、高灵活性的lua脚本规则编写功能，使得有一定编程功底的高级安全管理员可以创造出一系列传统WAF所不能实现的高级漏洞防护规则，用户可以编写一系列插件来扩展WAF现有功能。从而使得在拦截一些复杂漏洞时，可以更加得心应手。
  
  


## :rocket: 一键安装

南墙为你提供了强大灵活的扩展和安全规则的编写API，在管理后台发布后所有规则无需重启立即生效，远超市面上大部分免费WAF产品如`ModSecurity`，规则展示如下：

![](http://waf.uusec.com/_media/rule.png)

🏠请访问官网： https://waf.uusec.com/ 下载 南墙WAF使用说明书 了解规则API详情

南墙安装及其简便，通常在几分钟内即可安装完毕，具体耗时视网络下载情况而定。

注意：请尽量选择一台纯净Linux x86_64环境的服务器安装，因为安装过程会卸载旧的MySQL数据库并重新安装，如果没有备份，可造成旧的MySQL数据丢失，并且南墙采用云WAF反向代理模式，默认需要使用80、443端口。

> 主机版安装方式如下：

```bash
sudo yum install -y ca-certificates
curl https://waf.uusec.com/waf-install -o waf-install && sudo bash ./waf-install && rm -f ./waf-install
```

安装成功后会显示 “ 恭喜您，安装成功！”

> Docker版安装方式如下： 

```bash
curl https://waf.uusec.com/waf.tgz -o waf.tgz && tar -zxf waf.tgz && sudo bash ./waf/uuwaf.sh
```

> 1Panel安装方式如下：

1Panel 是新一代的 Linux 服务器运维管理面板，下载 https://1panel.cn/ 后在应用商店中找到南墙安装。

> 快速入门：

1. 登录后台：访问https://ip:4443 ，ip为安装南墙的服务器ip地址，用户名admin，密码wafadmin。

2. 添加站点：进入站点管理菜单，点击添加站点按钮，按提示添加站点域名与网站服务器ip。
3. 添加TLS证书：进入证书管理菜单，点击添加证书按钮，上传第二步中域名的https证书和私钥文件。
4. 修改域名DNS指向：到域名服务商管理后台把域名DNS A记录的ip地址改为南墙服务器ip地址。
5. 测试连通性：访问站点域名查看网站是否能够打开，查看返回的http header头server字段是否为uuWAF。



## :gift_heart: 贡献名单

如何贡献？参照: https://waf.uusec.com/#/guide/contribute

这里感谢puhui222、Kingdom为南墙所做的贡献！

  <img src="https://waf.uusec.com/_media/sponsor.jpg" alt="捐赠"  height="300px" />




## :kissing_heart: 加入讨论

欢迎各位就 南墙 的各种bug或功能需求及使用问题，在如下渠道参与讨论

- 问题提交：https://github.com/Safe3/uuWAF/issues

- 讨论社区：https://github.com/Safe3/uuWAF/discussions

- 官方 QQ 群：11500614

- 官方微信群：微信扫描以下二维码加入

  <img src="https://waf.uusec.com/_media/weixin.jpg" alt="微信群"  height="200px" />

