# 常见问题
> 南墙 的发展离不开社区的每一位用户的支持，欢迎在[github](https://github.com/Safe3/uuWAF)上点个小星星，这里收集常见的使用问题 。



### 🍎 为什么访问网站会出现规则ID为-1的拦截页面？ <!-- {docsify-ignore} -->
?> 如果域名没有在南墙站点管理中配置，访问南墙默认会拦截该域名的访问，以防止黑域名指向引起的法律风险。



### 🍐 经过南墙代理的网站如何获取客户端真实ip？ <!-- {docsify-ignore} -->
?> 南墙转发给网站的HTTP请求头中会加入X-Waf-Ip字段，它的值即为客户端ip，也可以通过X-Forwarded-For来获取。



### 🍑 集群模式下上游网站如何区分不同的南墙来源？ <!-- {docsify-ignore} -->

?> 南墙转发给网站的HTTP请求头中会加入X-Waf-Id字段，它的值即为用户在/uuwaf/conf/uuwaf.conf中配置的id值，用户可以通过该值来区分网站请求来自那台南墙服务器。



### 🍋 如何解决南墙Docker版获取的客户端ip为172的问题？ <!-- {docsify-ignore} -->

?> 这是部分主机docker网络和firewalld冲突引起的，导致南墙获取的客户端访问ip为172开头的容器网关ip。可以把docker网桥加入到防火墙的internal区域，手工执行如下命令解决，其中wafnet为南墙docker容器的网桥名称。

```bash
firewall-cmd --permanent --zone=internal --change-interface=wafnet
```



### 🍊 如何查看南墙CDN是否缓存了我们的网页？ <!-- {docsify-ignore} -->

?> 南墙提供了一个X-Waf-Cache返回头用以查看缓存情况，如X-Waf-Cache: HIT表示已缓存，X-Waf-Cache: MISS表示未缓存。



### 🍍 如何修改南墙管理后台的端口和SSL证书？ <!-- {docsify-ignore} -->

?> 南墙管理后台的配置位于/uuwaf/web/conf/conf.yaml中，addr字段值即为ip地址和端口。替换SSL证书可以替换/uuwaf/web/conf/目录中的server.crt和server.key文件，之后执行systemctl restart uuwaf重启服务使配置生效。
