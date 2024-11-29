# FAQ
> The development of UUSEC WAF cannot be separated from the support of every user in the community. Welcome to [Github](https://github.com/Safe3/uuWAF) to click on a little star, here to collect common usage questions.



### 🍎 Why does a blocking page with rule ID -1 appear when accessing a website? <!-- {docsify-ignore} -->
?> If the domain name is not configured in the UUSEC WAF site management, access to the UUSEC WAF will be blocked by default to prevent legal risks caused by black domain name pointing.



### 🍐 How to obtain the real IP address of the client through the UUSEC WAF proxy website? <!-- {docsify-ignore} -->
?> The HTTP request header forwarded by the UUSEC WAF to the website will include an X-Waf-Ip field, whose value is the client IP, which can also be obtained through X-Forwarded-For.



### 🍑 How can upstream websites distinguish different sources of UUSEC WAF in cluster mode? <!-- {docsify-ignore} -->

?> The X-Waf-Id field will be added to the HTTP request header forwarded by UUSEC WAF to the website. Its value is the ID value configured by the user in /uuwaf/web/conf/config.json, and the user can use this value to distinguish which UUSEC WAF server the website request comes from.



### 🍋 How to solve the problem of obtaining a client IP address of 172 for the Docker version of the UUSEC WAF? <!-- {docsify-ignore} -->

?> This is caused by a conflict between the Docker network of some hosts and Firewalld, resulting in the client access IP obtained by UUSEC WAF being the container gateway IP starting with 172. You can add the Docker bridge to the internal area of the firewall and manually execute the following command to solve the problem, where wafnet is the bridge name of the Docker container on the UUSEC WAF.

```bash
firewall-cmd --permanent --zone=internal --change-interface=wafnet
```



### 🍊 How to check if the UUSEC WAF CDN has cached our webpage? <!-- {docsify-ignore} -->

?> The UUSEC WAF provides an X-Waf-Cache return header to check the cache status, such as X-Waf-Cache: HIT indicating cached, and X-Waf-Cache: MISS indicating uncached.



### 🍍 How to modify the port and SSL certificate of the UUSEC WAF management ? <!-- {docsify-ignore} -->

?> The configuration of the UUSEC WAF management is located in /uuwaf/web/conf/config.json, and the value of the addr field is the IP address and port. Replacing the SSL certificate can replace the server.crt and server.key files in the /uuwaf/web/conf/ directory, and then execute `systemctl restart uuwaf` to restart the service for the configuration to take effect.



### 🍈 How to modify the default listening port of the reverse proxy on the UUSEC WAF? <!-- {docsify-ignore} -->

?> By default, the UUSEC WAF only listens to ports HTTP 80 and HTTPS 443. Users can customize any listening port in /uwaf/conf/uuwaf.conf. Please refer to nginx's [listen](https://nginx.org/en/docs/http/ngx_http_core_module.html#listen) configuration for more information to set up, then execute `systemctl restart uuwaf` to restart the service for the configuration to take effect. Docker users can modify the port mapping in docker-compose.yml.
