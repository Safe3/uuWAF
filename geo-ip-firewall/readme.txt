地理位置ip防火墙 - Geo ip firewall

简介：
利用系统底层对国家或区域的ip地址进行高性能黑白名单访问控制，支持x86和arm版Linux服务器。

使用：
Usage: gif <option> [country code]
Options:
  -b <country code>	Blacklist mode,deny IPs from the region you specified.Ex:gif -b us,jp
  -w <country code>	Whitelist mode,only allow IPs from the region you specified.Ex:gif -w cn,hk,mo,tw
  -c 			Clear the geo ip firewall rules
  -u 			Update myself and ip database
  -h, --help		Show this help message and exit


快速入门：
1、将gif和cidr.txt上传到指定服务器并赋予gif可执行权限：chmod +x gif
2、使用黑名单模式拦截指定地域ip访问，如拦截美国、日本ip可以使用命令：./gif -b us,jp
3、使用白名单模式只允许指定地域ip可以访问服务器，如只允许中国ip访问可以使用命令：./gif -w cn,hk,mo,tw
4、可以通过修改cidr.txt来自定义区域ip段，格式：国家代号 IP段
5、清除所有规则，执行命令：./gif -c
6、软件和ip库更新，执行命令：./gif -u