环境要求：
docker版本1.20以上

解压南墙安装包：
tar -zxf waf.tgz && cd waf

若服务器内存有限，可以取消docker-compose.yml中如下注释中的#号，降低mysql内存占用：
#- ./low-memory-my.cnf:/etc/mysql/my.cnf

南墙Docker管理：执行如下面命令，根据提示启动南墙docker服务
bash uuwaf.sh

快速入门：
1、登录后台，访问https://wafip:4443，wafip为安装南墙的服务器ip，用户名admin，密码Passw0rd!
2、添加站点，进入站点管理菜单，点击添加站点按钮，按提示添加站点域名与网站服务器ip
3、添加SSL证书：进入证书管理菜单，点击添加证书按钮，上传第二步中域名的https证书和私钥文件。若不添加SSL证书，则南墙会自动尝试申请Let's Encrypt免费SSL证书，并在证书到期前自动续期
4、将域名DNS的ip指向改为南墙服务器ip地址
5、访问站点域名查看网站是否能够访问
