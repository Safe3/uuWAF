Environmental requirements:
Docker 20.10.14 or above, Docker Compose 2.0.0 or above

Decompression UUSEC WAF Installation Package:
tar -zxf waf.tgz && cd waf

If the server memory is limited, you can remove the # sign in the following comments in docker-compose.yml to reduce MySQL memory usage:
#- ./low-memory-my.cnf:/etc/mysql/my.cnf

UUSEC WAF docker management: Execute the following command and start the UUSEC WAF Docker service according to the prompts
bash uuwaf.sh

Quick Start:

1. Login to the management: Access https://ip:4443 ,the IP address is the server IP address for installing the UUSEC WAF, the default username is "admin", and the default password is "Passw0rd!".

2. Add a site: Go to the "Site" menu, click the "Add Site" button, and follow the prompts to add the site domain name and website server IP.
3. Add SSL certificate: Go to the certificate management menu, click the "Add Certificate" button, and upload the HTTPS certificate and private key file of the domain name. If you do not add an SSL certificate, the UUSEC WAF will automatically attempt to apply for a Let's Encrypt free SSL certificate and renew it automatically before the certificate expires.
4. Change the DNS address of the domain: Go to the domain name service provider's management backend and change the IP address recorded in the DNS A of the domain name to the IP address of the UUSEC WAF server.
5. Test connectivity: Visit the site domain to see if the website can be opened, and check if the returned HTTP header server field is uuWAF.

