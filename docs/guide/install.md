# Installation
UUSEC WAF supports one click fully automatic installation, without the need for manual intervention, providing you with the ultimate experience.



## ♨️Requirements <!-- {docsify-ignore} -->
?> The UUSEC WAF has extremely low requirements for configuration, as detailed below:

  ```
  - CPU: 64 bit 1 gigahertz (GHz) or faster.
  - Memory: not less than 2GB
  - Disk space: not less than 8GB
  ```


## 🚀One click installation <!-- {docsify-ignore} -->
?> The installation of the UUSEC WAF is very simple, usually completed within a few minutes, and the specific time depends on the network download situation.

!> Attention: Please try to choose a pure Linux x86_64 environment server for installation, because the UUSEC WAF adopts cloud WAF reverse proxy mode, which requires the use of ports 80 and 443 by default.

**Installation:** 

- Software dependencies: Docker version 20.10.14 or above, Docker Compose version 2.0.0 or above.

If you encounter the inability to automatically install Docker Engine, please install it manually.

```bash
sudo bash -c "$(curl -fsSL https://uuwaf.uusec.com/installer.sh)"
```

Subsequently, `bash /opt/waf/manager.sh` is used to manage the UUSEC WAF container, including starting, stopping, updating, uninstalling, etc.

**Quick Start:**

1. Login to the management: Access https://ip:4443 ,the IP address is the server IP address for installing the UUSEC WAF, the default username is `admin`, and the default password is `#Passw0rd`.
2. Add a site: Go to the "Sites" menu, click the "Add Site" button, and follow the prompts to add the site domain name and website server IP.
3. Add SSL certificate: Go to the certificate management menu, click the "Add Certificate" button, and upload the HTTPS certificate and private key file of the domain name. If you don‘t have a SSL certificate, you can also apply for a Let's Encrypt free SSL certificate and renew it automatically before the certificate expires.
4. Change the DNS address of the domain: Go to the domain name service provider's management backend and change the IP address recorded in the DNS A of the domain name to the IP address of the UUSEC WAF server.
5. Test connectivity: Visit the site domain to see if the website can be opened, and check if the returned HTTP header server field is uuWAF.

!> For more solutions to problems encountered during use, please refer to [FAQ](https://uuwaf.uusec.com/#/guide/problems).