## [6.8.0 LTS](https://github.com/Safe3/uuWAF/compare/v6.8.0...v6.7.0) (2025-04-18)


### Improvements

- New support for adding multiple domain names while creating new sites
- Added support for automatically creating uuwaf database structures
- Beautiful web management interface and optimized functionality

### Bugfix

- Resolve the host version authentication failure issue of reconnecting after disconnecting  database
- Fix nginx CVE-225-23419 vulnerability




## [6.7.0](https://github.com/Safe3/uuWAF/compare/v6.7.0...v6.6.0) (2025-03-30)


### Improvements

- Added Lua advanced rule editor, supporting real-time auto-completion and code completion functions
- Added support for * certificates to wildcard all domain names, making it easier to access HTTPS content when certificates are missing
- Upgrade luajit to the latest version, enhance performance and fix bugs
- Added Tomcat RCE (CVE-2025-24813) vulnerability protection rule
- Docker version adds the UUWAF_DB_DSN environment variable to facilitate custom database connection information
- Further optimize the installation and use of Docker version scripts and configuration files
- Prevent the default rule from overwriting the custom rule, and adjust the starting value of the custom rule id range to 500



## [6.6.0](https://github.com/Safe3/uuWAF/compare/v6.6.0...v6.5.0) (2025-02-24)


### Improvements

- Ordinary rules support organizing conditional relationships based on logical AND, OR, NOT AND, NOT OR.
- Introduce new abnormal cookie detection rule to block certain cookie attacks and prevent vulnerabilities from being bypassed.
- Enhance the webpage compatibility of the web management backend under different computer screen sizes.



## [6.5.0](https://github.com/Safe3/uuWAF/compare/v6.5.0...v6.4.0) (2025-02-15)

### Improvements

- Support machine learning generated rules isolated by users
- Supports first level domain name extensions up to 16 characters in length

### Bugfix

- Fix the issue of misplaced display of custom regular rules in the web management
- Fix the issue where the internal network IP is displayed as empty in the attack area ranking



## [6.4.0](https://github.com/Safe3/uuWAF/compare/v6.4.0...v6.3.0) (2025-02-03)

### Improvements

- Improve XSS security rules to reduce false positive

### Bugfix

- Fix the problem of database connection failure after system restart



## [6.3.0](https://github.com/Safe3/uuWAF/compare/v6.3.0...v6.2.0) (2024-12-30)

### Improvements

- Upgrade command injection and SQL injection semantic detection engine to further improve detection rate and reduce false positives
- Optimize log management, add rule ID column for easy identification of specific intercepted rule numbers
- Upgrade multiple security rules to cover more security vulnerabilities and threats



## [6.2.0](https://github.com/Safe3/uuWAF/compare/v6.2.0...v6.1.0) (2024-11-26)

### Improvements

- Fully support IPv6 network addresses and lift restrictions on upstream and IP whitelists for IPv6 addresses
- Upgrade the UUSEC WAF sliding and rotating image human-machine verification function, supporting cookie free mode and frequency limit
- Added Cloudflare Turnstile human-machine verification function, providing waf.checkTurnstile function

