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

