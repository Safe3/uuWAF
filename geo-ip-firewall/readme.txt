Geo Ip Firewall

Introduction:
Utilizing the underlying system to perform high-performance blacklist and whitelist access control on IP addresses of countries or regions based on geographic location, supporting x86 and ARM versions of Linux servers.

Usage: gif <option> [country code]
Options:
  -b <country code>	Blacklist mode,deny IPs from the region you specified.Ex:gif -b us,jp
  -w <country code>	Whitelist mode,only allow IPs from the region you specified.Ex:gif -w cn,hk,mo,tw
  -c 			Clear the geo ip firewall rules
  -u 			Update myself and ip database
  -h, --help		Show this help message and exit

Quick Start:
1. Upload gif and cidr.txt to the specified server and grant gif executable permissions: chmod +x gif
2. To block IP access to servers in a specified region using blacklist mode, such as intercepting IP addresses from the United States or Japan, you can use the command: ./gif -b us,jp
3. Using whitelist mode only allows specified regional IP addresses to access the server. If only Chinese IP addresses are allowed to access, the command can be used: ./gif -w cn,hk,mo,tw
4. You can customize the region IP segment by modifying cidr.txt in the format of region code IP segment
5. Clear all rules and execute the command: ./gif -c
6. Software and IP library updates, execute command: ./gif -u