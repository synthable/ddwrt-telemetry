# DD-WRT Startup Script (Administration -> Commands -> Save Startup)
# Starts nflogd on boot for zero-dmesg / zero-syslog firewall logging + LAN HTTP/SSE API.
# Adjust -tz and -http-listen for your timezone and LAN IP if different from 192.168.1.1.

pidof nflogd >/dev/null 2>&1 || \
  (/jffs/bin/nflogd -http-listen 192.168.1.1:8789 -tz America/Los_Angeles </dev/null >/dev/null 2>&1 &)
