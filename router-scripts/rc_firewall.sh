# DD-WRT Firewall Script (Administration -> Commands -> Save Firewall)
# Routes ACCEPT -> NFLOG group 1 (/tmp/fw-accept.log) and DROP/REJECT -> NFLOG group 2 (/tmp/fw-drop.log).
# Completely bypasses dmesg and /var/log/messages so Wi-Fi/SSH/kernel logs stay clean.

sleep 5

if [ -x /jffs/bin/nflogd ]; then
  pidof nflogd >/dev/null 2>&1 || \
    (/jffs/bin/nflogd -http-listen 192.168.1.1:8789 -tz America/Los_Angeles </dev/null >/dev/null 2>&1 &)

  iptables -F logaccept
  iptables -A logaccept -m state --state NEW -j NFLOG --nflog-group 1 --nflog-prefix "ACCEPT "
  iptables -A logaccept -j ACCEPT

  iptables -F logdrop
  iptables -A logdrop -m state --state NEW -j NFLOG --nflog-group 2 --nflog-prefix "DROP "
  iptables -A logdrop -m state --state INVALID -j NFLOG --nflog-group 2 --nflog-prefix "DROP "
  iptables -A logdrop -j DROP

  iptables -F logreject
  iptables -A logreject -j NFLOG --nflog-group 2 --nflog-prefix "REJECT "
  iptables -A logreject -j REJECT --reject-with icmp-port-unreachable

  iptables -F logreject_tcp
  iptables -A logreject_tcp -j NFLOG --nflog-group 2 --nflog-prefix "REJECT "
  iptables -A logreject_tcp -p tcp -j REJECT --reject-with tcp-reset

  iptables -F portscan
  iptables -A portscan -j NFLOG --nflog-group 2 --nflog-prefix "portscan:"
  iptables -A portscan -j logdrop

  N=`iptables -L logbrute -n --line-numbers 2>/dev/null | awk '$2=="LOG"{print $1; exit}'`
  [ -n "$N" ] && iptables -R logbrute $N -j NFLOG --nflog-group 2 --nflog-prefix "[DROP BRUTEFORCE] : "
fi
