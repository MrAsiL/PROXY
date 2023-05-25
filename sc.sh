#!/bin/bash
#https://github.com/rghose/kill-close-wait-connections

#enable_ipv6 #contoba server

ulimit -n 600000
ulimit -u 600000

PORT_START=$1
PORT_FINISH=$2
USER=`date +%s | sha256sum | base64 | head -c 6 ; echo`
PASS=`date +%s | sha256sum | base64 | head -c 6 ; echo`
MAXIP=$(( PORT_FINISH - PORT_START + 1))
IP_ADD=0

IP=`/sbin/ifconfig|grep inet|head -1|sed 's/\:/ /'|awk '{print $3}' | grep -v '127.0.0.1'`
ETH=`ip -o link show | awk -F': ' '{print $2}' | grep -v "lo" | grep -v "ens7" | cut -d "@" -f 1`
#IPV6=`ip addr show | grep "/64 scope global" | grep l | cut -dl -f1 | cut -d/ -f1 | awk -F " " '{print $NF""$3}' | head -n1  | cut -d ":" -f 1,2,3,4`
IPV6=2a0f:a440:0:47


if [ -d /root/3proxy ]; then


rm -f /root/3proxy/script_file/$USER-3proxy.sh
rm -f /root/3proxy/script_file/$USER-gen-64.sh
rm -f /root/3proxy/ip_file/$USER-ip.list
rm -f /root/3proxy/cfg_file/$USER.cfg

cat > /root/3proxy/script_file/$USER-gen-64.sh << END
#!/usr/local/bin/bash

RND=`echo $((1 + RANDOM % 99))`
ETH=`ip -o link show | awk -F': ' '{print $2}' | grep -v "lo" | grep -v "ens7" | cut -d "@" -f 1`
rm -f /usr/src/ip.list

array=( 1 2 3 4 5 6 7 8 9 0 a b c d e f )
MAXCOUNT=$MAXIP
count=1
network=$IPV6
rnd_ip_block ()
{
    a=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
    b=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
    c=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
    d=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
    echo \$network:\$a:\$b:\$c:\$d
	echo /sbin/ip -6 addr add \$network:\$a:\$b:\$c:\$d/64 dev \$ETH >> /usr/src/ip.list
}
while [ "\$count" -le \$MAXCOUNT ]
do
        rnd_ip_block
        let "count += 1"
        done
END

bash /root/3proxy/script_file/$USER-gen-64.sh > /root/3proxy/ip_file/$USER-ip.list


cat > /root/3proxy/script_file/$USER-gen-64.sh << END
#!/usr/local/bin/bash

RND=`echo $((1 + RANDOM % 99))`
ETH=`ip -o link show | awk -F': ' '{print $2}' | grep -v "lo" | grep -v "ens7" | cut -d "@" -f 1`
rm -f /usr/src/ip.list

array=( 1 2 3 4 5 6 7 8 9 0 a b c d e f )
MAXCOUNT=$MAXIP
count=1
network=$IPV6
rnd_ip_block ()
{
    a=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
    b=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
    c=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
    d=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
    echo \$network:\$a:\$b:\$c:\$d
	echo /sbin/ip -6 addr add \$network:\$a:\$b:\$c:\$d/64 dev \$ETH >> /usr/src/ip.list
}
while [ "\$count" -le \$MAXCOUNT ]
do
        rnd_ip_block
        let "count += 1"
        done
END

cat > /root/$USER-refresh.sh << END
#!/bin/bash
rm -rf /root/3proxy/ip_file/$USER-ip.list
bash /root/3proxy/script_file/$USER-gen-64.sh > /root/3proxy/ip_file/$USER-ip.list
bash /root/3proxy/script_file/$USER-3proxy.sh > /root/3proxy/cfg_file/$USER.cfg
#pkill -f $USER.cfg
#/root/3proxy/src/3proxy /root/3proxy/cfg_file/$USER.cfg
/sbin/shutdown -r now
END

bash /root/3proxy/script_file/$USER-3proxy.sh > /root/3proxy/cfg_file/$USER.cfg
/root/3proxy/src/3proxy /root/3proxy/cfg_file/$USER.cfg
chmod 0777 /root/$USER-refresh.sh
echo "/root/3proxy/src/3proxy /root/3proxy/cfg_file/$USER.cfg" >> /etc/rc.local
echo "1 * * * * bash /root/$USER-refresh.sh" >> /var/spool/cron/crontabs/root
#rm -f /root/setup.sh

else

apt-get update
apt-get -y install gcc g++ git make bc pwgen conntrack libnet-rawip-perl libnet-pcap-perl libnetpacket-perl libarchive-extract-perl libnet-ssleay-perl
apt install bind9 -y && systemctl enable bind9 && systemctl start bind9
cd /usr/src/ && git clone https://github.com/rghose/kill-close-wait-connections
mv /usr/src/kill-close-wait-connections/kill_close_wait_connections.pl /usr/src/kill_close_wait_connections.pl

cat >> /etc/systemd/system/killconnections.service << END
[Unit]
Description=Kill Close Wait Connections
After=network.target
[Service]
ExecStart=/usr/src/kill_close_wait_connections.pl
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
END

chmod 0777 /etc/systemd/system/killconnections.service
chmod 0777 /usr/src/kill_close_wait_connections.pl
systemctl enable killconnections.service
systemctl start killconnections.service

cat >> /etc/sysctl.conf << END
net.ipv6.ip_nonlocal_bind = 1
END


cat >> /etc/security/limits.conf << END
root hard nofile 250000
root soft nofile 500000
nobody hard nofile 250000
nobody soft nofile 500000
* hard nofile 250000
* soft nofile 500000
root hard nproc 655360
root soft nproc 655360
nobody hard nproc 655360
nobody soft nproc 655360
* hard nproc 655360
* soft nproc 655360
END
sysctl -p


cd ~
git clone https://github.com/DanielAdolfsson/ndppd.git
cd ~/ndppd
make all && make install

cat > ndppd.conf << END
route-ttl 30000
proxy $ETH {
   router no
   timeout 500
   ttl 30000
   rule $IPV6::/64 {
      static
   }
}
END

ndppd -d -c /root/ndppd/ndppd.conf


/sbin/ip -6 addr add $IPV6::2/64 dev $ETH
/sbin/ip -6 route add default via fe80::1
/sbin/ip -6 route add local $IPV6::/64 dev lo

cd ~
wget --no-check-certificate https://github.com/z3APA3A/3proxy/archive/0.8.10.tar.gz
tar xzf 0.8.10.tar.gz
mv ~/3proxy-0.8.10 ~/3proxy
cd ~/3proxy
make -f Makefile.Linux
mkdir -p /root/3proxy/cfg_file/
mkdir -p /root/3proxy/ip_file/
mkdir -p /root/3proxy/script_file/

cat > /root/3proxy/script_file/$USER-gen-64.sh << END
#!/usr/local/bin/bash

RND=`echo $((1 + RANDOM % 99))`
ETH=`ip -o link show | awk -F': ' '{print $2}' | grep -v "lo" | grep -v "ens7" | cut -d "@" -f 1`
rm -f /usr/src/ip.list

array=( 1 2 3 4 5 6 7 8 9 0 a b c d e f )
MAXCOUNT=$MAXIP
count=1
network=$IPV6
rnd_ip_block ()
{
    a=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
    b=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
    c=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
    d=\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}\${array[\$RANDOM%16]}
    echo \$network:\$a:\$b:\$c:\$d
	echo /sbin/ip -6 addr add \$network:\$a:\$b:\$c:\$d/64 dev \$ETH >> /usr/src/ip.list
}
while [ "\$count" -le \$MAXCOUNT ]
do
        rnd_ip_block
        let "count += 1"
        done
END


cat > /root/$USER-refresh.sh << END
#!/bin/bash
rm -rf /root/3proxy/ip_file/$USER-ip.list
bash /root/3proxy/script_file/$USER-gen-64.sh > /root/3proxy/ip_file/$USER-ip.list
bash /root/3proxy/script_file/$USER-3proxy.sh > /root/3proxy/cfg_file/$USER.cfg
#pkill -f $USER.cfg
#/sbin/ip -6 addr add $IPV6::2/64 dev $ETH
#/sbin/ip -6 route add default via fe80::1
#/sbin/ip -6 route add local $IPV6::/64 dev lo
#/root/3proxy/src/3proxy /root/3proxy/cfg_file/$USER.cfg
/sbin/shutdown -r now
END

cat > /etc/rc.local << END
#!/bin/bash
ulimit -n 600000
ulimit -u 600000
echo 600000 > /proc/sys/vm/max_map_count
echo 200000 > /proc/sys/kernel/pid_max 
truncate -s0 /etc/resolv.conf && echo 'nameserver 127.0.0.1' >> /etc/resolv.conf
/sbin/ip -6 addr add $IPV6::2/64 dev $ETH
/sbin/ip -6 route add default via fe80::1
/sbin/ip -6 route add local $IPV6::/64 dev lo
/root/ndppd/ndppd -d -c /root/ndppd/ndppd.conf
END

echo "/root/3proxy/src/3proxy /root/3proxy/cfg_file/$USER.cfg" >> /etc/rc.local

bash /root/3proxy/script_file/$USER-gen-64.sh > /root/3proxy/ip_file/$USER-ip.list

cat > /root/3proxy/script_file/$USER-3proxy.sh << END
#!/bin/bash
echo daemon
echo maxconn 100000
echo nscache 65536
echo timeouts 1 5 30 60 180 1800 15 60
echo setgid 65535
echo setuid 65535
echo flush
echo auth iponly
echo allow "* *"
port=$PORT_START
count=1
for i in \$(cat /root/3proxy/ip_file/$USER-ip.list); do
    echo "proxy -6 -n1 -a -ocUSE_TCP_FASTOPEN -p\$port -i$IP -e\$i"
    ((port+=1))
    ((count+=1))
    if [ \$count -eq $MAXIP ]; then
        exit
    fi
done
END
bash /root/3proxy/script_file/$USER-3proxy.sh > /root/3proxy/cfg_file/$USER.cfg

ulimit -n 600000
ulimit -u 600000
/root/3proxy/src/3proxy /root/3proxy/cfg_file/$USER.cfg

echo 'nf_conntrack' >> /etc/modules
echo 'nf_conntrack_ipv4' >>  /etc/modules
echo 'fs.file-max = 700000' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_timestamps=1' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_max_tw_buckets=1440000' >> /etc/sysctl.conf
echo 'net.ipv4.ip_local_port_range = 512 65535' >> /etc/sysctl.conf
echo 'net.core.somaxconn = 61440' >> /etc/sysctl.conf
echo 'net.core.rmem_max = 12582912' >> /etc/sysctl.conf
echo 'net.core.wmem_default = 31457280' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 12582912' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_keepalive_time = 300' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_keepalive_probes = 5' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_keepalive_intvl = 15' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_fin_timeout = 15' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rfc1337 = 1' >> /etc/sysctl.conf
echo 'net.core.optmem_max = 25165824' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_mem = 65536 131072 262144' >> /etc/sysctl.conf
echo 'net.ipv4.udp_mem = 65536 131072 262144' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 8192 87380 16777216' >> /etc/sysctl.conf
echo 'net.ipv4.udp_rmem_min = 66384' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem = 8192 65536 16777216' >> /etc/sysctl.conf
echo 'net.ipv4.udp_wmem_min = 76384' >> /etc/sysctl.conf
echo 'net.ipv4.xfrm4_gc_thresh = 52768' >> /etc/sysctl.conf
echo 'net.netfilter.nf_conntrack_tcp_timeout_established=200' >> /etc/sysctl.conf
echo 'kernel.threads-max = 120000' >> /etc/sysctl.conf

sysctl -p

echo 'UserTasksMax=100000' >> /etc/systemd/logind.conf
echo 'DefaultTasksMax=100000' >> /etc/systemd/system.conf

echo '*       soft    nofile    655360' >> /etc/security/limits.d/90-nproc.conf
echo '*       hard    nofile    655360' >> /etc/security/limits.d/90-nproc.conf
echo '*       soft    nproc     655360' >> /etc/security/limits.d/90-nproc.conf
echo '*       hard    nproc     655360' >> /etc/security/limits.d/90-nproc.conf

echo 600000 > /proc/sys/vm/max_map_count
echo 200000 > /proc/sys/kernel/pid_max 
echo "1 * * * * bash /root/$USER-refresh.sh" >> /var/spool/cron/crontabs/root
rm -f /root/setup.sh
rm -f /root/0.8.13.tar.gz
rm -f /root/kill_close_wait_connections.pl 
chmod 0777 /root/$USER-refresh.sh

if [ $IP_ADD == '1' ]; then
echo 'bash /usr/src/ip.list' >> /etc/rc.local
bash /usr/src/ip.list
else
echo pass
fi
echo "@reboot bash /etc/rc.local" >> /var/spool/cron/crontabs/root

echo $IP:$PORT_START:$PORT_FINISH

fi