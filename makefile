.c.o:
	gcc -c -O2 -o $@ $<

all: dnsblock

install:
	cp ./dnsblock /usr/local/bin/
	iptables -t nat -I OUTPUT -p udp --dport 53 -j DNAT \
	  --to-destination 127.0.0.1:14901
	iptables -t nat -I OUTPUT -p udp --sport 14902 -j ACCEPT
	#iptables-save > /root/iptables-local
	#echo 'iptables-restore < /root/iptables-local' >> /etc/rc.d/rc.local

dnsblock: dnsblock.o
	gcc -o dnsblock dnsblock.o

