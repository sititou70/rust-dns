```text
send arp request...
arp reply received.
gateway_macaddr resolved: 02:2c:81:03:94:a8
[example.com. using 170.247.170.2] send dns request to 170.247.170.2...
[example.com. using 170.247.170.2] dns reply received:
|   header:
|   	id=0 qr opecode=Query !aa !tc !rd !ra rcode=NoError qdcount=1 ancount=0 nscount=13 arcount=14
|   Question Section:
|   	example.com.	IN	A
|   Answer Section:
|   Authority Section:
|   	com.	172800	IN	NS	g.gtld-servers.net.
|   	com.	172800	IN	NS	h.gtld-servers.net.
|   	com.	172800	IN	NS	a.gtld-servers.net.
|   	com.	172800	IN	NS	b.gtld-servers.net.
|   	com.	172800	IN	NS	k.gtld-servers.net.
|   	com.	172800	IN	NS	l.gtld-servers.net.
|   	com.	172800	IN	NS	c.gtld-servers.net.
|   	com.	172800	IN	NS	d.gtld-servers.net.
|   	com.	172800	IN	NS	m.gtld-servers.net.
|   	com.	172800	IN	NS	f.gtld-servers.net.
|   	com.	172800	IN	NS	e.gtld-servers.net.
|   	com.	172800	IN	NS	j.gtld-servers.net.
|   	com.	172800	IN	NS	i.gtld-servers.net.
|   Additional Section:
|   	m.gtld-servers.net.	172800	IN	A	192.55.83.30
|   	l.gtld-servers.net.	172800	IN	A	192.41.162.30
|   	k.gtld-servers.net.	172800	IN	A	192.52.178.30
|   	j.gtld-servers.net.	172800	IN	A	192.48.79.30
|   	i.gtld-servers.net.	172800	IN	A	192.43.172.30
|   	h.gtld-servers.net.	172800	IN	A	192.54.112.30
|   	g.gtld-servers.net.	172800	IN	A	192.42.93.30
|   	f.gtld-servers.net.	172800	IN	A	192.35.51.30
|   	e.gtld-servers.net.	172800	IN	A	192.12.94.30
|   	d.gtld-servers.net.	172800	IN	A	192.31.80.30
|   	c.gtld-servers.net.	172800	IN	A	192.26.92.30
|   	b.gtld-servers.net.	172800	IN	A	192.33.14.30
|   	a.gtld-servers.net.	172800	IN	A	192.5.6.30
[example.com. using 170.247.170.2] name server resource record found. server_name=m.gtld-servers.net.
[example.com. using 170.247.170.2] additional A resource record for name server found. name_server_address=192.55.83.30
[example.com. using 170.247.170.2] resolving another name server... name_server_address=192.55.83.30
    [example.com. using 192.55.83.30] send dns request to 192.55.83.30...
    [example.com. using 192.55.83.30] dns reply received:
    |   header:
    |   	id=1 qr opecode=Query !aa !tc !rd !ra rcode=NoError qdcount=1 ancount=0 nscount=2 arcount=0
    |   Question Section:
    |   	example.com.	IN	A
    |   Answer Section:
    |   Authority Section:
    |   	example.com.	172800	IN	NS	a.iana-servers.net.
    |   	example.com.	172800	IN	NS	b.iana-servers.net.
    |   Additional Section:
    [example.com. using 192.55.83.30] name server resource record found. server_name=a.iana-servers.net.
    [example.com. using 192.55.83.30] additional A resource record for name server not found, resolving name server address...
        [a.iana-servers.net. using 202.12.27.33] send dns request to 202.12.27.33...
        [a.iana-servers.net. using 202.12.27.33] arp request received, send arp reply.
        [a.iana-servers.net. using 202.12.27.33] dns reply received:
        |   header:
        |   	id=2 qr opecode=Query !aa !tc !rd !ra rcode=NoError qdcount=1 ancount=0 nscount=13 arcount=14
        |   Question Section:
        |   	a.iana-servers.net.	IN	A
        |   Answer Section:
        |   Authority Section:
        |   	net.	172800	IN	NS	a.gtld-servers.net.
        |   	net.	172800	IN	NS	k.gtld-servers.net.
        |   	net.	172800	IN	NS	h.gtld-servers.net.
        |   	net.	172800	IN	NS	m.gtld-servers.net.
        |   	net.	172800	IN	NS	c.gtld-servers.net.
        |   	net.	172800	IN	NS	g.gtld-servers.net.
        |   	net.	172800	IN	NS	l.gtld-servers.net.
        |   	net.	172800	IN	NS	b.gtld-servers.net.
        |   	net.	172800	IN	NS	d.gtld-servers.net.
        |   	net.	172800	IN	NS	e.gtld-servers.net.
        |   	net.	172800	IN	NS	j.gtld-servers.net.
        |   	net.	172800	IN	NS	i.gtld-servers.net.
        |   	net.	172800	IN	NS	f.gtld-servers.net.
        |   Additional Section:
        |   	m.gtld-servers.net.	172800	IN	A	192.55.83.30
        |   	l.gtld-servers.net.	172800	IN	A	192.41.162.30
        |   	k.gtld-servers.net.	172800	IN	A	192.52.178.30
        |   	j.gtld-servers.net.	172800	IN	A	192.48.79.30
        |   	i.gtld-servers.net.	172800	IN	A	192.43.172.30
        |   	h.gtld-servers.net.	172800	IN	A	192.54.112.30
        |   	g.gtld-servers.net.	172800	IN	A	192.42.93.30
        |   	f.gtld-servers.net.	172800	IN	A	192.35.51.30
        |   	e.gtld-servers.net.	172800	IN	A	192.12.94.30
        |   	d.gtld-servers.net.	172800	IN	A	192.31.80.30
        |   	c.gtld-servers.net.	172800	IN	A	192.26.92.30
        |   	b.gtld-servers.net.	172800	IN	A	192.33.14.30
        |   	a.gtld-servers.net.	172800	IN	A	192.5.6.30
        [a.iana-servers.net. using 202.12.27.33] name server resource record found. server_name=g.gtld-servers.net.
        [a.iana-servers.net. using 202.12.27.33] additional A resource record for name server found. name_server_address=192.42.93.30
        [a.iana-servers.net. using 202.12.27.33] resolving another name server... name_server_address=192.42.93.30
            [a.iana-servers.net. using 192.42.93.30] send dns request to 192.42.93.30...
            [a.iana-servers.net. using 192.42.93.30] arp request received, send arp reply.
            [a.iana-servers.net. using 192.42.93.30] arp request received, send arp reply.
            [a.iana-servers.net. using 192.42.93.30] dns reply received:
            |   header:
            |   	id=3 qr opecode=Query !aa !tc !rd !ra rcode=NoError qdcount=1 ancount=0 nscount=4 arcount=6
            |   Question Section:
            |   	a.iana-servers.net.	IN	A
            |   Answer Section:
            |   Authority Section:
            |   	iana-servers.net.	172800	IN	NS	ns.icann.org.
            |   	iana-servers.net.	172800	IN	NS	a.iana-servers.net.
            |   	iana-servers.net.	172800	IN	NS	b.iana-servers.net.
            |   	iana-servers.net.	172800	IN	NS	c.iana-servers.net.
            |   Additional Section:
            |   	a.iana-servers.net.	172800	IN	A	199.43.135.53
            |   	b.iana-servers.net.	172800	IN	A	199.43.133.53
            |   	c.iana-servers.net.	172800	IN	A	199.43.134.53
            [a.iana-servers.net. using 192.42.93.30] target A resource record found in additional section. address=199.43.135.53
        [a.iana-servers.net. using 202.12.27.33] resolving another name server done. resolved_address=199.43.135.53
    [example.com. using 192.55.83.30] name server address resolved. name_server_address=199.43.135.53
    [example.com. using 192.55.83.30] resolving another name server... name_server_address=199.43.135.53
        [example.com. using 199.43.135.53] send dns request to 199.43.135.53...
        [example.com. using 199.43.135.53] dns reply received:
        |   header:
        |   	id=2 qr opecode=Query aa !tc !rd !ra rcode=NoError qdcount=1 ancount=6 nscount=0 arcount=0
        |   Question Section:
        |   	example.com.	IN	A
        |   Answer Section:
        |   	example.com.	300	IN	A	23.192.228.80
        |   	example.com.	300	IN	A	23.192.228.84
        |   	example.com.	300	IN	A	23.215.0.136
        |   	example.com.	300	IN	A	23.215.0.138
        |   	example.com.	300	IN	A	96.7.128.175
        |   	example.com.	300	IN	A	96.7.128.198
        |   Authority Section:
        |   Additional Section:
        [example.com. using 199.43.135.53] target A resource record found in answer section. address=23.192.228.80
    [example.com. using 192.55.83.30] resolving another name server done. resolved_address=23.192.228.80
[example.com. using 170.247.170.2] resolving another name server done. resolved_address=23.192.228.80
domain name resolved: 23.192.228.80
```
