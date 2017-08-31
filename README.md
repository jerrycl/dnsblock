# dnsblock
A DNS filter for Linux desktops

PRELIMINARY
This software is useful to me, but not yet ready for the average user

PURPOSE

There seems to be a worldwide fight for control over your DNS requests.  Here's your chance to
bring the fight to your Linux desktop.

CAUTION

I'm still developing an install procedure for this that will work with most distributions
and existing firewall rules.  If you do an install now, you must then
run dnsblock, or the Internet will be broken until you reboot, or remove the firewall NAT
rules (try the command 'iptables -t nat -F' as root to deactivate.


DNS

If you know what DNS is, please skip ahead.

Every time you load a page in your browser, you may have dozens of sites included in that
page than need DNS lookups; Some of the sites you'll see this happening with are CDN servers,
which help decentralize and load balance the pages you visit.  

Some of these sites are just there to track you.  Targetted advertising on the Web is probably a good
thing, but you don't necessarily want companies whose security policies, procedures, and personnel
are unknown to you seeing almost every thing you do on the Web.. This tracking also slows down 
your browsing and eats up your bandwidth.  If you find this creepy, dnsblock is a tool to help 
control this tracking, aimed at the Linux desktop.

Another problem that can happen is with your ISP: they may decide that there is no such thing as
an NXDOMAIN (non-existent domain), and when you do try to look up a domain that isn't there, you
get hijacked to a cheesy search site controlled by your ISP. This can break software other than
your browser; in particular, spam filters may be broken by this behaviour.

If a domain doesn't exist, then it just doesn't exist.  

INSTALLATION

Change to the source directory for dnsblock, and type:

 make

Then as root, or as a sudo,

 make install.
 


Dnsblock does not need to be run as root. To run, type

 dnsblock \<actual dns server address\>

The dnsblock_blacklist file can be modified to include/remove tracking sites.  Dnsblock will
return a 'not found' (NXDOMAIN) response for any site whose url includes any of the strings in this file.


TODO

Allow dnsblock to run in the background.
Read the dns server from resolv.conf
Add a search for IP addresses that are returned when a domain doesn't exist.
