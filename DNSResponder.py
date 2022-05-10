#!/usr/bin/python3
from random import *
import sys
import getopt
import scapy.all as scapy


########### variable Section ###################
# NOTE: for a 10% NXDomain result set the variable below to 10. 
nxresponsefreq=10
# Set local IP to filter out any system DNS requests
src_IP="104.238.164.84"
# Set what you want the IPv4 response to be
resolved_ip4="1.2.3.4"
# Set what you want the IPV6 response to be
resolved_ip6="2800:370:10::110"
# Set the name of the public facing NIC
dev = "enp1s0"
# Set nameserver domain for any PTR requests
nameserver = "etinvasion.com"
######### end of Variable Section #############

filter = "udp port 53 and ip src not 127.0.0.1 and ip src not {}".format(src_IP)

def handle_packet(packet):
  ip = packet.getlayer(scapy.IP)
  udp = packet.getlayer(scapy.UDP)
  dns = packet.getlayer(scapy.DNS)
  randnum = randint(1, 100)
  if randnum <= nxresponsefreq:
    randrcode = 3
  else:
    randrcode = 0

  # Checks for queries.
  if dns.qr == 0 and dns.opcode == 0:
  # below line is for troubleshooting
    print("qr %s opcode %s qtype %s  rcode %s" % (dns.qr, dns.opcode, dns.qd.qtype, randrcode))
  
  # Gets the Queried host name for console output
    queried_host = dns.qd.qname[:-1].decode()

    # Checks if randrcode is 0, meaning no error, so provides an answer.  It also checks
    # if it's a AAAA request.  DNS won't send an AAAA request if it got a NXdomain 
    # response from an A request.  So if we ever get an AAAA request we must assume that 
    # the queried A reply was good.  So we always make the AAAA request good, otherwise
    # you could end up with a mixed response, meaning a resolved IPv4 with a NXDomain
    # below that from the AAAA request which is not a correct response.
    if ( randrcode == 0 or dns.qd.qtype == 28 ) and dns.qd.qtype != 12:
      # Checks if it's a A record request (1)
      if dns.qd.qtype == 1:
        #sets the resolved IP to the IPv4 variable
        resolved_ip=resolved_ip4
        dns_answer = scapy.DNSRR(rrname=queried_host + ".", 
                             ttl=333000, 
                             type="A", 
                             rclass="IN", 
                             rdata=resolved_ip)    
      # Checks if it's a AAAA record request (28)
      elif dns.qd.qtype == 28:
        resolved_ip=resolved_ip6
        dns_answer = scapy.DNSRR(rrname=queried_host + ".",
                               ttl=259200,
                               type="AAAA",
                               rclass="IN",
                               rdata=resolved_ip)
      # builds the reply
      dns_reply = scapy.IP(src=ip.dst, dst=ip.src) / \
                      scapy.UDP(sport=udp.dport, dport=udp.sport) / \
                      scapy.DNS(
                        id = dns.id,
                        qr = 1,
			opcode = 0,
			aa = 0,
			tc = 0,
			rd = 0,
			ra = 0,
			z = 0,
			rcode = 0,
		        qd = dns.qd,
		        an = dns_answer) 
      # outputs to terminal and sends UDP response.
      print("Send %s has %s to %s" % (queried_host, resolved_ip, ip.src))
      scapy.send(dns_reply, iface=dev)
    if dns.qd.qtype == 12: 
      dns_answer = scapy.DNSRR(rrname=queried_host + ".",
                         ttl=333000,
                         type="PTR",
                         rclass="IN",
                         rdata=nameserver)

      dns_reply = scapy.IP(src=ip.dst, dst=ip.src) / \
                      scapy.UDP(sport=udp.dport, dport=udp.sport) / \
                      scapy.DNS(
                        id = dns.id,
                        qr = 1,
                        opcode = 0,
                        aa = 0,
                        tc = 0,
                        rd = 1,
                        ra = 1, 
                        z = 0,
                        rcode = 0,
                        qd = dns.qd,
                        an = dns_answer)
      print("Send PTR replay to %s" % (ip.src))
      scapy.send(dns_reply, iface=dev)
    # This checks for rcode 3 which is NXDomain, then builds NXDomain responses. It also
    # makes sure it's a A request verses a AAAA request.
    if randrcode == 3 and dns.qd.qtype == 1:
      dns_reply = scapy.IP(src=ip.dst, dst=ip.src) / \
                      scapy.UDP(sport=udp.dport, dport=udp.sport) / \
                      scapy.DNS(
                        id = dns.id,
                        qr = 1,
			opcode = 0,
			aa = 0,
			tc = 0,
			ra = 0,
			z = 0,
			rcode = 3,
		        qd = dns.qd)
      # outputs to console and sends the NXDomain response
      print("Send %s has %s to %s" % (queried_host, "NXDomain", ip.src))
      scapy.send(dns_reply, iface=dev)

# Starts the listener.
print("Spoofing DNS requests on %s" % (dev))
scapy.sniff(iface=dev, filter=filter, prn=handle_packet)

