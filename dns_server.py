#!/usr/bin/env python
from __future__ import print_function

import sys
from dnslib import DNSRecord, QTYPE, RR, A, DNSHeader, TXT, CNAME, MX, PTR,NS,DNSQuestion,RCODE,SOA,CLASS
from circuits import Component, Debugger, Event
from circuits.net.events import write
from circuits.net.sockets import UDPServer


class query(Event):

    """query Event"""

class find(Event):

    """query Event"""


class DNS(Component):

    """DNS Protocol Handling"""

    def read(self, peer, data):
       	self.fire(find(peer, DNSRecord.parse(data)))
		

class Lookup(Component):
	def find(self,peer,request):
		domainz = {
		"lachlan.tech.":
			{"A":"lachlan.tech. 300 IN A 203.149.66.14","TXT":"lachlan.tech 300 IN TXT 'keybase-site-verification=0OmhJU2PImM37e7-o6vLg7undd25kx4KPS4VX_klscg'","MX":"mail.lachlan.tech 300 IN MX 10 mail.lachlan.tech","NS":("""ns1.glewb.com. IN NS ns1.glewb.com \nns2.glewb.com. IN NS ns2.glewb.com"""),"SOA":"""ns1.glewb.com. IN SOA ns1.glewb.com. root.glewb.com. (
			1122334 ; serial
			21600      ; refresh after 6 hours
			3600       ; retry after 1 hour
			1209600     ; expire after 1 week
			86400 )    ; minimum TTL of 1 day"""},
		"mail.lachlan.tech.":
			{"A":"mail.lachlan.tech. 300 IN A 203.149.66.13"},
		"ns1.glewb.com.":
			{"A":"ns1.glewb.com. 300 IN A 203.149.66.13"},
		"ns2.glewb.com.":
			{"A":"ns2.glewb.com. 300 IN A 203.149.66.14"},
		"41.66.941.302.in-addr.arpa.":
			{"PTR":"lachlan.tech"},		
		}
		switcher = {1: "A",5:"CNAME",16: "TXT",15: "MX",2:"NS", 12:"PTR",6:"SOA"}

		qname = request.q.qname
		
		reqtype = QTYPE.get(request.q.qtype) if QTYPE.get(request.q.qtype) else False

		if not domainz.get(str(qname)) or not (domainz.get(str(qname))).get(switcher.get(request.q.qtype)):
			print(peer)
			self.fire(query(peer,request,False,False,qname))
		else:
			print(peer)
			result = (domainz.get(str(qname))).get(switcher.get(request.q.qtype))
			self.fire(query(peer,request,result,reqtype,qname))

class Answer(Component):

    def query(self, peer,request,result,reqtype,qname):

		id = request.header.id
		reply = DNSRecord(
			DNSHeader(id=id, qr=1, aa=1, ra=1),
			q=request.q
			)

		if reqtype and result:
			print(result)
			reply.add_answer(*RR.fromZone(result))
		else:
			print("nice try")
			print(request)
			reply.header.rcode = getattr(RCODE,'NXDOMAIN')

		reply.add_auth(*RR.fromZone(("{} 3600 NS ns1.glewb").format(str(qname))))	
		reply.add_auth(*RR.fromZone(("{} 3600 NS ns2.glewb").format(str(qname))))
		reply.add_ar(*RR.fromZone(("ns1.glewb 3600 A 203.149.66.13")))
		reply.add_ar(*RR.fromZone(("ns2.glewb 3600 A 203.149.66.14")))
		self.fire(write(peer, reply.pack()))

class DNSServer(Component):

    def init(self, bind=None, verbose=False):
        self.bind = bind or ("0.0.0.0", 53)

        if verbose:
            Debugger().register(self)

        self.transport = UDPServer(self.bind).register(self)
        self.protocol = DNS().register(self)
        self.answer = Answer().register(self)
	self.lookup = Lookup().register(self)


    def started(self, manager):
        print("DNS Server Started!", file=sys.stderr)

    def ready(self, server, bind):
        print("Ready! Listening on {0:s}:{1:d}".format(*bind), file=sys.stderr)


DNSServer(("0.0.0.0", 53), verbose=False).run()

