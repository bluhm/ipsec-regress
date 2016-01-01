#	$OpenBSD$

# The following ports must be installed:
#
# python-2.7          interpreted object-oriented programming language
# py-libdnet          python interface to libdnet
# scapy               powerful interactive packet manipulation in python

# Check wether all required python packages are installed.  If some
# are missing print a warning and skip the tests, but do not fail.
PYTHON_IMPORT != python2.7 -c 'from scapy.all import *' 2>&1 || true
.if ! empty(PYTHON_IMPORT)
regress:
	@echo '${PYTHON_IMPORT}'
	@echo install python and the scapy module for additional tests
.endif

# This test needs a manual setup of four machines
# The setup is the same as for regress/sys/net/pf_fragment
# Set up machines: SRC PF RT ECO
# SRC is the machine where this makefile is running.
# PF is running OpenBSD forwarding through pf, it is the test target.
# RT is a router forwarding packets, maximum MTU is 1300.
# ECO is reflecting the ping and UDP and TCP echo packets.
# RDR does not exist, PF redirects the traffic to ECO.
# AF does not exist, PF translates address family and sends to ECO.
# RTT addresses exist on ECO, PF has no route and must use route-to RT
# RPT addresses exist on SRC, PF has no route and must use reply-to SRC
#
# transport v4
# transport v6
# tunnel v4 in v4
# tunnel v6 in v4
# tunnel v4 in v6
# tunnel v6 in v6
#
#               1400       1300
# +---+   0   +---+   2   +--+  789  +---+
# |SRC| ----> |IPS| ----> |RT| ----> |ECO|
# +---+       +---+       +--+       +---+
#    out     in  out     in out     in
#

PREFIX4 ?=	10.188.1
PREFIX6 ?=	fdd7:e83e:66bc:1

SRC_OUT4 ?=	${PREFIX4}20.17
SRC_OUT6 ?=	${PREFIX6}20::17

IPS_IN4 ?=	${PREFIX4}20.70
IPS_IN6 ?=	${PREFIX6}20::70
IPS_OUT4 ?=	${PREFIX4}22.70
IPS_OUT6 ?=	${PREFIX6}22::70

RT_IN4 ?=	${PREFIX4}22.71
RT_IN6 ?=	${PREFIX6}22::71
RT_OUT40 ?=	${PREFIX4}27.71
RT_OUT60 ?=	${PREFIX6}27::71
RT_OUT44 ?=	${PREFIX4}28.71
RT_OUT64 ?=	${PREFIX6}28::71
RT_OUT46 ?=	${PREFIX4}29.71
RT_OUT66 ?=	${PREFIX6}29::71

ECO_IN40 ?=	${PREFIX4}27.72
ECO_IN60 ?=	${PREFIX6}27::72
ECO_IN44 ?=	${PREFIX4}28.72
ECO_IN64 ?=	${PREFIX6}28::72
ECO_IN46 ?=	${PREFIX4}29.72
ECO_IN66 ?=	${PREFIX6}29::72

#           1300       1400
# +---+   1   +--+  345  +---+
# |SRC| ----> |RT| ----> |IPS|
# +---+       +--+       +---+
#     in     out in     out
#

SRC_IN4 ?=	${PREFIX4}21.17
SRC_IN6 ?=	${PREFIX6}21::17

RT_OUT4 ?=	${PREFIX4}21.71
RT_OUT6 ?=	${PREFIX6}21::71
RT_IN40 ?=	${PREFIX4}23.71
RT_IN60 ?=	${PREFIX6}23::71
RT_IN44 ?=	${PREFIX4}24.71
RT_IN64 ?=	${PREFIX6}24::71
RT_IN46 ?=	${PREFIX4}25.71
RT_IN66 ?=	${PREFIX6}25::71

IPS_OUT40 ?=	${PREFIX4}23.70
IPS_OUT60 ?=	${PREFIX6}23::70
IPS_OUT44 ?=	${PREFIX4}24.70
IPS_OUT64 ?=	${PREFIX6}24::70
IPS_OUT46 ?=	${PREFIX4}25.70
IPS_OUT66 ?=	${PREFIX6}25::70

# Configure Addresses on the machines, there must be routes for the
# networks.  Adapt interface and addresse variables to your local
# setup.  To control the remote machine you need a hostname for
# ssh to log in.
#
# Run make check-setup to see if you got the setup correct.

SRC_IFIN ?=	tap2
SRC_IFOUT ?=	tap0
IPS_IFIN ?=	vio0
IPS_IFOUT ?=	vio1
RT_IF ?=	le0
ECO_IF ?=	vio0
IPS_SSH ?=	q70
RT_SSH ?=	q71
ECO_SSH ?=	q72

.if empty (IPS_SSH) || empty (RT_SSH) || empty (ECO_SSH)
regress:
	@echo this tests needs three remote machines to operate on
	@echo IPS_SSH RT_SSH ECO_SSH are empty
	@echo fill out these variables for additional tests, then
	@echo check wether your test machines are set up properly
.endif

.MAIN: all

.if ! empty (PF_SSH)
.if make (regress) || make (all)
.BEGIN: pf.conf addr.py
	@echo
	${SUDO} true
	ssh root@${IPS_SSH} true
	ssh root@${RT_SSH} true
	ssh root@${ECO_SSH} true
	rm -f stamp-ipsec
.endif
.endif

depend: addr.py

# Create python include file containing the addresses.
addr.py: Makefile
	rm -f $@ $@.tmp
	echo 'SRC_IFIN="${SRC_IFIN}"' >>$@.tmp
	echo 'SRC_IFOUT="${SRC_IFOUT}"' >>$@.tmp
	echo 'IPS_IFIN="${IPS_IFIN}"' >>$@.tmp
	echo 'IPS_IFOUT="${IPS_IFOUT}"' >>$@.tmp
	echo 'RT_IF="${RT_IF}"' >>$@.tmp
	echo 'ECO_IF="${ECO_IF}"' >>$@.tmp
.for ipv in 4 6
.for var in SRC_IN SRC_OUT RT_IN RT_OUT IPS_IN IPS_OUT
	echo '${var}${ipv}="${${var}${ipv}}"' >>$@.tmp
.endfor
.for tun in 0 4 6
.for var in IPS_OUT RT_IN RT_OUT ECO_IN
	echo '${var}${ipv}${tun}="${${var}${ipv}${tun}}"' >>$@.tmp
.endfor
.endfor
.endfor
	mv $@.tmp $@

# load the ipsec sa and flow into the kernel of the SRC and PF machine
stamp-ipsec: addr.py ipsec.conf
	${SUDO} ipsecctl -F
	cat addr.py ${.CURDIR}/ipsec.conf | ipsecctl -n -f -
	cat addr.py ${.CURDIR}/ipsec.conf | \
	    ${SUDO} ipsecctl -f -
	cat addr.py ${.CURDIR}/ipsec.conf | \
	    ssh root@${IPS_SSH} ipsecctl -f - \
	    -D FROM=to -D TO=from -D LOCAL=peer -D PEER=local
	@date >$@

etc/hostname.${SRC_IFOUT}: Makefile
	mkdir -p etc
	rm -f $@ $@.tmp
	echo '### regress $@' >$@.tmp
	echo '# SRC_OUT' >>$@.tmp
	echo 'inet alias ${SRC_OUT4}/24' >>$@.tmp
	echo 'inet6 alias ${SRC_OUT6}/64' >>$@.tmp
.for tun in 0 4 6
	echo '# ECO_IN${tun} IPS_IN' >>$@.tmp
	echo '!route -q delete -inet ${ECO_IN4${tun}}/24' >>$@.tmp
	echo '!route add -inet ${ECO_IN4${tun}}/24 ${IPS_IN4}' >>$@.tmp
	echo '!route -q delete -inet6 ${ECO_IN6${tun}}/64' >>$@.tmp
	echo '!route add -inet6 ${ECO_IN6${tun}}/64 ${IPS_IN6}' >>$@.tmp
.endfor
	mv $@.tmp $@

${IPS_SSH}/hostname.${IPS_IFIN}: Makefile
	mkdir -p ${IPS_SSH}
	rm -f $@ $@.tmp
	echo '### regress $@' >$@.tmp
	echo '# IPS_IN' >>$@.tmp
	echo 'inet alias ${IPS_IN4}/24' >>$@.tmp
	echo 'inet6 alias ${IPS_IN6}/64' >>$@.tmp
	mv $@.tmp $@

${IPS_SSH}/hostname.${IPS_IFOUT}: Makefile
	mkdir -p etc
	rm -f $@ $@.tmp
	echo '### regress $@' >$@.tmp
	echo '# IPS_OUT' >>$@.tmp
	echo 'inet alias ${IPS_OUT4}/24' >>$@.tmp
	echo 'inet6 alias ${IPS_OUT6}/64' >>$@.tmp
.for tun in 0 4 6
	echo '# IPS_OUT${tun}' >>$@.tmp
	echo 'inet alias ${IPS_OUT4${tun}}/24' >>$@.tmp
	echo 'inet6 alias ${IPS_OUT6${tun}}/64' >>$@.tmp
.endfor
.for tun in 0 4 6
	echo '# ECO_IN${tun} RT_IN' >>$@.tmp
	echo '!route -q delete -inet ${ECO_IN4${tun}}/24' >>$@.tmp
	echo '!route add -inet ${ECO_IN4${tun}}/24 ${RT_IN4}' >>$@.tmp
	echo '!route -q delete -inet6 ${ECO_IN6${tun}}/64' >>$@.tmp
	echo '!route add -inet6 ${ECO_IN6${tun}}/64 ${RT_IN6}' >>$@.tmp
.endfor
	echo '# SRC_IN RT_IN0' >>$@.tmp
	echo '!route -q delete -inet ${SRC_IN4}/24' >>$@.tmp
	echo '!route add -inet ${SRC_IN4}/24 ${RT_IN40}' >>$@.tmp
	echo '!route -q delete -inet6 ${SRC_IN60}/64' >>$@.tmp
	echo '!route add -inet6 ${SRC_IN6}/64 ${RT_IN60}' >>$@.tmp
	mv $@.tmp $@

${RT_SSH}/hostname.${RT_IF}: Makefile
	mkdir -p ${RT_SSH}
	rm -f $@ $@.tmp
	echo '### regress $@' >$@.tmp
.for dir in IN OUT
	echo '# RT_${dir}' >>$@.tmp
	echo 'inet alias ${RT_${dir}4}/24' >>$@.tmp
	echo 'inet6 alias ${RT_${dir}6}/64' >>$@.tmp
.for tun in 0 4 6
	echo '# RT_${dir}${tun}' >>$@.tmp
	echo 'inet alias ${RT_${dir}4${tun}}/24' >>$@.tmp
	echo 'inet6 alias ${RT_${dir}6${tun}}/64' >>$@.tmp
.endfor
.endfor
	echo '# SRC_OUT${tun} IPS_OUT' >>$@.tmp
	echo '!route -q delete -inet ${SRC_OUT4${tun}}/24' >>$@.tmp
	echo '!route add -inet ${SRC_OUT4${tun}}/24 ${IPS_OUT4}' >>$@.tmp
	echo '!route -q delete -inet6 ${SRC_OUT6${tun}}/64' >>$@.tmp
	echo '!route add -inet6 ${SRC_OUT6${tun}}/64 ${IPS_OUT6}' >>$@.tmp
	mv $@.tmp $@

${ECO_SSH}/hostname.${ECO_IF}: Makefile
	mkdir -p ${ECO_SSH}
	rm -f $@ $@.tmp
	echo '### regress $@' >$@.tmp
.for tun in 0 4 6
	echo '# ECO_IN${tun}' >>$@.tmp
	echo 'inet alias ${ECO_IN4${tun}}/24' >>$@.tmp
	echo 'inet6 alias ${ECO_IN6${tun}}/64' >>$@.tmp
.endfor
	echo '# SRC_OUT RT_OUT0' >>$@.tmp
	echo '!route -q delete -inet ${SRC_OUT4}/24' >>$@.tmp
	echo '!route add -inet ${SRC_OUT4}/24 ${RT_OUT40}' >>$@.tmp
	echo '!route -q delete -inet6 ${SRC_OUT6}/64' >>$@.tmp
	echo '!route add -inet6 ${SRC_OUT6}/64 ${RT_OUT60}' >>$@.tmp
	mv $@.tmp $@

etc/hostname.${SRC_IFIN}: Makefile
	mkdir -p etc
	rm -f $@ $@.tmp
	echo '### regress $@' >$@.tmp
	echo '# SRC_IN' >>$@.tmp
	echo 'inet alias ${SRC_IN4}/24' >>$@.tmp
	echo 'inet6 alias ${SRC_IN6}/64' >>$@.tmp
.for tun in 0 4 6
	echo '# IPS_OUT${tun} RT_OUT' >>$@.tmp
	echo '!route -q delete -inet ${IPS_OUT4${tun}}/24' >>$@.tmp
	echo '!route add -inet ${IPS_OUT4${tun}}/24 ${RT_OUT4}' >>$@.tmp
	echo '!route -q delete -inet6 ${IPS_OUT6${tun}}/64' >>$@.tmp
	echo '!route add -inet6 ${IPS_OUT6${tun}}/64 ${RT_OUT6}' >>$@.tmp
.endfor
	mv $@.tmp $@

stamp-hostname: etc/hostname.${SRC_IFOUT} \
    ${IPS_SSH}/hostname.${IPS_IFIN} \
    ${IPS_SSH}/hostname.${IPS_IFOUT} \
    ${RT_SSH}/hostname.${RT_IF} \
    ${ECO_SSH}/hostname.${ECO_IF} \
    etc/hostname.${SRC_IFIN}
.for if in IPS_IFOUT IPS_IFIN
	ssh root@${IPS_SSH} "umask 027;\
	    { sed '/^### regress/,\$$d' /etc/hostname.${${if}} && cat; }\
	    >/etc/hostname.${${if}}.tmp"\
	    <${IPS_SSH}/hostname.${${if}}
	ssh root@${IPS_SSH}\
	    "mv /etc/hostname.${${if}}.tmp /etc/hostname.${${if}} &&\
	    sh /etc/netstart ${${if}}"
.endfor
.for host in RT ECO
	ssh root@${${host}_SSH} "umask 027;\
	    { sed '/^### regress/,\$$d' /etc/hostname.${${host}_IF} && cat; }\
	    >/etc/hostname.${${host}_IF}.tmp"\
	    <${${host}_SSH}/hostname.${${host}_IF}
	ssh root@${${host}_SSH}\
	    "mv /etc/hostname.${${host}_IF}.tmp /etc/hostname.${${host}_IF} &&\
	    sh /etc/netstart ${${host}_IF}"
.endfor
.for if in SRC_IFOUT SRC_IFIN
	${SUDO} sh -c "umask 027;\
	    { sed '/^### regress/,\$$d' /etc/hostname.${${if}} &&\
	    cat etc/hostname.${${if}}; } >/etc/hostname.${${if}}.tmp"
	${SUDO} mv /etc/hostname.${${if}}.tmp /etc/hostname.${${if}}
	${SUDO} sh /etc/netstart ${${if}}
.endfor
	date >$@

# Set variables so that make runs with and without obj directory.
# Only do that if necessary to keep visible output short.
.if ${.CURDIR} == ${.OBJDIR}
PYTHON =	python2.7 ./
.else
PYTHON =	PYTHONPATH=${.OBJDIR} python2.7 ${.CURDIR}/
.endif

# Ping all addresses.  This ensures that the IP addresses are configured
# and all routing table are set up to allow bidirectional packet flow.
# Note that RDR does not exist physically.  So this traffic is rewritten
# by PF and handled by ECO.
TARGETS +=	ping  ping6

run-regress-ping:
	@echo '\n======== $@ ========'
.for var in SRC_IN SRC_OUT RT_OUT IPS_IN
	@echo Check ping ${var}4:
	ping -n -c 1 ${${var}4}
.endfor
.for var in IPS_OUT RT_OUT ECO_IN
.for tun in 0 4 6
	@echo Check ping ${var}4${tun}:
	ping -n -c 1 ${${var}4${tun}}
.endfor
.endfor

run-regress-ping6: stamp-ipsec
	@echo '\n======== $@ ========'
.for var in SRC_IN SRC_OUT RT_OUT IPS_IN
	@echo Check ping ${var}6:
	ping6 -n -c 1 ${${var}6}
.endfor
.for var in IPS_OUT RT_OUT ECO_IN
.for tun in 0 4 6
	@echo Check ping ${var}6${tun}:
	ping6 -n -c 1 ${${var}6${tun}}
.endfor
.endfor

# Send a large IPv4/ICMP-Echo-Request packet with enabled DF bit and
# parse response packet to determine MTU of the packet filter.  The
# outgoing MTU of PF has to be 1400 octets.  Packet size is 1500.
# Check that the IP length of the original packet and the ICMP
# quoted packet are the same.
# XXX AF_IN is broken with PF MTU
TARGETS +=	ping-mtu-1400 ping6-mtu-1400

run-regress-ping-mtu-1400: addr.py stamp-pfctl
	@echo '\n======== $@ ========'
.for ip in ECO_IN ECO_OUT RDR_IN RDR_OUT RTT_IN
	@echo Check path MTU to ${ip} is 1400
	${SUDO} ${PYTHON}ping_mtu.py ${SRC_OUT} ${${ip}} 1500 1400
.endfor
	@echo Check path MTU from RPT_OUT is 1400
	${SUDO} ${PYTHON}ping_mtu.py ${RPT_OUT} ${ECO_IN} 1500 1400

run-regress-ping6-mtu-1400: addr.py stamp-pfctl
	@echo '\n======== $@ ========'
.for ip in ECO_IN ECO_OUT RDR_IN RDR_OUT RTT_IN
	@echo Check path MTU to ${ip}6 is 1400
	${SUDO} ${PYTHON}ping6_mtu.py ${SRC_OUT6} ${${ip}6} 1500 1400
.endfor
	@echo Check path MTU from RPT_OUT6 is 1400
	${SUDO} ${PYTHON}ping6_mtu.py ${RPT_OUT6} ${ECO_IN6} 1500 1400

# Send a large IPv4/ICMP-Echo-Request packet with enabled DF bit and
# parse response packet to determine MTU of the router.  The MTU has
# to be 1300 octets.  The MTU has to be defined at out interface of
# the router RT before.  Packet size is 1400 to pass PF MTU.
# Check that the IP length of the original packet and the ICMP
# quoted packet are the same.
TARGETS +=	ping-mtu-1300 ping6-mtu-1300

run-regress-ping-mtu-1300: addr.py stamp-pfctl
	@echo '\n======== $@ ========'
.for ip in ECO_IN ECO_OUT RDR_IN RDR_OUT RTT_IN
	@echo Check path MTU to ${ip} is 1300
	${SUDO} ${PYTHON}ping_mtu.py ${SRC_OUT} ${${ip}} 1400 1300
.endfor
	@echo Check path MTU to AF_IN is 1280
	${SUDO} ${PYTHON}ping_mtu.py ${SRC_OUT} ${AF_IN} 1380 1280
	@echo Check path MTU from RPT_OUT is 1300
	${SUDO} ${PYTHON}ping_mtu.py ${RPT_OUT} ${ECO_IN} 1400 1300

run-regress-ping6-mtu-1300: addr.py stamp-pfctl
	@echo '\n======== $@ ========'
.for ip in ECO_IN ECO_OUT RDR_IN RDR_OUT RTT_IN
	@echo Check path MTU to ${ip}6 is 1300
	${SUDO} ${PYTHON}ping6_mtu.py ${SRC_OUT6} ${${ip}6} 1400 1300
.endfor
	@echo Check path MTU to AF_IN6 is 1320
	${SUDO} ${PYTHON}ping6_mtu.py ${SRC_OUT6} ${AF_IN6} 1420 1320
	@echo Check path MTU from RPT_OUT6 is 1300
	${SUDO} ${PYTHON}ping6_mtu.py ${RPT_OUT6} ${ECO_IN6} 1400 1300

# Send one UDP echo port 7 packet to all destination addresses with netcat.
# The response must arrive in 1 second.
TARGETS +=	udp  udp6

run-regress-udp: stamp-pfctl
	@echo '\n======== $@ ========'
.for ip in ECO_IN ECO_OUT RDR_IN RDR_OUT AF_IN RTT_IN
	@echo Check UDP ${ip}:
	( echo $$$$ | nc -u ${${ip}} 7 & sleep 1; kill $$! ) | grep $$$$
.endfor
	@echo Check UDP RPT_OUT:
	( echo $$$$ | nc -u -s ${RPT_OUT} ${ECO_IN} 7 & sleep 1; kill $$! ) | grep $$$$

run-regress-udp6: stamp-pfctl
	@echo '\n======== $@ ========'
.for ip in ECO_IN ECO_OUT RDR_IN RDR_OUT AF_IN RTT_IN
	@echo Check UDP ${ip}6:
	( echo $$$$ | nc -u ${${ip}6} 7 & sleep 1; kill $$! ) | grep $$$$
.endfor
	@echo Check UDP RPT_OUT6:
	( echo $$$$ | nc -u -s ${RPT_OUT6} ${ECO_IN6} 7 & sleep 1; kill $$! ) | grep $$$$

# Send a data stream to TCP echo port 7 to all destination addresses
# with netcat.  Use enough data to make sure PMTU discovery works.
# Count the reflected bytes and compare with the transmitted ones.
# Delete host route before test to trigger PMTU discovery.
# XXX AF_IN is broken with PF MTU, make sure that it hits RT MTU 1300.
TARGETS +=	tcp  tcp6

run-regress-tcp: stamp-pfctl
	@echo '\n======== $@ ========'
.for ip in ECO_IN ECO_OUT RDR_IN RDR_OUT RTT_IN
	@echo Check tcp ${ip}:
	${SUDO} route -n delete -host -inet ${${ip}} || true
	openssl rand 200000 | nc -N ${${ip}} 7 | wc -c | grep '200000$$'
.endfor
	@echo Check tcp AF_IN:
	${SUDO} route -n delete -host -inet ${AF_IN} || true
	${SUDO} ${PYTHON}ping_mtu.py ${SRC_OUT} ${AF_IN} 1380 1280 || true
	openssl rand 200000 | nc -N ${AF_IN} 7 | wc -c | grep '200000$$'
	@echo Check tcp RPT_OUT:
	${SUDO} route -n delete -host -inet ${RPT_OUT} || true
	openssl rand 200000 | nc -N -s ${RPT_OUT} ${ECO_IN} 7 | wc -c | grep '200000$$'

run-regress-tcp6: stamp-pfctl
	@echo '\n======== $@ ========'
.for ip in ECO_IN ECO_OUT RDR_IN RDR_OUT RTT_IN
	@echo Check tcp ${ip}6:
	${SUDO} route -n delete -host -inet6 ${${ip}6} || true
	openssl rand 200000 | nc -N ${${ip}6} 7 | wc -c | grep '200000$$'
.endfor
	@echo Check tcp AF_IN6:
	${SUDO} route -n delete -host -inet6 ${AF_IN6} || true
	${SUDO} ${PYTHON}ping6_mtu.py ${SRC_OUT6} ${AF_IN6} 1420 1320 || true
	openssl rand 200000 | nc -N ${AF_IN6} 7 | wc -c | grep '200000$$'
	@echo Check tcp RPT_OUT6:
	${SUDO} route -n delete -host -inet6 ${RPT_OUT6} || true
	openssl rand 200000 | nc -N -s ${RPT_OUT6} ${ECO_IN6} 7 | wc -c | grep '200000$$'

#REGRESS_TARGETS =	${TARGETS:S/^/run-regress-/}
REGRESS_TARGETS =	${TARGETS:Mping:S/^/run-regress-/}

${REGRESS_TARGETS}: stamp-ipsec stamp-hostname

CLEANFILES +=		addr.py *.pyc *.log stamp-* */hostname.*

.include <bsd.regress.mk>
