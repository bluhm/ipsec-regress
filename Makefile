#	$OpenBSD$

# The following ports must be installed:
#
# python-2.7          interpreted object-oriented programming language
# py-libdnet          python interface to libdnet
# scapy               powerful interactive packet manipulation in python

# Check wether all required python packages are installed.  If some
# are missing print a warning and skip the tests, but do not fail.
PYTHON_IMPORT !!= python2.7 -c 'from scapy.all import *' 2>&1 || true
.if ! empty(PYTHON_IMPORT)
regress:
	@echo '${PYTHON_IMPORT}'
	@echo install python and the scapy module for additional tests
	@echo SKIPPED
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
# 3 transport v4
# 3 transport v6
# 4 tunnel v4 in v4 stack
# 4 tunnel v6 in v4 stack
# 5 tunnel v4 in v6 stack
# 5 tunnel v6 in v6 stack
# 6 tunnel v4 in v4 forward
# 6 tunnel v6 in v4 forward
# 7 tunnel v4 in v6 forward
# 7 tunnel v6 in v6 forward
#
#               1400       1300
# +---+   0   +---+   1   +---+   2   +---+
# |SRC| ----> |IPS| ----> |RT | ----> |ECO|
# +---+   3   +---+ 45    +---+    67 +---+
#     isp   src   rt    isp   rcp    rt
#

PREFIX_IPV4 ?=	10.188.10
PREFIX_IPV6 ?=	fdd7:e83e:66bc:10

SRC_OUT_IPV4 ?=	${PREFIX_IPV4}0.17
SRC_OUT_IPV6 ?=	${PREFIX_IPV6}0::17
SRC_TRANSP_IPV4 ?=	${PREFIX_IPV4}3.17
SRC_TRANSP_IPV6 ?=	${PREFIX_IPV6}3::17

IPS_IN_IPV4 ?=	${PREFIX_IPV4}0.70
IPS_IN_IPV6 ?=	${PREFIX_IPV6}0::70
IPS_OUT_IPV4 ?=	${PREFIX_IPV4}1.70
IPS_OUT_IPV6 ?=	${PREFIX_IPV6}1::70
IPS_TRANSP_IPV4 ?=	${PREFIX_IPV4}3.70
IPS_TRANSP_IPV6 ?=	${PREFIX_IPV6}3::70
IPS_TUNNEL4_IPV4 ?=	${PREFIX_IPV4}4.70
IPS_TUNNEL4_IPV6 ?=	${PREFIX_IPV6}4::70
IPS_TUNNEL6_IPV4 ?=	${PREFIX_IPV4}5.70
IPS_TUNNEL6_IPV6 ?=	${PREFIX_IPV6}5::70

RT_IN_IPV4 ?=	${PREFIX_IPV4}1.71
RT_IN_IPV6 ?=	${PREFIX_IPV6}1::71
RT_OUT_IPV4 ?=	${PREFIX_IPV4}2.71
RT_OUT_IPV6 ?=	${PREFIX_IPV6}2::71

ECO_IN_IPV4 ?=	${PREFIX_IPV4}2.72
ECO_IN_IPV6 ?=	${PREFIX_IPV6}2::72
ECO_TUNNEL4_IPV4 ?=	${PREFIX_IPV4}6.72
ECO_TUNNEL4_IPV6 ?=	${PREFIX_IPV6}6::72
ECO_TUNNEL6_IPV4 ?=	${PREFIX_IPV4}7.72
ECO_TUNNEL6_IPV6 ?=	${PREFIX_IPV6}7::72

# Configure Addresses on the machines, there must be routes for the
# networks.  Adapt interface and addresse variables to your local
# setup.  To control the remote machine you need a hostname for
# ssh to log in.
#
# Run make check-setup to see if you got the setup correct.

SRC_OUT_IF ?=	tap4
IPS_IN_IF ?=	vio1
IPS_OUT_IF ?=	vio2
RT_IN_IF ?=	vio1
RT_OUT_IF ?=	vio2
ECO_IN_IF ?=	vio1

.if empty (IPS_SSH) || empty (RT_SSH) || empty (ECO_SSH)
regress:
	@echo this tests needs three remote machines to operate on
	@echo IPS_SSH RT_SSH ECO_SSH are empty
	@echo fill out these variables for additional tests, then
	@echo check wether your test machines are set up properly
	@echo SKIPPED
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
.for host in SRC IPS RT ECO
.for dir in IN OUT
.for ipv in IF IPV4 IPV6
	echo '${host}_${dir}_${ipv}="${${host}_${dir}_${ipv}}"' >>$@.tmp
.endfor
.endfor
.endfor
.for host in IPS ECO
.for tun in TUNNEL4 TUNNEL6
.for ipv in IPV4 IPV6
	echo '${host}_${tun}_${ipv}="${${host}_${tun}_${ipv}}"' >>$@.tmp
.endfor
.endfor
.endfor
.for host in SRC IPS
.for ipv in IPV4 IPV6
	echo '${host}_TRANSP_${ipv}="${${host}_TRANSP_${ipv}}"' >>$@.tmp
.endfor
.endfor
	mv $@.tmp $@

# load the ipsec sa and flow into the kernel of the SRC and IPS machine
stamp-ipsec: addr.py ipsec.conf
	@echo '\n======== $@ ========'
	${SUDO} ipsecctl -F
	cat addr.py ${.CURDIR}/ipsec.conf | ipsecctl -n -f -
	cat addr.py ${.CURDIR}/ipsec.conf | \
	    ${SUDO} ipsecctl -f -
	ssh root@${IPS_SSH} ipsecctl -F
	cat addr.py ${.CURDIR}/ipsec.conf | \
	    ssh root@${IPS_SSH} ipsecctl -f - \
	    -D FROM=to -D TO=from -D LOCAL=peer -D PEER=local
	@date >$@


etc/hostname.${SRC_OUT_IF}: Makefile
	@echo '\n======== $@ ========'
	mkdir -p ${@:H}
	rm -f $@ $@.tmp
	echo '### regress ipsec $@' >$@.tmp
.for dir in OUT TRANSP
	echo '# SRC_${dir}' >>$@.tmp
.for inet ipv masklen in inet IPV4 255.255.255.0 inet6 IPV6 64
	echo '${inet} alias ${SRC_${dir}_${ipv}} ${masklen}' >>$@.tmp
.endfor
.endfor
.for host in RT ECO
	echo '# ${host}_IN/pfxlen IPS_IN' >>$@.tmp
.for inet ipv pfxlen in inet IPV4 24 inet6 IPV6 64
	echo '!route -q delete -${inet} ${${host}_IN_${ipv}}/${pfxlen}'\
	    >>$@.tmp
	echo '!route add -${inet} ${${host}_IN_${ipv}}/${pfxlen}'\
	    ${IPS_IN_${ipv}} >>$@.tmp
.endfor
.endfor
.for host in IPS ECO
.for dir in TUNNEL4 TUNNEL6
	echo '# ${host}_${dir}/pfxlen reject' >>$@.tmp
.for inet ipv pfxlen in inet IPV4 24 inet6 IPV6 64
	echo '!route -q delete -${inet} ${${host}_${dir}_${ipv}}/${pfxlen}'\
	    >>$@.tmp
	echo '!route add -${inet} ${${host}_${dir}_${ipv}}/${pfxlen}'\
	    -reject ${SRC_OUT_${ipv}} >>$@.tmp
.endfor
.endfor
.endfor
	mv $@.tmp $@

${IPS_SSH}/hostname.${IPS_IN_IF}: Makefile
	mkdir -p ${@:H}
	rm -f $@ $@.tmp
	echo '### regress ipsec $@' >$@.tmp
.for dir in IN TRANSP
	echo '# IPS_${dir}' >>$@.tmp
.for inet ipv masklen in inet IPV4 255.255.255.0 inet6 IPV6 64
	echo '${inet} alias ${IPS_${dir}_${ipv}} ${masklen}' >>$@.tmp
.endfor
.endfor
	mv $@.tmp $@

${IPS_SSH}/hostname.${IPS_OUT_IF}: Makefile
	@echo '\n======== $@ ========'
	mkdir -p ${@:H}
	rm -f $@ $@.tmp
	echo '### regress ipsec $@' >$@.tmp
.for dir in OUT TUNNEL4 TUNNEL6
	echo '# IPS_${dir}' >>$@.tmp
.for inet ipv masklen in inet IPV4 255.255.255.0 inet6 IPV6 64
	echo '${inet} alias ${IPS_${dir}_${ipv}} ${masklen}' >>$@.tmp
.endfor
.endfor
.for dir in IN TUNNEL4 TUNNEL6
	echo '# ECO_${dir}/pfxlen RT_IN' >>$@.tmp
.for inet ipv pfxlen in inet IPV4 24 inet6 IPV6 64
	echo '!route -q delete -${inet} ${ECO_${dir}_${ipv}}/${pfxlen}'\
	    >>$@.tmp
	echo '!route add -${inet} ${ECO_${dir}_${ipv}}/${pfxlen}'\
	    ${RT_IN_${ipv}} >>$@.tmp
.endfor
.endfor
	mv $@.tmp $@

${RT_SSH}/hostname.${RT_IN_IF}: Makefile
	@echo '\n======== $@ ========'
	mkdir -p ${@:H}
	rm -f $@ $@.tmp
	echo '### regress ipsec $@' >$@.tmp
	echo '# RT_IN' >>$@.tmp
.for inet ipv masklen in inet IPV4 255.255.255.0 inet6 IPV6 64
	echo '${inet} alias ${RT_IN_${ipv}} ${masklen}' >>$@.tmp
.endfor
.for dir in OUT TRANSP
	echo '# SRC_${dir}/pfxlen IPS_OUT' >>$@.tmp
.for inet ipv pfxlen in inet IPV4 24 inet6 IPV6 64
	echo '!route -q delete -${inet} ${SRC_${dir}_${ipv}}/${pfxlen}'\
	    >>$@.tmp
	echo '!route add -${inet} ${SRC_${dir}_${ipv}}/${pfxlen}'\
	    ${IPS_OUT_${ipv}} >>$@.tmp
.endfor
.endfor
	mv $@.tmp $@

${RT_SSH}/hostname.${RT_OUT_IF}: Makefile
	@echo '\n======== $@ ========'
	mkdir -p ${@:H}
	rm -f $@ $@.tmp
	echo '### regress ipsec $@' >$@.tmp
	echo '# RT_OUT' >>$@.tmp
.for inet ipv masklen in inet IPV4 255.255.255.0 inet6 IPV6 64
	echo '${inet} alias ${RT_OUT_${ipv}} ${masklen}' >>$@.tmp
.endfor
.for dir in TUNNEL4 TUNNEL6
	echo '# ECO_${dir}/pfxlen ECO_IN' >>$@.tmp
.for inet ipv pfxlen in inet IPV4 24 inet6 IPV6 64
	echo '!route -q delete -${inet} ${ECO_${dir}_${ipv}}/${pfxlen}'\
	    >>$@.tmp
	echo '!route add -${inet} ${ECO_${dir}_${ipv}}/${pfxlen}'\
	    ${ECO_IN_${ipv}} >>$@.tmp
.endfor
.endfor
	mv $@.tmp $@

${ECO_SSH}/hostname.${ECO_IN_IF}: Makefile
	@echo '\n======== $@ ========'
	mkdir -p ${@:H}
	rm -f $@ $@.tmp
	echo '### regress ipsec $@' >$@.tmp
.for dir in IN TUNNEL4 TUNNEL6
	echo '# ECO_${dir}' >>$@.tmp
.for inet ipv masklen in inet IPV4 255.255.255.0 inet6 IPV6 64
	echo '${inet} alias ${ECO_${dir}_${ipv}} ${masklen}' >>$@.tmp
.endfor
.endfor
	echo '# IPS_OUT/pfxlen RT_OUT' >>$@.tmp
.for inet ipv pfxlen in inet IPV4 24 inet6 IPV6 64
	echo '!route -q delete -${inet} ${IPS_OUT_${ipv}}/${pfxlen}'\
	    >>$@.tmp
	echo '!route add -${inet} ${IPS_OUT_${ipv}}/${pfxlen}'\
	    ${RT_OUT_${ipv}} >>$@.tmp
.endfor
.for dir in OUT TRANSP
	echo '# SRC_${dir}/pfxlen RT_OUT' >>$@.tmp
.for inet ipv pfxlen in inet IPV4 24 inet6 IPV6 64
	echo '!route -q delete -${inet} ${SRC_${dir}_${ipv}}/${pfxlen}'\
	    >>$@.tmp
	echo '!route add -${inet} ${SRC_${dir}_${ipv}}/${pfxlen}'\
	    ${RT_OUT_${ipv}} >>$@.tmp
.endfor
.endfor
	mv $@.tmp $@

stamp-hostname: etc/hostname.${SRC_OUT_IF} \
    ${IPS_SSH}/hostname.${IPS_IN_IF} ${IPS_SSH}/hostname.${IPS_OUT_IF} \
    ${RT_SSH}/hostname.${RT_IN_IF} ${RT_SSH}/hostname.${RT_OUT_IF} \
    ${ECO_SSH}/hostname.${ECO_IN_IF}
	@echo '\n======== $@ ========'
	${SUDO} sh -c "umask 027;\
	    { sed '/^### regress/,\$$d' /etc/hostname.${SRC_OUT_IF} &&\
	    cat; } >/etc/hostname.${SRC_OUT_IF}.tmp"\
	    <etc/hostname.${SRC_OUT_IF}
	${SUDO} sh -c "mv /etc/hostname.${SRC_OUT_IF}.tmp\
	    /etc/hostname.${SRC_OUT_IF} &&\
	    sh /etc/netstart ${SRC_OUT_IF}"
.for host dir in IPS IN IPS OUT RT IN RT OUT ECO IN
	ssh root@${${host}_SSH} "umask 027;\
	    { sed '/^### regress/,\$$d' /etc/hostname.${${host}_${dir}_IF} &&\
	    cat; } >/etc/hostname.${${host}_${dir}_IF}.tmp"\
	    <${${host}_SSH}/hostname.${${host}_${dir}_IF}
	ssh root@${${host}_SSH} "mv /etc/hostname.${${host}_${dir}_IF}.tmp\
	    /etc/hostname.${${host}_${dir}_IF} &&\
	    sh /etc/netstart ${${host}_${dir}_IF}"
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

.for host dir in SRC OUT SRC TRANSP \
    IPS IN IPS OUT IPS TUNNEL4 IPS TUNNEL6 \
    RT IN RT OUT \
    ECO IN ECO TUNNEL4 ECO TUNNEL6
.for ping ipv in ping IPV4 ping6 IPV6
TARGETS +=      ping-${host}-${dir}-${ipv}
run-regress-ping-${host}-${dir}-${ipv}:
	@echo '\n======== $@ ========'
	${ping} -n -c 1 ${${host}_${dir}_${ipv}}
.endfor
.endfor

REGRESS_TARGETS =	${TARGETS:S/^/run-regress-/}

#${REGRESS_TARGETS}: stamp-ipsec stamp-hostname

CLEANFILES +=		addr.py *.pyc *.log stamp-* */hostname.*

.PHONY: check-setup

# Check wether the address, route and remote setup is correct
check-setup: check-setup-src check-setup-ips

check-setup-src:
	@echo '\n======== $@ ========'
.for ping inet ipv in ping inet IPV4 ping6 inet6 IPV6
.for host dir in SRC OUT SRC TRANSP
	${ping} -n -c 1 ${${host}_${dir}_${ipv}}  # ${host}_${dir}_${ipv}
	route -n get -${inet} ${${host}_${dir}_${ipv}} |\
	    grep -q 'flags: .*LOCAL'  # ${host}_${dir}_${ipv}
.endfor
	${ping} -n -c 1 ${IPS_IN_${ipv}}  # IPS_IN_${ipv}
.for host dir in IPS OUT RT IN RT OUT ECO IN
	route -n get -${inet} ${${host}_${dir}_${ipv}} |\
	    fgrep -q 'gateway: ${IPS_IN_${ipv}}' \
	    # ${host}_${dir}_${ipv} IPS_IN_${ipv}
.endfor
.for host dir in IPS TUNNEL4 IPS TUNNEL6 ECO TUNNEL4 ECO TUNNEL6
	route -n get -${inet} ${${host}_${dir}_${ipv}} |\
	    grep -q 'flags: .*REJECT'  # ${host}_${dir}_${ipv}
.endfor
.endfor

check-setup-ips:
	@echo '\n======== $@ ========'
.for ping inet ipv in ping inet IPV4 ping6 inet6 IPV6
.for host dir in IPS IN IPS OUT IPS TRANSP IPS TUNNEL4 IPS TUNNEL6
	ssh ${IPS_SSH} ${ping} -n -c 1 ${${host}_${dir}_${ipv}} \
	    # ${host}_${dir}_${ipv}
	ssh ${IPS_SSH} route -n get -${inet} ${${host}_${dir}_${ipv}} |\
	    grep -q 'flags: .*LOCAL'  # ${host}_${dir}_${ipv}
.endfor
	ssh ${IPS_SSH} ${ping} -n -c 1 ${RT_IN_${ipv}}  # RT_IN_${ipv}
.for host dir in RT OUT ECO IN ECO TUNNEL4 ECO TUNNEL6
	ssh ${IPS_SSH} route -n get -${inet} ${${host}_${dir}_${ipv}} |\
	    fgrep -q 'gateway: ${RT_IN_${ipv}}' \
	    # ${host}_${dir}_${ipv} RT_IN_${ipv}
.endfor
#.for host dir in SRC TUNNEL4 SRC TUNNEL6 SRC TUNNEL4 SRC TUNNEL6
#	ssh ${IPS_SSH} route -n get -${inet} ${${host}_${dir}_${ipv}} |\
#	    grep -q 'flags: .*REJECT'  # ${host}_${dir}_${ipv}
#.endfor
.endfor

.include <bsd.regress.mk>
