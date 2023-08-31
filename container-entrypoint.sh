#!/bin/sh
# SPDX-License-Identifier: GPL2-or-later
#
# Copyright (C) 2023 Olliver Schinagl <oliver@schinagl.nl>
#
# A beginning user should be able to docker run image bash (or sh) without
# needing to learn about --entrypoint
# https://github.com/docker-library/official-images#consistency

set -eu

bin='sslh'

# run command if it is not starting with a "-" and is an executable in PATH
if [ "${#}" -le 0 ] || \
   [ "${1#-}" != "${1}" ] || \
   [ -d "${1}" ] || \
   ! command -v "${1}" > '/dev/null' 2>&1; then
	entrypoint='true'
fi

unconfigure_iptables() { 
	echo "Received SIG TERM/INT/KILL. Removing iptables / routing changes"

	set +e # Don't exit if got error
	set -x

	iptables -t raw -D PREROUTING ! -i lo -d 127.0.0.0/8 -j DROP
	iptables -t mangle -D POSTROUTING ! -o lo -s 127.0.0.0/8 -j DROP

	iptables -t nat -D OUTPUT -m owner --uid-owner sslh -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j CONNMARK --set-xmark 0x01/0x0f
	iptables -t mangle -D OUTPUT ! -o lo -p tcp -m connmark --mark 0x01/0x0f -j CONNMARK --restore-mark --mask 0x0f

	ip rule del fwmark 0x1 lookup 100
	ip route del local 0.0.0.0/0 dev lo table 100


	if [ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6) -eq 0 ]; then
		ip6tables -t raw -D PREROUTING ! -i lo -d ::1/128 -j DROP
		ip6tables -t mangle -D POSTROUTING ! -o lo -s ::1/128 -j DROP
		ip6tables -t nat -D OUTPUT -m owner --uid-owner sslh -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j CONNMARK --set-xmark 0x01/0x0f
		ip6tables -t mangle -D OUTPUT ! -o lo -p tcp -m connmark --mark 0x01/0x0f -j CONNMARK --restore-mark --mask 0x0f

		ip -6 rule del fwmark 0x1 lookup 100
		ip -6 route del local ::/0 dev lo table 100
	fi
		
	set -e
	set +x
}

configure_iptables() {
	echo "Configuring iptables and routing..."

	set +e # Don't exit if got error
	set -x
	
	iptables -t raw -A PREROUTING ! -i lo -d 127.0.0.0/8 -j DROP
	iptables -t mangle -A POSTROUTING ! -o lo -s 127.0.0.0/8 -j DROP

	iptables -t nat -A OUTPUT -m owner --uid-owner sslh -p tcp --tcp-flags FIN,SYN,RST,ACK SYN  -j CONNMARK --set-xmark 0x01/0x0f
	iptables -t mangle -A OUTPUT ! -o lo -p tcp -m connmark --mark 0x01/0x0f -j CONNMARK --restore-mark --mask 0x0f

	ip rule add fwmark 0x1 lookup 100
	ip route add local 0.0.0.0/0 dev lo table 100

	if [ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6) -eq 0 ]; then
		ip6tables -t raw -A PREROUTING ! -i lo -d ::1/128 -j DROP
		ip6tables -t mangle -A POSTROUTING ! -o lo -s ::1/128 -j DROP
		ip6tables -t nat -A OUTPUT -m owner --uid-owner sslh -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j CONNMARK --set-xmark 0x01/0x0f
		ip6tables -t mangle -A OUTPUT ! -o lo -p tcp -m connmark --mark 0x01/0x0f -j CONNMARK --restore-mark --mask 0x0f

		ip -6 rule add fwmark 0x1 lookup 100
		ip -6 route add local ::/0 dev lo table 100
	fi
	
	set -e
	set +x
}

for _args in "${@}" ; do
	if [ "${_args:-}" = '--transparent' ] ; then
		echo '--transparent flag is set'
		configure_iptables
		trap unconfigure_iptables TERM INT KILL
		break
	fi
done

# Drop privileges and run as sslh user
sslh_cmd="${entrypoint:+${bin}} ${@}"
echo "Executing with user 'sslh': ${sslh_cmd}"

exec su - sslh -c "${sslh_cmd}" &
wait "${!}"

exit 0
