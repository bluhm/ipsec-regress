/*	$OpenBSD$	*/
/*
 * Copyright (c) Alexander Bluhm <bluhm@genua.de>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void __dead
usage(void)
{
	fprintf(stderr, "usage: nonxt-send addr\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct addrinfo hints, *res, *res0;
	struct timeval to;
	struct sockaddr_storage ss;
	const char *cause = NULL;
	socklen_t slen;
	int error;
	int save_errno;
	int s, r, u;
	char buf[1024];
	int icmp;

	if (argc != 2)
		usage();

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_NONE;
	error = getaddrinfo(argv[1], NULL, &hints, &res0);
	if (error)
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	s = -1;
	for (res = res0; res; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1) {
			cause = "socket nonxt";
			continue;
		}
		if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "connect nonxt";
			save_errno = errno;
			close(s);
			errno = save_errno;
			s = -1;
			continue;
		}

		/* connect udp socket and bind to local address */
		u = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP);
		if (u == -1)
			err(1, "socket udp");
		memcpy(&ss, res->ai_addr, res->ai_addrlen);
		if (res->ai_family == AF_INET)
			((struct sockaddr_in *)&ss)->sin_port = htons(1);
		if (res->ai_family == AF_INET6)
			((struct sockaddr_in6 *)&ss)->sin6_port = htons(1);
		if (connect(u, (struct sockaddr *)&ss, res->ai_addrlen) == -1)
			err(1, "connect udp");
		slen = sizeof(ss);
		if (getsockname(u, (struct sockaddr *)&ss, &slen) == -1)
			err(1, "getsockname udp");
		if (res->ai_family == AF_INET)
			((struct sockaddr_in *)&ss)->sin_port = htons(0);
		if (res->ai_family == AF_INET6)
			((struct sockaddr_in6 *)&ss)->sin6_port = htons(0);
		if (close(u) == -1)
			err(1, "close udp");

		icmp = res->ai_family == AF_INET ? IPPROTO_ICMP :
		    res->ai_family == AF_INET6 ? IPPROTO_ICMPV6 : 0;
		r = socket(res->ai_family, SOCK_RAW, icmp);
		if (r == -1)
			err(1, "socket icmp");
		if (bind(r, (struct sockaddr *)&ss, slen) == -1)
			err(1, "bind icmp");
		if (connect(r, res->ai_addr, res->ai_addrlen) == -1)
			err(1, "connect icmp");
		break;
	}
	if (s == -1)
		err(1, "%s", cause);
	freeaddrinfo(res0);

	if (send(s, buf, 0, 0) == -1)
		err(1, "send nonxt");
	to.tv_sec = 3;
	to.tv_usec = 0;
	if (setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to)) == -1)
		err(1, "setsockopt icmp");
	if (recv(r, buf, sizeof(buf), 0) == -1)
		err(1, "recv icmp");

	return 0;
}
