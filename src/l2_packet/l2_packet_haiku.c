/*
 * WPA Supplicant - Layer2 packet handling for Haiku
 * Copyright (c) 2010, Axel Dörfler, axeld@pinc-software.de.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 *
 * This file can be used as a starting point for layer2 packet implementation.
 */

#include "includes.h"

#include "common.h"
#include "eloop.h"
#include "l2_packet.h"

#include <net/ethernet.h>
#include <net/if_dl.h>
#include <sys/sockio.h>


struct l2_packet_data {
	char ifname[IF_NAMESIZE];
	union {
		struct sockaddr_dl link_address;
		struct sockaddr_storage link_storage;
	};
	void (*rx_callback)(void *ctx, const u8 *src_addr,
			    const u8 *buf, size_t len);
	void *rx_callback_ctx;
	int l2_hdr; /* whether to include layer 2 (Ethernet) header data
		     * buffers */
	int rx_fd;
	int tx_fd;
};


int l2_packet_get_own_addr(struct l2_packet_data *l2, u8 *addr)
{
	os_memcpy(addr, LLADDR(&l2->link_address), ETH_ALEN);
	return 0;
}


#if 0
static void
dump_block(const u8* buffer, int size, const char* prefix)
{
	const int DUMPED_BLOCK_SIZE = 16;
	int i;

	for (i = 0; i < size;) {
		int start = i;

		printf("%s%04x ", prefix, i);
		for (; i < start + DUMPED_BLOCK_SIZE; i++) {
			if (!(i % 4))
				printf(" ");

			if (i >= size)
				printf("  ");
			else
				printf("%02x", *(unsigned char*)(buffer + i));
		}
		printf("  ");

		for (i = start; i < start + DUMPED_BLOCK_SIZE; i++) {
			if (i < size) {
				char c = buffer[i];

				if (c < 30)
					printf(".");
				else
					printf("%c", c);
			} else
				break;
		}
		printf("\n");
	}
}
#endif


int l2_packet_send(struct l2_packet_data *l2, const u8 *dst_addr, u16 proto,
		   const u8 *buf, size_t len)
{
	int result = -1;
	struct sockaddr_dl to;

	if (l2 == NULL)
		return -1;

	if (l2->l2_hdr) {
		int result = send(l2->tx_fd, buf, len, 0);
		if (result < 0)
			printf("l2_packet_send failed to send: %s", strerror(errno));
		return result;
	}

	memset(&to, 0, sizeof(struct sockaddr_dl));
	to.sdl_len = sizeof(struct sockaddr_dl);
	to.sdl_family = AF_LINK;
	to.sdl_e_type = htons(proto);
	to.sdl_alen = ETHER_ADDR_LEN;
	memcpy(LLADDR(&to), dst_addr, ETHER_ADDR_LEN);

	result = sendto(l2->tx_fd, buf, len, 0, (struct sockaddr*)&to,
		sizeof(struct sockaddr_dl));
	if (result < 0)
		printf("l2_packet_send failed to send: %s", strerror(errno));

	return result;
}


static void l2_packet_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct l2_packet_data *l2 = eloop_ctx;
	struct sockaddr_dl from;
	socklen_t fromLength = sizeof(struct sockaddr_dl);
	ssize_t bytesReceived;
	u8 buffer[2300];

	bytesReceived = recvfrom(l2->rx_fd, buffer, sizeof(buffer), MSG_TRUNC,
				 (struct sockaddr*)&from, &fromLength);

	if (bytesReceived <= 0)
		return;

	l2->rx_callback(l2->rx_callback_ctx, LLADDR(&from), buffer, bytesReceived);
}


struct l2_packet_data * l2_packet_init(
	const char *ifname, const u8 *own_addr, unsigned short protocol,
	void (*rx_callback)(void *ctx, const u8 *src_addr,
			    const u8 *buf, size_t len),
	void *rx_callback_ctx, int l2_hdr)
{
	struct l2_packet_data *l2;
	struct ifreq request;

	/* check if the interface exists */
	if (if_nametoindex(ifname) == 0)
		return NULL;

	l2 = os_zalloc(sizeof(struct l2_packet_data));
	if (l2 == NULL)
		return NULL;
	os_strlcpy(l2->ifname, ifname, sizeof(l2->ifname));
	l2->rx_callback = rx_callback;
	l2->rx_callback_ctx = rx_callback_ctx;
	l2->l2_hdr = l2_hdr;

	/* open connection for sending and receiving frames */
	l2->tx_fd = socket(AF_LINK, SOCK_DGRAM, 0);
	if (l2->tx_fd < 0)
		goto err1;

	/* retrieve link address */
	strlcpy(request.ifr_name, ifname, IF_NAMESIZE);
	if (ioctl(l2->tx_fd, SIOCGIFADDR, &request, sizeof(struct ifreq)) < 0)
		goto err2;

	memcpy(&l2->link_address, &request.ifr_addr, request.ifr_addr.sa_len);

	if (l2_hdr) {
		/* we need to preserve the L2 header - this is only
		   possible by using a dedicated socket.
		 */

		/* open connection for monitoring frames */
		l2->rx_fd = socket(AF_LINK, SOCK_DGRAM, 0);
		if (l2->rx_fd < 0)
			goto err2;

		/* start monitoring */
		if (ioctl(l2->rx_fd, SIOCSPACKETCAP, &request,
			  sizeof(struct ifreq)) < 0)
			goto err2;
	} else {
		/* bind to protocol */
		l2->link_address.sdl_e_type = htons(protocol);

		if (bind(l2->tx_fd, (struct sockaddr *)&l2->link_address,
				((struct sockaddr *)&l2->link_address)->sa_len) < 0)
			goto err2;

		/* we can use the same socket to receive our packets */
		l2->rx_fd = l2->tx_fd;
	}

	eloop_register_read_sock(l2->rx_fd, l2_packet_receive, l2, NULL);

	return l2;

err2:
	close(l2->tx_fd);
err1:
	os_free(l2);
	return NULL;
}


struct l2_packet_data * l2_packet_init_bridge(
       const char *br_ifname, const char *ifname, const u8 *own_addr,
       unsigned short protocol,
       void (*rx_callback)(void *ctx, const u8 *src_addr,
                           const u8 *buf, size_t len),
       void *rx_callback_ctx, int l2_hdr)
{
       return l2_packet_init(br_ifname, own_addr, protocol, rx_callback,
                             rx_callback_ctx, l2_hdr);
}


void l2_packet_deinit(struct l2_packet_data *l2)
{
	if (l2 == NULL)
		return;

	if (l2->rx_fd >= 0) {
		eloop_unregister_read_sock(l2->rx_fd);

		close(l2->rx_fd);
		if (l2->rx_fd != l2->tx_fd) {
			/* we aren't bound to the protocol and use two different sockets
				for sending and receiving */
			close(l2->rx_fd);
		}
	}

	os_free(l2);
}


int l2_packet_get_ip_addr(struct l2_packet_data *l2, char *buf, size_t len)
{
	/* TODO: get interface IP address */
	return -1;
}


void l2_packet_notify_auth_start(struct l2_packet_data *l2)
{
	/* This function can be left empty */
}
