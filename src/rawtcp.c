#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "utils.h"
#include "rawtcp.h"

/* #define DEBUG */
/* #undef DEBUG */


struct tcp_pseudo_header
{
        uint32_t source;
        uint32_t dest;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
};


static
uint16_t
checksum(void *buf, size_t len)
{
        uint16_t *p = buf;
        uint32_t sum = 0;
        size_t len2 = len / 2;
        
        for (size_t i = 0; i < len2; i++)
                sum += *p++;
        
        if (len & 1)
                sum += *(uint8_t*)p;
        
        sum = (uint16_t)sum + (sum >> 16);
        sum = (uint16_t)sum + (sum >> 16);

        return ~sum;
}


size_t
rawtcp_make(void *buf_,
            size_t bufsize,
            const lenval_t *text,
            const struct sockaddr_in *src,
            const struct sockaddr_in *dst,
            uint32_t seq, uint32_t ack, uint8_t flags)
{

#ifdef DEBUG
        log_debug("rawtcp_send():");
        log_debug("src: %s:%hu (%hu)", ip_to_sa(ntohl(src->sin_addr.s_addr)), ntohs(src->sin_port), src->sin_family);
        log_debug("dst: %s:%hu (%hu)", ip_to_sa(ntohl(dst->sin_addr.s_addr)), ntohs(dst->sin_port), dst->sin_family);
        log_debug("seq: %u ack: %u flags: %u", seq, ack, flags);
#endif
        uint8_t *buf = buf_;

        const size_t hdr_len = sizeof(struct tcphdr) + sizeof(struct iphdr);
        const size_t text_len = text ? text->len : 0;
        const size_t tot_len = hdr_len + text_len;

        if (tot_len > bufsize && tot_len > 65535) {
                log_err("rawtcp_send(): data too big");
                return 0;
        }
        
        if (text)
                memcpy(buf + hdr_len, text->val, text->len);

        struct tcphdr *tcphdr = (void*)(buf + sizeof(struct iphdr));
        
        struct tcp_pseudo_header *phdr = (void*)((uint8_t*)tcphdr - sizeof(struct tcp_pseudo_header));

        memset(phdr, 0, sizeof(struct tcp_pseudo_header) + sizeof(struct tcphdr));
        
        phdr->source = src->sin_addr.s_addr;
        phdr->dest = dst->sin_addr.s_addr;
        phdr->protocol = IPPROTO_TCP;
        phdr->tcp_length = htons(sizeof(struct tcphdr) + text_len);
        
        tcphdr->th_sport = src->sin_port;
        tcphdr->th_dport = dst->sin_port;
        
        tcphdr->th_seq = htonl(seq); 
        tcphdr->th_ack = htonl(ack);

        tcphdr->th_off = sizeof(struct tcphdr) / 4;

        tcphdr->th_flags = flags;
        
        tcphdr->th_sum = checksum(phdr, sizeof(struct tcp_pseudo_header) + sizeof(struct tcphdr) + text_len);
        
        struct iphdr *iphdr = (void*)buf;
        memset(iphdr, 0, sizeof(struct iphdr));
        
        iphdr->ihl = sizeof(struct iphdr) / 4;
        iphdr->version = 4;
        iphdr->tot_len = htons(tot_len);
	iphdr->ttl = 63;
	iphdr->protocol = IPPROTO_TCP;
	iphdr->saddr = src->sin_addr.s_addr;
	iphdr->daddr = dst->sin_addr.s_addr;

        iphdr->check = checksum(iphdr, sizeof(struct iphdr));

#ifdef DEBUG
        log_debug("rawtcp_send: %s:%hu > %s:%hu",
                  ip_to_sa(ntohl(iphdr->saddr)), ntohs(tcphdr->source),
                  ip_to_sa(ntohl(iphdr->daddr)), ntohs(tcphdr->dest));
#endif
        
        return tot_len;
}


void
rawtcp_send(int sock,
            const lenval_t *text,
            const struct sockaddr_in *src,
            const struct sockaddr_in *dst,
            uint32_t seq, uint32_t ack, uint8_t flags)
{
        
        uint8_t buf[IP_MAXPACKET];
        size_t len = rawtcp_make(buf, sizeof(buf),
                                 text,
                                 src, dst,
                                 seq, ack, flags);
        
        if (len == 0)
                errexit("rawtcp_make()");

        if(sendto(sock, buf, len, 0, (struct sockaddr*)dst, sizeof(struct sockaddr_in)) == -1)
                syserr("sendto()");
}


int
rawtcp_open()
{
        int sock;
        if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
                syserr("socket()");

        int one = 1;
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1)
                syserr("setsockopt()");
        
        return sock;
}


#ifdef RAWTCP_MAIN

int
main(int argc, char **argv)
{
        log_level(L_DEBUG);

        struct sockaddr_in src, dst;
        src.sin_port = 0;
        dst.sin_port = 0;
        
        uint8_t flags = 0;
        uint32_t seq = 0, ack = 0;

        int opt;
        while ((opt = getopt(argc, argv, "s:d:f:S:A:")) != -1) {
                int integer;

                switch (opt) {
                        
                case 's':
                        if (parse_sockaddr(optarg, &src) == -1)
                                goto usage;
                        break;
                        
                case 'd':
                        if (parse_sockaddr(optarg, &dst) == -1)
                                goto usage;
                        break;

                case 'f':
                        if (string_to_integer(optarg, 0, 255, &integer) < 0)
                                goto usage;
                        flags = integer;
                        break;
                        
                case 'S':
                        if (string_to_integer(optarg, 0, -1, &integer) < 0)
                                goto usage;
                        seq = integer;
                        break;

                case 'A':
                        if (string_to_integer(optarg, 0, -1, &integer) < 0)
                                goto usage;
                        ack = integer;
                        break;

                default:
                        errexit("Unknown key: %c\n", opt);
                }
        }
        
        if (src.sin_port == 0 || dst.sin_port == 0)
                goto usage;

        printf("sending %s:%hu > %s:%hu seq: %u ack: %u\n",
               ip_to_sa(ntohl(src.sin_addr.s_addr)), ntohs(src.sin_port),
               ip_to_sa(ntohl(dst.sin_addr.s_addr)), ntohs(dst.sin_port),
               seq, ack);
        
        char *s = NULL;
        size_t slen = 0;
        
        for (int i = optind; i < argc; i++) {
                size_t l = strlen(argv[i]);
                s = realloc(s, slen + l + 1);
                memcpy(s + slen, argv[i], l);
                s[slen + l] = ' ';
                slen += l + 1;
        }

        /* if (s == NULL)  */
        /*         goto usage; */

        lenval_t m;
        if (s) {
                s[slen-1] = 0;
                m.val = s;
                m.len = strlen(m.val);
        }

        int sock = rawtcp_open();

        rawtcp_send(sock, s ? &m : NULL, &src, &dst, seq, ack, flags); 

        if (close(sock) == -1)
                syserr("close()");

        return 0;

 usage:
        fprintf(stderr, "Usage: -s A.B.C.D:N -d A.B.C.D:N\n");
        return -1;
}

#endif
