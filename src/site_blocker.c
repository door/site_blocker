/*
 * Nfq Site Blocker
 */ 


#define _GNU_SOURCE         /* stdio: asprintf */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>

#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <http_parser.h>
#include <tommy.h>

#include "utils.h"
#include "rawtcp.h"


#define HTTP_REDIRECT_FORMAT                            \
        "HTTP/1.1 301 Moved Permanently\r\n"            \
        "Location: %s\r\n"                              \
        "Connection: close\r\n\r\n"

#define DEFAULT_QUEUE 0


struct request {
        lenval_t pkt;
        const struct iphdr *iphdr;
        const struct tcphdr *tcphdr;
        lenval_t l4msg;
        enum http_method method;
        lenval_t host;
        lenval_t path;
        int major, minor;
        char hostbuf[65536];
};


struct lenvalobj {
        tommy_node node;
        lenval_t *lv;
        void *data;
};


struct urls {
        tommy_hashlin *hosts;
};


struct userdata {
        struct urls *urls;
        pthread_rwlock_t urls_lock;
        const char *urls_file;
        int queuenum;
        int sock;
        lenval_t redirect;
        int reload_counter;
};


static
int
lenvalobj_compare(const void* arg, const void* obj)
{
        const lenval_t *lv1 = (const lenval_t *)arg;
        const lenval_t *lv2 = ((const struct lenvalobj*)obj)->lv;
        
        return lenval_compare(lv1, lv2);
}


static
inline
tommy_uint32_t
lenval_hash(const lenval_t *lv)
{
        return tommy_hash_u32(0, lv->val, lv->len);
}


static
inline
void
hashlin_new(tommy_hashlin **hashlin)
{
        *hashlin = calloc(1, sizeof(tommy_hashlin));
        tommy_hashlin_init(*hashlin);
}


static
int
parse_tcpip(struct request *rq)
{
        if (rq->pkt.len < sizeof(struct iphdr))
                return -1;

        rq->iphdr = (void*)(rq->pkt.val);

        if (rq->iphdr->protocol != IPPROTO_TCP)
                return -1;

        const size_t iphlen = rq->iphdr->ihl*4;

        if (rq->pkt.len < iphlen + sizeof(struct tcphdr))
                return -1;
        
        rq->tcphdr = rq->pkt.val + iphlen;
        
        const size_t hdrlen = iphlen + rq->tcphdr->th_off*4;

        if (hdrlen >= rq->pkt.len)
                return -1;

        rq->l4msg.len = rq->pkt.len - hdrlen;
        rq->l4msg.val = rq->pkt.val + hdrlen;

        return 0;
}


static
int
parse_http(struct request *rq)
{
        int host_flag = 0;
        
        rq->host.val = NULL;
        rq->path.val = NULL;

        int on_path(http_parser *parser, const char *p, size_t ln) {
                (void)parser;
                rq->path.val = p;
                rq->path.len = ln;
                return 0;
        }

        int on_header_field(http_parser *parser, const char *p, size_t ln) {
                (void)parser;
                host_flag =
                        (ln == 4) &&
                        (tolower(p[0]) == 'h') &&
                        (tolower(p[1]) == 'o') &&
                        (tolower(p[2]) == 's') &&
                        (tolower(p[3]) == 't');
                return 0;
        }
 
        int on_header_value(http_parser *parser, const char *p, size_t ln) {
                (void)parser;
                if (host_flag) {
                        if (ln > sizeof(rq->hostbuf))
                                return -1;
                        memcpy_tolower(rq->hostbuf, p, ln);
                        rq->host.val = rq->hostbuf;
                        rq->host.len = ln;
                        return 1; // stop
                }
                return 0;
        }

        int on_headers_complete(http_parser *parser) {
                (void)parser;
                return 1; // stop
        }
        
        http_parser_settings settings;
        memset(&settings, 0, sizeof(settings));
        settings.on_url = on_path;
        settings.on_header_field = on_header_field;
        settings.on_header_value = on_header_value;
        settings.on_headers_complete = on_headers_complete;

        http_parser parser;
        memset(&parser, 0, sizeof(parser));
        http_parser_init(&parser, HTTP_REQUEST);
        parser.data = NULL;

        http_parser_execute(&parser, &settings, rq->l4msg.val, rq->l4msg.len);
        
        if (!(rq->path.val && rq->host.val))
                return -1;
        
        rq->major = parser.http_major;
        rq->minor = parser.http_minor;
        rq->method = parser.method;

        return 0;
}


#if 0
static
void
print_pkt(struct request *rq)
{
        const struct iphdr *iphdr = rq->iphdr;
        const struct tcphdr *tcphdr = rq->tcphdr;
        const lenval_t *l4msg = &rq->l4msg;
        const uint32_t ack = ntohl(tcphdr->th_seq) + l4msg->len;
        
        printf("%s:%hu %s:%hu  %c%c%c%c%c%c Seq: %u Ack: %u Win: 0x%x TcpLen: %d  L:%u A:%u\n",
               ip_to_sa(ntohl(iphdr->saddr)), ntohs(tcphdr->th_sport),
               ip_to_sa(ntohl(iphdr->daddr)), ntohs(tcphdr->th_dport),
               (tcphdr->urg ? 'U' : '*'),
               (tcphdr->ack ? 'A' : '*'),
               (tcphdr->psh ? 'P' : '*'),
               (tcphdr->rst ? 'R' : '*'),
               (tcphdr->syn ? 'S' : '*'),
               (tcphdr->fin ? 'F' : '*'),
               ntohl(tcphdr->seq),
               ntohl(tcphdr->ack_seq),
               ntohs(tcphdr->window),
               tcphdr->doff*4,
               l4msg->len,
               ack);
}
#endif


static
int
is_blocked(const struct request *rq, struct urls *urls)
{
        struct lenvalobj *hostobj = tommy_hashlin_search(urls->hosts, lenvalobj_compare, &rq->host, lenval_hash(&rq->host));

        /* site host name not found */
        if (hostobj == NULL)
                return 0;

        /* whole site blocked */
        if (hostobj->data == NULL)
                return 1;

        struct lenvalobj *pathobj = tommy_hashlin_search(hostobj->data, lenvalobj_compare, &rq->path, lenval_hash(&rq->path));
        
        /* the page blocked */
        return pathobj != NULL;
}


static
void
redirect(struct userdata *userdata, const struct request *rq)
{
        struct sockaddr_in src, dst;
        // src == browser
        // dst == web server
        
        src.sin_family = AF_INET;
        src.sin_addr.s_addr = rq->iphdr->saddr;
        src.sin_port = rq->tcphdr->th_sport;

        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = rq->iphdr->daddr;
        dst.sin_port = rq->tcphdr->th_dport;

        uint32_t seq = ntohl(rq->tcphdr->th_seq);
        uint32_t ack = ntohl(rq->tcphdr->th_ack);

#ifdef DEBUG
        printf("%s:%d > %s:%d seq: %u ack: %u\n", 
               ip_to_sa(ntohl(src.sin_addr.s_addr)), ntohs(src.sin_port), 
               ip_to_sa(ntohl(dst.sin_addr.s_addr)), ntohs(dst.sin_port), 
               seq, ack);
#endif        

        rawtcp_send(userdata->sock, &userdata->redirect, &dst, &src, ack, seq + rq->l4msg.len,
                    TH_ACK|TH_FIN|TH_PUSH);

        // +1 для FIN в предыдущем пакете
        rawtcp_send(userdata->sock, NULL, &dst, &src, ack + userdata->redirect.len + 1, 0,
                    TH_FIN|TH_RST);
        
        rawtcp_send(userdata->sock, NULL, &src, &dst, seq, ack, TH_RST);
}


static
int
on_receive(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfq_data, void *userdata_)
{
        (void)nfmsg; // сравнить с рез-том nfq_get_payload
        struct userdata *userdata = userdata_;

	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfq_data);
        
        void verdict (int v) {
                if (nfq_set_verdict(qh, ntohl(ph->packet_id), v, 0, NULL) == -1)
                        syserr("nfq_set_verdict()");
        }
        
	if (ph->hook != NF_IP_PRE_ROUTING)
                goto accept;
        
        struct request rq;
        
        int len = nfq_get_payload(nfq_data, (void*)&rq.pkt.val);
        if (len == -1)
                syserr("nfq_get_payload()");
        rq.pkt.len = len;
        
        if (parse_tcpip(&rq))
                goto accept;
        
        // print_pkt(&rq);

        if (parse_http(&rq)) 
                // Отсутствует Path или Host 
                goto accept;
        
        if (pthread_rwlock_rdlock(&userdata->urls_lock))
                errexit("pthread_rwlock_rdlock()");

        int blocked = is_blocked(&rq, userdata->urls);

        if (pthread_rwlock_unlock(&userdata->urls_lock))
                errexit("pthread_rwlock_unlock()");

        void log_result(int level, const char *action) {
                logmsg(level, "%s %s %s %s%s HTTP/%d.%d",
                       action,
                       ip_to_sa(ntohl(rq.iphdr->saddr)), 
                       http_method_str(rq.method),
                       lvzs(rq.host), lvzs(rq.path),
                       rq.major, rq.minor);
        }

        if (!blocked) {
#ifdef DEBUG
                log_result(L_DEBUG, "passed");
#endif
                goto accept;
        }
        
        log_result(L_INFO, "blocked");

        redirect(userdata, &rq);

        verdict(NF_DROP);
        
        return 0;

 accept:
        verdict(NF_ACCEPT);
        return 0;
}


static
int
add_url(struct urls *urls, const char *s)
{
        while(*s && isspace(*s))
                s++;
        
        if (s[0] == '#')
                return 0;
        
        size_t len = strlen(s);
        while (len > 0 && isspace(s[len-1]))
                len -= 1;
        
        if (len == 0)
                return 0;
        
        lenval_t host, path;

        char *p = memchr(s, '/', len);

        if (p) {
                host.len = p - s;
                host.val = s;

                path.len = len - host.len;
                path.val = p;

        } else {
                host.len = len;
                host.val = s;

                path.len = 0;
                path.val = NULL;
        }

        char buf[65536];
        if (host.len > sizeof(buf)) {
                log_warn("Hostname too long");
                return -1;
        }
        memcpy_tolower(buf, host.val, host.len);
        host.val = buf;

        uint32_t host_hash = lenval_hash(&host); 

        struct lenvalobj *hostobj = tommy_hashlin_search(urls->hosts, lenvalobj_compare, &host, host_hash);
        if (!hostobj) {
                hostobj = calloc(1, sizeof(struct lenvalobj));
                hostobj->lv = lenval_dup(&host);
                tommy_hashlin_insert(urls->hosts, &hostobj->node, hostobj, host_hash);
                if (path.val)
                        hashlin_new((void *)&hostobj->data);
        }
        
        tommy_hashlin *paths = hostobj->data;

        if (path.val)
                if (paths == NULL)
                        log_warn("Adding url with path (%s) when blocking whole domain (%s)", lvzs(path), lvzs(host));
                else {
                        uint32_t path_hash = lenval_hash(&path);
                        struct lenvalobj *pathobj = tommy_hashlin_search(paths, lenvalobj_compare, &path, path_hash);
                        if (pathobj)
                                log_warn("(Duplicated url %s)", s);
                        else {
                                pathobj = calloc(1, sizeof(struct lenvalobj));
                                pathobj->lv = lenval_dup(&path);
                                tommy_hashlin_insert(hostobj->data, &pathobj->node, pathobj, lenval_hash(&path));
                        }
                }
        else
                if (hostobj->data)
                        log_warn("Adding whole domain blocking (%s) when page-wise blocking already present", 
                               lvzs(host));
        
        
        return 0;
}


static
struct urls *
read_urls(const char *filename)
{
        log_debug("Loading urls from %s", filename);
        FILE *f = fopen(filename, "r");
        if (f == NULL) {
                log_err("Cannot open urls file %s", filename);
                return NULL;
        }
        char s[1024];
        struct urls *urls = calloc(1, sizeof(struct urls));
        hashlin_new(&urls->hosts);
        while (fgets(s, sizeof(s), f) != NULL)
                add_url(urls, s);
        fclose(f);
        return urls;
}


static
void
free_urls(struct urls *urls)
{
        void free_host(void *hostobj_) {
                struct lenvalobj *hostobj = hostobj_;
                void free_path(void *pathobj_) {
                        struct lenvalobj *pathobj = pathobj_;
                        lenval_free(pathobj->lv);
                        free(pathobj);
                }
                if (hostobj->data) {
                        tommy_hashlin_foreach(hostobj->data, free_path);
                        tommy_hashlin_done(hostobj->data);
                        free(hostobj->data);
                }
                lenval_free(hostobj->lv);
                free(hostobj);
        }
        tommy_hashlin_foreach(urls->hosts, free_host);
        tommy_hashlin_done(urls->hosts);
        free(urls->hosts);
        free(urls);
}


static
void
print_urls(struct urls *urls)
{
        void dump_host(void *hostobj_) {
                struct lenvalobj *hostobj = hostobj_;
                void dump_path(void *pathobj_) {
                        struct lenvalobj *pathobj = pathobj_;
                        printf("%s%s\n", lvpzs(hostobj->lv), lvpzs(pathobj->lv));
                }
                if (hostobj->data)
                        tommy_hashlin_foreach(hostobj->data, dump_path);
                else
                        printf("%s\n", lvpzs(hostobj->lv));
        }
        tommy_hashlin_foreach(urls->hosts, dump_host);
}


static
void *
filter_thread(void *userdata_)
{
        struct userdata *userdata = userdata_;

        userdata->sock = rawtcp_open();
        
	struct nfq_handle *h;
	if ((h = nfq_open()) == NULL)
                syserr("nfq_open()");

        if (nfq_unbind_pf(h, AF_INET) < 0)
		syserr("nfq_unbind_pf()");

 	if (nfq_bind_pf(h, AF_INET) < 0)
		syserr("nfq_bind_pf()");

        struct nfq_q_handle *qh;
	if ((qh = nfq_create_queue(h, userdata->queuenum, on_receive, userdata)) == NULL)
		syserr("nfq_create_queue()");
        
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
		syserr("nfq_set_mode()");
        
        int fd = nfq_fd(h);

        char buf[2048];
        ssize_t len;
        while ((len = recv(fd, buf, sizeof(buf), 0)) >= 0) {
		nfq_handle_packet(h, buf, len);
	}
        
        return NULL;
}


static
void
msleep(long us)
{
        struct timespec time = {
                .tv_sec = 0,
                .tv_nsec = us * 1000
        };
        nanosleep(&time, NULL);
}


static
void *
reload_thread(void *userdata_)
{
        struct userdata *userdata = userdata_;

        int reload_counter = 0;

        for (;;) {
                while (reload_counter == userdata->reload_counter)
                        msleep(1000); // 1ms
                
                log_debug("Reload urls=%p", userdata->urls);

                struct urls *urls_new = read_urls(userdata->urls_file);
                
                if (pthread_rwlock_wrlock(&userdata->urls_lock))
                        errexit("pthread_rwlock_wrlock()");

                struct urls *urls_old = userdata->urls;
                userdata->urls = urls_new;
                
                if (pthread_rwlock_unlock(&userdata->urls_lock))
                        errexit("pthread_rwlock_unlock()");

                free_urls(urls_old);

                reload_counter = userdata->reload_counter;
        }

        return NULL;
}


int 
main(int argc, char **argv)
{
        (void)argc;
        (void)argv;
        
        log_level(L_DEBUG);
        
        struct userdata userdata = {
                .queuenum = DEFAULT_QUEUE,
                .urls_file = NULL,
                .reload_counter = 0
        };
        
        if (pthread_rwlock_init(&userdata.urls_lock, NULL))
                errexit("pthread_rwlock_init()");
        
        struct stat urls_stat;

        char *redirect_location = NULL;
        int test_urls = 0;
        int foreground = 0;
        int facility = LOG_DAEMON;
        char *pidfile = "/var/run/site_blocker.pid";
        
        int opt;
        while ((opt = getopt(argc, argv, "u:r:n:qtl:fP:")) != -1) { 
                switch (opt) {

                case 'u':
                        if (userdata.urls_file)
                                goto usage;
                        userdata.urls_file = optarg;
                        break;

                case 'r':
                        if (redirect_location)
                                goto usage;
                        redirect_location = optarg;
                        break;

                case 'n':
                        if (string_to_integer(optarg, 0, 65535, &userdata.queuenum))
                                goto usage;
                        break;

                case 'q':
                        log_level(L_INFO);
                        break;

                case 't':
                        test_urls = 1;
                        break;

                case 'f':
                        foreground = 1;
                        break;
                        
                case 'l':
                        facility = syslog_facility(optarg);
                        if (facility == -1)
                                errexit("Invalid syslog facility '%s'", optarg);
                        break;
                        
                case 'P':
                        pidfile = optarg;
                        break;
                        
                default: /* '?' */
                        goto usage;
                }
        }
        
        if (userdata.urls_file == NULL)
                goto usage;
        
        if (!test_urls && redirect_location == NULL)
                goto usage;
        
        if (stat(userdata.urls_file, &urls_stat) == -1)
                syserr("stat(\"%s\")", userdata.urls_file);

        userdata.urls = read_urls(userdata.urls_file);

        if (test_urls) {
                print_urls(userdata.urls);
                goto free;
        }

        if (asprintf((char**)&userdata.redirect.val, HTTP_REDIRECT_FORMAT, redirect_location) == -1)
                errexit("asprintf failed");
        userdata.redirect.len = strlen(userdata.redirect.val);
        
        if (!foreground) {
                daemonize();
                use_syslog(LOG_PID, facility);
                FILE *pid = fopen(pidfile, "w");
                if (pid == NULL)
                        syserr("fopen(\"%s\", \"w\")", pidfile);
                fprintf(pid, "%d\n", getpid());
                fclose(pid);
        }

        void sighup_handler(int signum) {
                (void)signum;
                userdata.reload_counter++;
        }

        signal(SIGHUP, sighup_handler);
        
        pthread_t filter_tid;
        if (pthread_create(&filter_tid, NULL, filter_thread, &userdata))
                syserr("pthread_create()");

        pthread_t reload_tid;
        if (pthread_create(&reload_tid, NULL, reload_thread, &userdata))
                syserr("pthread_create()");
        
        log_info("started.");
        
        for (;;) {
                sleep(1);

                struct stat newstat;
                if (stat(userdata.urls_file, &newstat) == -1)
                        syserr("stat(\"%s\")", userdata.urls_file);

                if (urls_stat.st_ino   == newstat.st_ino  &&
                    urls_stat.st_mtime == newstat.st_mtime)
                        continue;
                
                log_debug("%s changed", userdata.urls_file);

                userdata.reload_counter++;

                urls_stat.st_ino = newstat.st_ino;
                urls_stat.st_mtime = newstat.st_mtime;
        }
        
        pthread_join(filter_tid, NULL);

	/* nfq_destroy_queue(qh); */
	/* nfq_close(h); */

 free:
        free_urls(userdata.urls);
        return 0;

 usage:
        fprintf(stderr, "Usage: %s -u urls_file -r redirect_location [-n QUEUE -q -f -t -l FACILITY]\n", argv[0]);
        exit(EXIT_FAILURE);
}
