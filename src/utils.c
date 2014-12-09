#define _GNU_SOURCE   /* errno.h: program_invocation_short_name */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <regex.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "utils.h"


static
int
map_level_priority(int level)
{
        switch (level) {
        case L_ERR:
                return LOG_ERR;
        case L_WARN:
                return LOG_WARNING;
        case L_INFO:
                return LOG_INFO;
        case L_DEBUG:
                return LOG_DEBUG;
        default:
                return LOG_NOTICE;
        }
}


struct rxc {
        // const char *pattern;
        regex_t rx;
        size_t pmatch_size;
        regmatch_t *pmatch;
        const char *string;
};


static int i_log_level = L_INFO;
static int i_use_syslog = 0;


void
log_level(int ll)
{
        i_log_level = ll;
}


void
use_syslog(int option, int facility)
{
        if (option == -1)
                option = LOG_PID;

        if (facility == -1)
                facility = LOG_DAEMON;

        openlog(program_invocation_short_name, option, facility);

        i_use_syslog = 1;
}


int
syslog_facility(const char *s)
{
#define SF(name, result) if (strcmp(s, name) == 0) return result;
        SF("kern",     LOG_KERN);
        SF("user",     LOG_USER);
        SF("mail",     LOG_MAIL);
        SF("daemon",   LOG_DAEMON);
        SF("auth",     LOG_AUTH);
        SF("syslog",   LOG_SYSLOG);
        SF("lpr",      LOG_LPR);
        SF("news",     LOG_NEWS);
        SF("uucp",     LOG_UUCP);
        SF("cron",     LOG_CRON);
        SF("authpriv", LOG_AUTHPRIV);
        SF("ftp",      LOG_FTP);
        SF("local0",   LOG_LOCAL0);
        SF("local1",   LOG_LOCAL1);
        SF("local2",   LOG_LOCAL2);
        SF("local3",   LOG_LOCAL3);
        SF("local4",   LOG_LOCAL4);
        SF("local5",   LOG_LOCAL5);
        SF("local6",   LOG_LOCAL6);
        SF("local7",   LOG_LOCAL7);
        return -1;
}


void
vlogmsg(int level, const char *format, va_list ap)
{
        if (level > i_log_level)
                return;
        
        if (i_use_syslog) {
                vsyslog(map_level_priority(level), format, ap);
        } else {
                vfprintf(stderr, format, ap);
                fprintf(stderr, "\n");
        }
}



void
logmsg(int level, const char *format, ...)
{
        if (level > i_log_level)
                return;

        va_list ap;
        va_start(ap, format);
        vlogmsg(level, format, ap);
        va_end(ap);
}


void
errexit(const char *format, ...)
{
        va_list ap;
        va_start(ap, format);
        vlogmsg(L_ERR, format, ap);
        exit(EXIT_FAILURE);
}


void
syserr(const char *format, ...)
{
        char errbuf[1024];
        char *errstr = strerror_r(errno, errbuf, sizeof(errbuf)); // _GNU_SOURCE variant
        va_list ap;
        va_start(ap, format);
        char msgbuf[2048];
        vsnprintf(msgbuf, sizeof(msgbuf), format, ap);
        errexit("%s: %s", msgbuf, errstr);
}


void
print_hex_dump(const void *bufptr, int length)
{
        const uint8_t *buf = bufptr;

        if (length < 1)
                return;

        int lines = (length - 1) / 16 + 1;

        for (int l = 0; l < lines; l++) {
                for (int k = 0; k < 16; k++) {
                        if (k == 8)
                                printf(" ");
                        int i = l * 16 + k;
                        if (i < length)
                                printf("%02x ", buf[i]);
                        else
                                printf("   ");
                }

                printf("\t");

                for (int k = 0; k < 16; k++) {
                        int i = l * 16 + k;
                        if (i == length)
                                break;
                        if (0x20 <= buf[i] && buf[i] <= 0x7e)
                                printf("%c", buf[i]);
                        else
                                printf(".");
                }

                printf("\n");
        }
}


void
putsn(const uint8_t *s, size_t ln)
{
        for (size_t i = 0; i < ln && s[i]; i++)
                putchar(s[i]);
        printf("\n");
}


char *
strtoup(char *str)
{
        for (; *str; str++) {
                char u = toupper(*str);
                if (u != *str)
                        *str = u;
        }
        return str;
}


struct rxc *
rxc_make(const char *pattern)
{
        struct rxc *rxc = calloc(1, sizeof(struct rxc));
        // rxc->pattern = strdup(pattern);

        int rc = regcomp(&rxc->rx, pattern, REG_EXTENDED|REG_ICASE);
        if (rc) {
                char errbuf[1024];
                regerror(rc, &rxc->rx, errbuf, sizeof(errbuf));
                errexit("regcomp(%s): %s", pattern, errbuf);
        }

        rxc->pmatch_size = rxc->rx.re_nsub + 1;
        rxc->pmatch = malloc(rxc->pmatch_size * sizeof(regmatch_t));

        return rxc;
}


int
rxc_match(struct rxc *rxc, const char *string)
{
        rxc->string = string;
        return regexec(&rxc->rx, string, rxc->pmatch_size, rxc->pmatch, 0);
}


char *
rxc_capture(struct rxc *rxc, int n, char *buf, size_t bufsize)
{
        regmatch_t *m = rxc->pmatch + n;
        size_t ln = m->rm_eo - m->rm_so;
        if (bufsize < ln+1)
                return NULL;
        memcpy(buf, rxc->string + m->rm_so, ln);
        buf[ln] = 0;
        return buf;
}


size_t
fread_all(FILE* f, void **ptr)
{
        char buf[20480];
        char *result_buffer = NULL;
        size_t l, size = 0;

        while ((l = fread(buf, 1, sizeof(buf), f)) > 0) {
                size_t newsize = size + l;
                result_buffer = realloc(result_buffer, newsize);
                memcpy(result_buffer+size, buf, l);
                size = newsize;
        }

        *ptr = result_buffer;

        return size;
}


size_t
read_all(const char *filename, void **ptr)
{
        FILE *f = fopen(filename, "r");
        if (f == NULL)
                return 0;
        *ptr = NULL;
        size_t len = fread_all(f, ptr);
        fclose(f);
        return len;
}


char *
ip_to_s(uint32_t ip, char *s)
{
        uint8_t *p = (uint8_t*)(&ip);
        sprintf(s, "%d.%d.%d.%d", p[3], p[2], p[1], p[0]);
        return s;
}


int
string_to_integer(const char *s, int min, int max, int *result)
{
        char *endptr;

        long val = strtoul(s, &endptr, 10);

        if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || (errno != 0 && val == 0))
                return -1;

        if (endptr == s)
                return -2;

        if (max >= min && (val < min || val > max)) {
                log_debug("%ld < %d || %ld > %d (%d >= %d)\n", val, min, val, max, max, min);
                return -3;
        }

        *result = val;

        return 0;
}


int
parse_sockaddr(const char *s, struct sockaddr_in *sin)
{
        const char *p = strchr(s, ':');
        if (p == NULL)
                goto badaddr;

        size_t ln = p - s;
        char *ip = alloca(ln + 1);
        memcpy(ip, s, ln);
        ip[ln] = 0;
        
        struct in_addr in_addr;
        if (inet_pton(AF_INET, ip, &in_addr) != 1)
                goto badaddr;
        
        sin->sin_addr = in_addr;

        int port;
        if (string_to_integer(s + ln + 1, 0, 65535, &port) < 0)
                goto badaddr;
        sin->sin_port = htons(port);
        
        sin->sin_family = AF_INET;
        
        return 0;

 badaddr:
        fprintf(stderr, "Invalid sockaddr '%s'\n", s);
        return -1;
}


// (c) Devin Watson, Linux Daemon Writing HOWTO
void
daemonize(void)
{
        pid_t pid;

        /* already a daemon */
        if(1 == getppid())
                return;

        /* Fork off the parent process */
        pid = fork();
        if(-1 == pid)
                syserr("fork()");

        /* If we got a good PID, then we can exit the parent process. */
        if(pid > 0)
                exit(EXIT_SUCCESS);

        /* At this point we are executing as the child process */

        /* Change the file mode mask */
        umask(022);

        /* Create a new SID for the child process */
        if(-1 == setsid())
                syserr("setsid()");

        /* Change the current working directory.  This prevents the current
           directory from being locked; hence not being able to remove it. */
        if((chdir("/")) < 0)
                syserr("chdir()");

        /* Redirect standard files to /dev/null */
        freopen("/dev/null", "r", stdin);
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);
}

