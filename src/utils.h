#include <ctype.h> // tolower
#include <stdint.h> // uintX_t
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

enum {
        L_ERR,
        L_WARN,
        L_INFO,
        L_DEBUG
};


void log_level(int);
void use_syslog(int option, int facility);
int syslog_facility(const char *s);

void logmsg(int level, const char *format, ...) 
        __attribute__ ((format (printf, 2, 3)));

#define log_err(format, ...) logmsg(L_ERR, format, ## __VA_ARGS__)
#define log_warn(format, ...) logmsg(L_WARN, format, ## __VA_ARGS__)
#define log_info(format, ...) logmsg(L_INFO, format, ## __VA_ARGS__)
#define log_debug(format, ...) logmsg(L_DEBUG, format, ## __VA_ARGS__)

void errexit(const char *format, ...)
        __attribute__ ((format (printf, 1, 2), noreturn));

void syserr(const char *format, ...);

void daemonize(void);

void print_hex_dump(const void *bufptr, int length);

size_t read_all(const char *filename, void **ptr);
size_t fread_all(FILE* f, void **ptr);

#define min(a, b) ({                            \
                        typeof(a) _a = (a);     \
                        typeof(b) _b = (b);     \
                        _a < _b ? _a : _b;      \
                })


#define array_size(a) (sizeof(a)/sizeof(*a))


struct rxc;

struct rxc *rxc_make(const char *pattern);
int rxc_match(struct rxc *rxc, const char *string);
char *rxc_capture(struct rxc *rxc, int n, char *buf, size_t bufsize);




void putsn(const uint8_t *s, size_t ln);

#define zs(p, l) ({                                     \
                        char *_zs_ptr_ = alloca(l+1);   \
                        memcpy(_zs_ptr_, p, l);         \
                        _zs_ptr_[l] = 0;                \
                        _zs_ptr_;                       \
                })


char * ip_to_s(uint32_t ip, char *s);
#define ip_to_sa(ip) ip_to_s(ip, alloca(16))


int string_to_integer(const char *s, int min, int max, int *result);

struct sockaddr_in;

int parse_sockaddr(const char *s, struct sockaddr_in *sin);

//
// lenval
//
struct lenval {
        size_t len;
        const void *val;
};

typedef struct lenval lenval_t;

#define lvzs(lv)  ({(lv.val && lv.len) ? zs(lv.val, lv.len) : "";})
#define lvpzs(lvp)  ({(lvp->val && lvp->len) ? zs(lvp->val, lvp->len) : "";})




static
inline
void
memcpy_tolower(char *dst, const char *src, size_t len)
{
        for (size_t i = 0; i < len; i++)
                dst[i] = tolower(src[i]);
}


static
inline
int 
lenval_compare(const lenval_t *lv1, const lenval_t *lv2)
{
        int equal = lv1->len == lv2->len && !memcmp(lv1->val, lv2->val, lv1->len);
        return !equal;
}


static
inline
lenval_t *
lenval_dup(lenval_t *lv)
{
        lenval_t *lvnew = malloc(sizeof(lenval_t));
        lvnew->len = lv->len;
        void *p = malloc(lv->len);
        memcpy(p, lv->val, lv->len);
        lvnew->val = p;
        return lvnew;
}


static
inline
void
lenval_free(lenval_t *lv)
{
        free((void*)lv->val);
        free(lv);
}


/* static */
/* inline */
/* void */
/* lenval_tolower(lenval_t *lv) */
/* { */
/*         memcpy_tolower((char*)lv->val, lv->val, lv->len); */
/* } */

