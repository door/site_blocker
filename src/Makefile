.PHONY: default

BINPATH = /usr/local/sbin

CC = gcc

CFLAGS = -pthread
CFLAGS += -std=gnu99
CFLAGS += -g -O0
CFLAGS += -W -Wall -Wextra -Werror 

LDFLAGS = -lnetfilter_queue -lpthread -g

PROG = site_blocker

TOMMYDIR = tommyds/tommyds
TOMMYOBJ = $(TOMMYDIR)/tommy.o

CFLAGS += -I$(TOMMYDIR)
CFLAGS += -Ihttp-parser

OBJS = site_blocker.o utils.o rawtcp.o http-parser/http_parser.o $(TOMMYOBJ)


build: $(PROG)


install: build
	install $(PROG) $(BINPATH)


-include $(OBJS:.o=.d)


%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@
	@$(CC) -MM $(CFLAGS) $*.c > $*.d


$(PROG): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)


run: build
	sudo -u root $(CURDIR)/$(PROG) -u ../etc/urls.txt -r http://google.com/


clean:
	@rm -fv $(PROG) $(OBJS) *.o *~ core *.d
	@rm -fv cscope.out


# test prog
rawtcp: rawtcp_main.o utils.o
	gcc -o $@ $^


rawtcp_main.o: rawtcp.c
	$(CC) -c $(CFLAGS) -DRAWTCP_MAIN $< -o $@
