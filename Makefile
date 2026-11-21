CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections
LDFLAGS ?= -Wl,--gc-sections
MBEDTLS_DIR ?= /usr
MBEDTLS_LIBS ?= $(MBEDTLS_DIR)/lib/libmbedtls.a $(MBEDTLS_DIR)/lib/libmbedx509.a $(MBEDTLS_DIR)/lib/libmbedcrypto.a $(MBEDTLS_DIR)/lib/libeverest.a $(MBEDTLS_DIR)/lib/libp256m.a
LDLIBS ?= $(MBEDTLS_LIBS) -lm
PREFIX ?= /usr/local

SRCS = src/main.c src/util.c src/json.c src/http.c src/store.c src/policy.c src/oauth.c src/daemon.c src/quota.c src/atop.c
HDRS = $(wildcard src/*.h)
OBJS = $(SRCS:.c=.o)

all: auth-router

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -Isrc -I$(MBEDTLS_DIR)/include -c $< -o $@

auth-router: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

install: auth-router
	mkdir -p $(PREFIX)/bin
	install -m 755 auth-router $(PREFIX)/bin/auth-router
	ln -sf auth-router $(PREFIX)/bin/crest-auth
	ln -sf auth-router $(PREFIX)/bin/atop

clean:
	rm -f auth-router $(OBJS)

.PHONY: all install clean
