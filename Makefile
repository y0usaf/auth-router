CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections
LDFLAGS ?= -Wl,--gc-sections
PSY_DIR ?= ../psy
MBEDTLS_DIR ?= /usr
MBEDTLS_LIBS ?= $(MBEDTLS_DIR)/lib/libmbedtls.a $(MBEDTLS_DIR)/lib/libmbedx509.a $(MBEDTLS_DIR)/lib/libmbedcrypto.a $(MBEDTLS_DIR)/lib/libeverest.a $(MBEDTLS_DIR)/lib/libp256m.a
LDLIBS ?= $(MBEDTLS_LIBS) -lm
PREFIX ?= /usr/local

SRCS = src/main.c src/util.c src/json.c src/http.c src/store.c src/policy.c src/oauth.c src/daemon.c $(PSY_DIR)/psy.c

all: auth-router

src/router_psy_builtin.h: policy/router.psy
	@printf 'static const char router_psy_builtin[] = {\n' > $@
	@od -An -tx1 -v $< | awk '{for(i=1;i<=NF;i++) printf "0x%s,", $$i; printf "\n"}' >> $@
	@printf '0x00};\n' >> $@

auth-router: src/router_psy_builtin.h $(SRCS)
	$(CC) $(CFLAGS) -Isrc -I$(PSY_DIR) -I$(MBEDTLS_DIR)/include $(SRCS) -o $@ $(LDFLAGS) $(LDLIBS)

install: auth-router
	mkdir -p $(PREFIX)/bin $(PREFIX)/share/auth-router
	install -m 755 auth-router $(PREFIX)/bin/auth-router
	install -m 644 policy/router.psy $(PREFIX)/share/auth-router/router.psy

clean:
	rm -f auth-router src/router_psy_builtin.h

.PHONY: all install clean
