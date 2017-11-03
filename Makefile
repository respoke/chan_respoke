# Respoke - Web communications made easy
#
# Copyright (C) 2014, D.C.S. LLC
#
# See https://www.respoke.io for more information about
# Respoke. Please do not directly contact any of the
# maintainers of this project for assistance.
# Respoke offers a community forum to submit and discuss
# issues at http://community.respoke.io; please raise any
# issues there.
#
# See http://www.asterisk.org for more information about
# the Asterisk project. Please do not directly contact
# any of the maintainers of this project for assistance;
# the project provides a web site, mailing lists and IRC
# channels for your use.
#
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the LICENSE file
# at the top of the source tree.

# Respoke Modules for Asterisk (An open source telephony toolkit).
#
# Top level Makefile

CC=gcc

ifeq ($(AST_INSTALL_DIR),)
    AST_EXECS_DIR=/usr
else
    AST_EXECS_DIR=$(AST_INSTALL_DIR)
endif

AST_VERSION=$(shell build_tools/get_asterisk_version $(AST_EXECS_DIR))
AST_MODULES_DIR=$(AST_EXECS_DIR)/lib/asterisk/modules
AST_INCLUDE_DIR=$(AST_EXECS_DIR)/include/asterisk
AST_CONF_DIR=$(AST_INSTALL_DIR)/etc/asterisk
AST_SOUNDS_DIR=$(AST_INSTALL_DIR)/var/lib/asterisk/sounds

# if asterisk is not installed at location don't proceed
$(if $(wildcard $(AST_INCLUDE_DIR)),, \
	$(error "Asterisk installation not found under $(AST_EXECS_DIR)"))

# res_respoke
RES_RESPOKE_DIR=res/res_respoke
RES_RESPOKE_TARGET=res/res_respoke.so
RES_RESPOKE_SRC=$(RES_RESPOKE_TARGET:.so=.c)
RES_RESPOKE_SRCS=$(wildcard $(RES_RESPOKE_DIR)/*.c) res/res_respoke/respoke_version.c
RES_RESPOKE_OBJS=$(RES_RESPOKE_SRCS:.c=.o) $(RES_RESPOKE_TARGET:.so=.o)

# test modules
TEST_DIRS=tests/
TEST_SRCS=$(wildcard $(addsuffix *.c,$(TEST_DIRS)))
TEST_TARGETS=$(TEST_SRCS:.c=.so)

# the rest of the modules
EXCLUDE_DIRS=build_tools/ include/ tests/
SUB_DIRS=$(filter-out $(EXCLUDE_DIRS),$(wildcard */))
MOD_SRCS=$(filter-out $(RES_RESPOKE_SRC),$(wildcard $(addsuffix *.c,$(SUB_DIRS))))
MOD_TARGETS=$(MOD_SRCS:.c=.so)

# build/link flags
INCLUDES=-I$(AST_EXECS_DIR)/include -Iinclude -I$(RES_RESPOKE_DIR)/include
CFLAGS=-fPIC -g -Wall -Werror -D_REENTRANT $(INCLUDES)
LDFLAGS=-shared -Wl,--version-script,$(subst .so,.exports,$@)

# module link rule
define mod.link
	build_tools/make_linker_version_script $(basename $@)
	$(LINK.o) $(MAKE_DEPS) $^ -o $@ \
	$(addprefix -l,$(shell build_tools/get_mod_deps $(@:.so=.c)))
endef

all: $(RES_RESPOKE_TARGET) $(MOD_TARGETS)

%.o: %.c
	$(COMPILE.c) $(MODULE_CFLAGS) $< -o $@

$(RES_RESPOKE_TARGET): MODULE_CFLAGS = -DAST_VERSION_MAJOR=$(AST_VERSION) -DAST_MODULE=\"res_respoke\" -DAST_MODULE_SELF_SYM=__internal_res_respoke_self
$(RES_RESPOKE_TARGET): $(RES_RESPOKE_OBJS)
	$(mod.link)

$(MOD_TARGETS): MODULE_CFLAGS = -DAST_VERSION_MAJOR=$(AST_VERSION) -DAST_MODULE=\"$(notdir $(basename $@))\" -DAST_MODULE_SELF_SYM=__internal_$(notdir $(basename $@))_self
$(MOD_TARGETS): %.so: %.o
	$(mod.link)

$(TEST_TARGETS): %.so: %.o
	$(mod.link)

debug: CFLAGS+=-g3 -DDEBUG
debug: all

tests: CFLAGS+=-DTEST_FRAMEWORK
tests: debug $(TEST_TARGETS)

install-keys:
	openssl genrsa -out /tmp/respoke.key
	openssl req -new -key /tmp/respoke.key -out /tmp/respoke.csr -subj "/CN=Respoke"
	openssl x509 -req -days 3650 -in /tmp/respoke.csr -signkey /tmp/respoke.key -out /tmp/respoke.crt
	cat /tmp/respoke.key /tmp/respoke.crt > /tmp/respoke.pem
	install -m 755 -d $(AST_CONF_DIR)/keys
	install -m 644 /tmp/respoke.pem $(AST_CONF_DIR)/keys/
	rm -f /tmp/respoke.{key,csr,crt,pem}

uninstall-keys:
	rm -f $(AST_CONF_DIR)/keys/respoke.pem

install-example: install-keys
	install -m 644 example/*.conf $(AST_CONF_DIR)
	sed "s#/etc/asterisk#$(AST_CONF_DIR)#" example/respoke.conf > $(AST_CONF_DIR)/respoke.conf
	install -m 644 example/sounds/respoke* $(AST_SOUNDS_DIR)

uninstall-example:
	$(RM) $(AST_CONF_DIR)/respoke.conf
	$(RM) $(AST_CONF_DIR)/extensions.conf
	$(RM) $(AST_SOUNDS_DIR)/respoke*
	$(RM) -r $(AST_CONF_DIR)/rma_example_keys

clean:
	find . -type f -name "*.exports" -delete
	find . -type f -name "*.o" -delete
	find . -type f -name "*.so" -delete

distclean: clean
	rm -f .version
	rm -f res/res_respoke/respoke_version.c
	rm -f chan_respoke*.tar.gz

install: all
	install -m 644 include/asterisk/*.h $(AST_INCLUDE_DIR)
	find . -type f -name "*.so" -exec install -m 755 {} $(AST_MODULES_DIR) \;

uninstall:
	$(RM) $(AST_INCLUDE_DIR)/*socket_io*.h
	$(RM) $(AST_INCLUDE_DIR)/*respoke*.h
	$(RM) $(AST_MODULES_DIR)/*socket_io*.so
	$(RM) $(AST_MODULES_DIR)/*respoke*.so

dist: .version
	build_tools/make_dist

.version:
	@build_tools/make_version

res/res_respoke/respoke_version.c: .version
	build_tools/make_version_c > $@

.PHONY: all clean install uninstall debug tests install-example \
	uninstall-example install-keys uninstall-keys .version dist distclean
