# Respoke - Web communications made easy
#
# Copyright (C) 2014, D.C.S. LLC
#
# See https://www.respoke.io for more information about
# Respoke. Please do not directly contact
# any of the maintainers of this project for assistance;
# Respoke offers a community forum to submit and discuss
# issues at http://community.respoke.io; please raise any
# issues there, using the tag chan_respoke
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
    AST_INSTALL_DIR=/usr
endif

AST_VERSION=13
AST_MODULES_DIR=$(AST_INSTALL_DIR)/lib/asterisk/modules
AST_INCLUDE_DIR=$(AST_INSTALL_DIR)/include/asterisk

# if asterisk is not installed at location don't proceed
$(if $(wildcard $(AST_INCLUDE_DIR)),, \
	$(error "Asterisk installation not found under $(AST_INSTALL_DIR)"))

# only build against certain asterisk versions
$(if $(shell build_tools/get_asterisk_version $(AST_INSTALL_DIR) $(AST_VERSION)), \
	$(error "Asterisk version must be >= $(AST_VERSION) to build against"))

# res_respoke
RES_RESPOKE_DIR=res/res_respoke
RES_RESPOKE_TARGET=res/res_respoke.so
RES_RESPOKE_SRC=$(RES_RESPOKE_TARGET:.so=.c)
RES_RESPOKE_SRCS=$(wildcard $(RES_RESPOKE_DIR)/*.c)
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
INCLUDES=-I$(AST_INSTALL_DIR)/include -Iinclude -I$(RES_RESPOKE_DIR)/include
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
	$(COMPILE.c) -DAST_MODULE=\"$(notdir $(basename $@))\" $< -o $@

$(RES_RESPOKE_TARGET): $(RES_RESPOKE_OBJS)
	$(mod.link)

$(MOD_TARGETS): %.so: %.o
	$(mod.link)

$(TEST_TARGETS): %.so: %.o
	$(mod.link)

debug: CFLAGS+=-g3 -DDEBUG
debug: all

tests: CFLAGS+=-DTEST_FRAMEWORK
tests: debug $(TEST_TARGETS)

clean:
	find . -type f -name "*.exports" -delete
	find . -type f -name "*.o" -delete
	find . -type f -name "*.so" -delete

install: all
	install -m 644 include/asterisk/*.h $(AST_INCLUDE_DIR)
	find . -type f -name "*.so" -exec install -m 755 {} $(AST_MODULES_DIR) \;

uninstall:
	$(RM) $(AST_INCLUDE_DIR)/*socket_io*.h
	$(RM) $(AST_INCLUDE_DIR)/*respoke*.h
	$(RM) $(AST_MODULES_DIR)/*socket_io*.so
	$(RM) $(AST_MODULES_DIR)/*respoke*.so

.PHONY: all clean install uninstall debug tests
