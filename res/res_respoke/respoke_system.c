/*
 * Respoke - Web communications made easy
 *
 * Copyright (C) 2014, D.C.S. LLC
 *
 * Joshua Colp <jcolp@digium.com>
 *
 * See https://www.respoke.io for more information about
 * Respoke. Please do not directly contact any of the
 * maintainers of this project for assistance.
 * Respoke offers a community forum to submit and discuss
 * issues at http://community.respoke.io; please raise any
 * issues there.
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
*/

#include "asterisk.h"

#include "asterisk/respoke.h"
#include "include/respoke_system.h"

#include "asterisk/sorcery.h"
#include "asterisk/threadpool.h"

static struct ast_threadpool_options respoke_threadpool_options = {
	.version = AST_THREADPOOL_OPTIONS_VERSION,
};

void respoke_get_threadpool_options(struct ast_threadpool_options *threadpool_options)
{
	*threadpool_options = respoke_threadpool_options;
}

/*! \brief Allocator for system configuration */
static void *system_alloc(const char *name)
{
	return ast_sorcery_generic_alloc(sizeof(struct respoke_system), NULL);
}

/*! \brief Callback function when configuration is applied to a system configuration */
static int system_apply(const struct ast_sorcery *sorcery, void *obj)
{
	struct respoke_system *system = obj;

	respoke_threadpool_options.initial_size = system->threadpool.initial_size;
	respoke_threadpool_options.auto_increment = system->threadpool.auto_increment;
	respoke_threadpool_options.idle_timeout = system->threadpool.idle_timeout;
	respoke_threadpool_options.max_size = system->threadpool.max_size;

	return 0;
}

int respoke_initialize_system(void)
{
	struct ast_sorcery *sorcery = respoke_get_sorcery();
	RAII_VAR(struct ao2_container *, system_configs, NULL, ao2_cleanup);
	RAII_VAR(struct respoke_system *, system, NULL, ao2_cleanup);

	ast_sorcery_apply_default(sorcery, "system", "config", "respoke.conf,criteria=type=system");

	if (ast_sorcery_internal_object_register(sorcery, "system", system_alloc, NULL, system_apply)) {
		return -1;
	}

	/* These are purposely marked as nodoc as documentation will not be included with the running Asterisk */
	ast_sorcery_object_field_register_nodoc(sorcery, "system", "type", "", OPT_NOOP_T, 0, 0);
	ast_sorcery_object_field_register_nodoc(sorcery, "system", "threadpool_initial_size", "0",
			OPT_UINT_T, 0, FLDSET(struct respoke_system, threadpool.initial_size));
	ast_sorcery_object_field_register_nodoc(sorcery, "system", "threadpool_auto_increment", "5",
			OPT_UINT_T, 0, FLDSET(struct respoke_system, threadpool.auto_increment));
	ast_sorcery_object_field_register_nodoc(sorcery, "system", "threadpool_idle_timeout", "60",
			OPT_UINT_T, 0, FLDSET(struct respoke_system, threadpool.idle_timeout));
	ast_sorcery_object_field_register_nodoc(sorcery, "system", "threadpool_max_size", "0",
			OPT_UINT_T, 0, FLDSET(struct respoke_system, threadpool.max_size));

	ast_sorcery_load(sorcery);

	system_configs = ast_sorcery_retrieve_by_fields(sorcery, "system",
		AST_RETRIEVE_FLAG_MULTIPLE | AST_RETRIEVE_FLAG_ALL, NULL);

	if (ao2_container_count(system_configs)) {
		return 0;
	}

	/* No config present, allocate one and apply defaults */
	system = ast_sorcery_alloc(sorcery, "system", NULL);
	if (!system) {
		ast_log(LOG_ERROR, "Unable to allocate default system config.\n");
		return -1;
	}

	if (system_apply(sorcery, system)) {
		ast_log(LOG_ERROR, "Failed to apply default system config.\n");
		return -1;
	}

	return 0;
}
