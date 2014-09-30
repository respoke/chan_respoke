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
#include "res_respoke/include/respoke_private.h"
#include "res_respoke/include/respoke_system.h"

#include "asterisk/astobj2.h"
#include "asterisk/module.h"
#include "asterisk/sorcery.h"
#include "asterisk/threadpool.h"
#include "asterisk/taskprocessor.h"

/*** MODULEINFO
	<depend>res_socket_io</depend>
	<depend>res_sorcery_config</depend>
	<support_level>extended</support_level>
 ***/

static struct ast_threadpool *respoke_threadpool;

const struct ast_module_info *respoke_get_module_info(void)
{
	return ast_module_info;
}

struct ast_taskprocessor *respoke_create_serializer(void)
{
	char name[AST_UUID_STR_LEN];

	ast_uuid_generate_str(name, sizeof(name));

	return ast_threadpool_serializer(name, respoke_threadpool);
}

int respoke_push_task(struct ast_taskprocessor *serializer, int (*respoke_task)(void *), void *task_data)
{
	if (serializer) {
		return ast_taskprocessor_push(serializer, respoke_task, task_data);
	} else {
		return ast_threadpool_push(respoke_threadpool, respoke_task, task_data);
	}
}

struct sync_task_data {
	ast_mutex_t lock;
	ast_cond_t cond;
	int complete;
	int fail;
	int (*task)(void *);
	void *task_data;
};

static int sync_task(void *data)
{
	struct sync_task_data *std = data;
	std->fail = std->task(std->task_data);

	ast_mutex_lock(&std->lock);
	std->complete = 1;
	ast_cond_signal(&std->cond);
	ast_mutex_unlock(&std->lock);
	return std->fail;
}

int respoke_push_task_synchronous(struct ast_taskprocessor *serializer, int (*respoke_task)(void *), void *task_data)
{
	/* This method is an onion */
	struct sync_task_data std;

	ast_mutex_init(&std.lock);
	ast_cond_init(&std.cond, NULL);
	std.fail = std.complete = 0;
	std.task = respoke_task;
	std.task_data = task_data;

	if (serializer) {
		if (ast_taskprocessor_push(serializer, sync_task, &std)) {
			return -1;
		}
	} else {
		if (ast_threadpool_push(respoke_threadpool, sync_task, &std)) {
			return -1;
		}
	}

	ast_mutex_lock(&std.lock);
	while (!std.complete) {
		ast_cond_wait(&std.cond, &std.lock);
	}
	ast_mutex_unlock(&std.lock);

	ast_mutex_destroy(&std.lock);
	ast_cond_destroy(&std.cond);
	return std.fail;
}

static int load_module(void)
{
	struct ast_threadpool_options options;

	if (respoke_initialize_configuration()) {
		ast_log(LOG_ERROR, "Failed to initialize Respoke configuration. Aborting load\n");
		return AST_MODULE_LOAD_DECLINE;
	}

	respoke_get_threadpool_options(&options);
	respoke_threadpool = ast_threadpool_create("Respoke", NULL, &options);
	if (!respoke_threadpool) {
		ast_log(LOG_ERROR, "Failed to initialize Respoke threadpool. Aborting load\n");
		respoke_destroy_configuration();
		return AST_MODULE_LOAD_DECLINE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

static int reload_module(void)
{
	if (respoke_reload_configuration()) {
		ast_log(LOG_ERROR, "Failed to reload Respoke configuration.\n");
		return AST_MODULE_LOAD_FAILURE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_threadpool_shutdown(respoke_threadpool);
	respoke_destroy_configuration();
	return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS | AST_MODFLAG_LOAD_ORDER, "Basic Respoke resource",
		.support_level = AST_MODULE_SUPPORT_EXTENDED,
		.load = load_module,
		.unload = unload_module,
		.reload = reload_module,
		.load_pri = AST_MODPRI_CHANNEL_DEPEND - 5,
);
