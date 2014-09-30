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

#include "asterisk/cli.h"
#include "asterisk/format.h"
#include "asterisk/format_cap.h"
#include "asterisk/sorcery.h"
#include "asterisk/utils.h"
#include "asterisk/linkedlists.h"
#include "asterisk/callerid.h"

#include "asterisk/respoke.h"
#include "include/respoke_private.h"
#include "include/respoke_app.h"

static void respoke_app_destroy(void *obj)
{
	struct respoke_app *app = obj;

	ast_string_field_free_memory(app);
}

static void *respoke_app_alloc(const char *name)
{
	struct respoke_app *app = ast_sorcery_generic_alloc(
		sizeof(*app), respoke_app_destroy);

	if (!app) {
		return NULL;
	}

	if (ast_string_field_init(app, 256)) {
		ao2_ref(app, -1);
		return NULL;
	}

	return app;
}

static int respoke_app_apply(const struct ast_sorcery *sorcery, void *obj)
{
	struct respoke_app *app = obj;

	if (ast_strlen_zero(app->secret)) {
		ast_log(LOG_ERROR, "A secret must be specified for application '%s'\n",
			ast_sorcery_object_get_id(app));
		return -1;
	}

	return 0;
}

int respoke_app_initialize(void)
{
	struct ast_sorcery *sorcery = respoke_get_sorcery();

	ast_sorcery_apply_default(sorcery, RESPOKE_APP, "config",
				  "respoke.conf,criteria=type=app");

	if (ast_sorcery_internal_object_register(
		    sorcery, RESPOKE_APP, respoke_app_alloc,
		    NULL, respoke_app_apply)) {
		return -1;
	}

	/* These are purposely marked as nodoc as documentation will
	   not be included with the running Asterisk */
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_APP, "type", "", OPT_NOOP_T, 0, 0);
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_APP, "app_secret", "", OPT_STRINGFIELD_T, 0,
		STRFLDSET(struct respoke_app, secret));

	ast_sorcery_reload_object(sorcery, RESPOKE_APP);

	return 0;
}
