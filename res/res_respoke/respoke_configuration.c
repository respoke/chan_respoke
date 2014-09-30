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
#include "asterisk/respoke_endpoint.h"
#include "asterisk/respoke_transport.h"
#include "include/respoke_private.h"
#include "include/respoke_system.h"
#include "include/respoke_app.h"
#include "include/respoke_general.h"
#include "asterisk/sorcery.h"

static struct ast_sorcery *respoke_sorcery;

int respoke_initialize_configuration()
{
	if (!(respoke_sorcery = ast_sorcery_open())) {
		ast_log(LOG_ERROR, "Failed to open Respoke sorcery object\n");
		return -1;
	}

	if (respoke_initialize_system()) {
		ast_log(LOG_ERROR, "Could not initialize Respoke system configuration support\n");
		ast_sorcery_unref(respoke_sorcery);
		return -1;
	}

	if (respoke_initialize_general()) {
		ast_log(LOG_ERROR, "Could not initialize Respoke general configuration support\n");
		ast_sorcery_unref(respoke_sorcery);
		return -1;
	}

	if (respoke_transport_initialize()) {
		ast_log(LOG_ERROR, "Could not initialize Respoke transport support\n");
		ast_sorcery_unref(respoke_sorcery);
		return -1;
	}

	if (respoke_app_initialize()) {
		ast_log(LOG_ERROR, "Could not initialize Respoke app support\n");
		ast_sorcery_unref(respoke_sorcery);
		return -1;
	}

	if (respoke_endpoint_initialize()) {
		ast_log(LOG_ERROR, "Could not initialize Respoke endpoint support\n");
		ast_sorcery_unref(respoke_sorcery);
		return -1;
	}

	ast_sorcery_load(respoke_sorcery);

	return 0;
}

void respoke_destroy_configuration(void)
{
	respoke_endpoint_deinitialize();
	respoke_transport_deinitialize();
	ast_sorcery_unref(respoke_sorcery);
}

int respoke_reload_configuration(void)
{
	if (respoke_sorcery) {
		ast_sorcery_reload(respoke_sorcery);
	}
	return 0;
}

struct ast_sorcery *respoke_get_sorcery(void)
{
	return respoke_sorcery;
}
