/*
 * Respoke - Web communications made easy
 *
 * Copyright (C) 2014, D.C.S. LLC
 *
 * Kevin Harwell <kharwell@digium.com>
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

/*** MODULEINFO
	<depend>res_respoke</depend>
	<support_level>extended</support_level>
 ***/

#include "asterisk.h"

#include "asterisk/module.h"
#include "asterisk/sorcery.h"

#include "asterisk/respoke.h"
#include "asterisk/respoke_endpoint.h"
#include "asterisk/respoke_message.h"

static struct respoke_endpoint *identify(struct respoke_message *message)
{
	return ast_sorcery_retrieve_by_id(respoke_get_sorcery(), RESPOKE_ENDPOINT,
					  respoke_message_from_get(message));
}

static struct respoke_endpoint_identifier identifier = {
	.identify = identify
};

static int unload_module(void)
{
	respoke_unregister_endpoint_identifier(&identifier);
	return 0;
}

static int load_module(void)
{
	return respoke_register_endpoint_identifier(&identifier) ?
		AST_MODULE_LOAD_FAILURE : AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Respoke from endpoint identifier",
		.support_level = AST_MODULE_SUPPORT_EXTENDED,
		.load = load_module,
		.unload = unload_module,
		.load_pri = AST_MODPRI_APP_DEPEND,
	       );
