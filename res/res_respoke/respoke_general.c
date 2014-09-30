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
#include "include/respoke_general.h"

#include "asterisk/sorcery.h"

struct respoke_general {
	/*! Sorcery object details */
	SORCERY_OBJECT(details);
	/*! Whether packet logging is enabled or not */
	unsigned int packet_logging;
};

/*! \brief Global config debugging */
static unsigned int config_packet_logging;

unsigned int respoke_get_packet_logging(void)
{
	return config_packet_logging;
}

/*! \brief Allocator for general configuration */
static void *general_alloc(const char *name)
{
	return ast_sorcery_generic_alloc(sizeof(struct respoke_general), NULL);
}

/*! \brief Callback function when configuration is applied to a general configuration */
static int general_apply(const struct ast_sorcery *sorcery, void *obj)
{
	struct respoke_general *general = obj;

	config_packet_logging = general->packet_logging;

	return 0;
}

int respoke_initialize_general(void)
{
	struct ast_sorcery *sorcery = respoke_get_sorcery();
	RAII_VAR(struct ao2_container *, general_configs, NULL, ao2_cleanup);
	RAII_VAR(struct respoke_general *, general, NULL, ao2_cleanup);

	ast_sorcery_apply_default(sorcery, "general", "config", "respoke.conf,criteria=type=general");

	if (ast_sorcery_internal_object_register(sorcery, "general", general_alloc, NULL, general_apply)) {
		return -1;
	}

	/* These are purposely marked as nodoc as documentation will not be included with the running Asterisk */
	ast_sorcery_object_field_register_nodoc(sorcery, "general", "type", "", OPT_NOOP_T, 0, 0);
	ast_sorcery_object_field_register_nodoc(sorcery, "general", "packet_logging", "no", OPT_BOOL_T, 1,
		FLDSET(struct respoke_general, packet_logging));

	ast_sorcery_load(sorcery);

	general_configs = ast_sorcery_retrieve_by_fields(sorcery, "general",
		AST_RETRIEVE_FLAG_MULTIPLE | AST_RETRIEVE_FLAG_ALL, NULL);

	if (ao2_container_count(general_configs)) {
		return 0;
	}

	/* No config present, allocate one and apply defaults */
	general = ast_sorcery_alloc(sorcery, "general", NULL);
	if (!general) {
		ast_log(LOG_ERROR, "Unable to allocate default general config.\n");
		return -1;
	}

	if (general_apply(sorcery, general)) {
		ast_log(LOG_ERROR, "Failed to apply default general config.\n");
		return -1;
	}

	return 0;
}
