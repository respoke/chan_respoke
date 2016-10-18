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

/*! \file
 *
 * \brief Get information about a Respoke endpoint
 *
 * \author \verbatim Joshua Colp <jcolp@digium.com> \endverbatim
 *
 * \ingroup functions
 *
 */

/*** MODULEINFO
	<depend>res_respoke</depend>
	<support_level>extended</support_level>
 ***/

#include "asterisk.h"

ASTERISK_REGISTER_FILE()

#include "asterisk/app.h"
#include "asterisk/pbx.h"
#include "asterisk/module.h"
#include "asterisk/channel.h"
#include "asterisk/sorcery.h"

#include "asterisk/respoke.h"
#include "asterisk/respoke_endpoint.h"

/*** DOCUMENTATION
	<function name="RESPOKE_ENDPOINT" language="en_US">
		<synopsis>
			Get information about a Respoke endpoint
		</synopsis>
		<syntax>
			<parameter name="name" required="true">
				<para>The name of the endpoint to query.</para>
			</parameter>
			<parameter name="field" required="true">
				<para>The configuration option for the endpoint to query for.
				Supported options are those fields on the
				<replaceable>endpoint</replaceable> object in
				<filename>respoke.conf</filename>.</para>
			</parameter>
		</syntax>
	</function>
***/

static int respoke_endpoint_function_read(struct ast_channel *chan,
	const char *cmd, char *data, struct ast_str **buf, ssize_t len)
{
	struct ast_sorcery *respoke_sorcery;
	char *parsed_data = ast_strdupa(data);
	RAII_VAR(void *, endpoint_obj, NULL, ao2_cleanup);
	struct ast_variable *change_set;
	struct ast_variable *it_change_set;
	int res;

	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(endpoint_name);
		AST_APP_ARG(field_name);
	);

	/* Check for zero arguments */
	if (ast_strlen_zero(parsed_data)) {
		ast_log(AST_LOG_ERROR, "Cannot call %s without arguments\n", cmd);
		return -1;
	}

	AST_STANDARD_APP_ARGS(args, parsed_data);

	if (ast_strlen_zero(args.endpoint_name)) {
		ast_log(AST_LOG_ERROR, "Cannot call %s without an endpoint name to query\n", cmd);
		return -1;
	}

	if (ast_strlen_zero(args.field_name)) {
		ast_log(AST_LOG_ERROR, "Cannot call %s with an empty field name to query\n", cmd);
		return -1;
	}

	respoke_sorcery = respoke_get_sorcery();
	if (!respoke_sorcery) {
		ast_log(AST_LOG_ERROR, "Unable to retrieve Respoke configuration: sorcery object is NULL\n");
		return -1;
	}

	endpoint_obj = ast_sorcery_retrieve_by_id(respoke_sorcery, RESPOKE_ENDPOINT, args.endpoint_name);
	if (!endpoint_obj) {
		ast_log(AST_LOG_WARNING, "Failed to retrieve information for endpoint '%s'\n", args.endpoint_name);
		return -1;
	}

	change_set = ast_sorcery_objectset_create(respoke_sorcery, endpoint_obj);
	if (!change_set) {
		ast_log(AST_LOG_WARNING, "Failed to retrieve information for endpoint '%s': change set is NULL\n", args.endpoint_name);
		return -1;
	}

	for (it_change_set = change_set; it_change_set; it_change_set = it_change_set->next) {
		if (!strcmp(it_change_set->name, args.field_name)) {
			if (!strcmp(it_change_set->name, "disallow")) {
				ast_str_set(buf, len, "!%s", it_change_set->value);
			} else {
				ast_str_set(buf, len, "%s", it_change_set->value);
			}
			break;
		}
	}

	res = it_change_set ? 0 : 1;
	if (res) {
		ast_log(AST_LOG_WARNING, "Unknown property '%s' for Respoke endpoint\n", args.field_name);
	}

	ast_variables_destroy(change_set);

	return res;
}


static struct ast_custom_function respoke_endpoint_function = {
	.name = "RESPOKE_ENDPOINT",
	.read2 = respoke_endpoint_function_read,
};

static int unload_module(void)
{
	return ast_custom_function_unregister(&respoke_endpoint_function);
}

static int load_module(void)
{
	return ast_custom_function_register(&respoke_endpoint_function);
}

#undef AST_BUILDOPT_SUM
#define AST_BUILDOPT_SUM ""
AST_MODULE_INFO_STANDARD_EXTENDED(ASTERISK_GPL_KEY, "Get information about a Respoke endpoint");
