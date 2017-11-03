/*
 * Respoke - Web communications made easy
 *
 * Copyright (C) 2015, D.C.S. LLC
 *
 * Chad McElligott <cmcelligott@respoke.io>
 * David M. Lee, II <dlee@respoke.io>
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
 * \brief Retrieve data from a respoke session's metadata
 *
 * \author \verbatim Chad McElligott <cmcelligott@respoke.io> \endverbatim
 * \author \verbatim David M. Lee, II <dlee@respoke.io> \endverbatim
 *
 * \ingroup functions
 *
 */

/*** MODULEINFO
	<depend>res_respoke</depend>
	<depend>res_respoke_session</depend>
	<support_level>extended</support_level>
 ***/

#include "asterisk.h"

#if ASTERISK_MAJOR_VERSION >= 13 && ASTERISK_MAJOR_VERSION < 15
ASTERISK_REGISTER_FILE()
#endif

#include "asterisk/app.h"
#include "asterisk/pbx.h"
#include "asterisk/module.h"
#include "asterisk/channel.h"
#include "asterisk/json.h"

#include "asterisk/respoke.h"
#include "asterisk/res_respoke_session.h"

/*** DOCUMENTATION
	<function name="RESPOKE_METADATA" language="en_US">
		<synopsis>
			Get the value at the specified key from a respoke session's metadata,
			or the full value of the metadata when no key is provided.
		</synopsis>
		<syntax>
			<parameter name="key" required="true">
				<para>
					The key to retrieve the value for. If no such key is found,
					returns an empty string. If the value at the key is an object or
					an array, returns the stringified representation of the value.
					If no key is provided, returns the full value of the session's
					metadata using the same rules.
				</para>
			</parameter>
		</syntax>
	</function>
***/

static int respoke_metadata_function_read(struct ast_channel *chan,
	const char *cmd, char *data, struct ast_str **buf, ssize_t len)
{
	char *parsed_data = ast_strdupa(data);
	const char *key;
	const struct respoke_session *session = chan ? ast_channel_tech_pvt(chan) : NULL;
	struct ast_json *value_json;
	int res = -1;

	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(key);
	);

	if (!session || strncmp(ast_channel_name(chan), "RESPOKE/", 8)) {
		ast_log(AST_LOG_ERROR, "This function requires a RESPOKE channel.\n");
		return -1;
	}

	if (session->metadata == NULL) {
		ast_debug(1, "No metadata on the respoke channel.\n");
		return -1;
	}

	AST_STANDARD_APP_ARGS(args, parsed_data);
	key = args.key ? args.key : "";

	/* Supplying a complex key will not do the right thing currently, so
	 * this check is here to prevent anyone from doing that. We can come
	 * in later and add support for complex keys.
	 */
	if (strpbrk(key, "['.\"") != NULL) {
		ast_log(AST_LOG_ERROR, "Key \"%s\" cannot contain any of [ ' . \"\n", key);
		return -1;
	}

	value_json = ast_strlen_zero(key) ?
		session->metadata : ast_json_object_get(session->metadata, key);

	if (value_json == NULL) {
		ast_debug(1, "Metadata has no key \"%s\"\n", key);
		return -1;
	}

	switch (ast_json_typeof(value_json)) {
	case AST_JSON_OBJECT:
	case AST_JSON_ARRAY:
		res = ast_json_dump_str(value_json, buf);
		break;
	case AST_JSON_STRING:
		res = ast_str_set(buf, len, "%s", ast_json_string_get(value_json));
		break;
	case AST_JSON_INTEGER:
		res = ast_str_set(buf, len, "%jd", ast_json_integer_get(value_json));
		break;
	case AST_JSON_REAL:
		res = ast_str_set(buf, len, "%lf", ast_json_real_get(value_json));
		break;
	case AST_JSON_TRUE:
		res = ast_str_set(buf, len, "true");
		break;
	case AST_JSON_FALSE:
		res = ast_str_set(buf, len, "false");
		break;
	case AST_JSON_NULL:
		res = ast_str_set(buf, len, "null");
		break;
	}

	return res < 0 ? -1 : 0;
}

static struct ast_custom_function respoke_metadata_function = {
	.name = "RESPOKE_METADATA",
	.read2 = respoke_metadata_function_read,
};

static int unload_module(void)
{
	return ast_custom_function_unregister(&respoke_metadata_function);
}

static int load_module(void)
{
	return ast_custom_function_register(&respoke_metadata_function);
}

#undef AST_BUILDOPT_SUM
#define AST_BUILDOPT_SUM ""
AST_MODULE_INFO_STANDARD_EXTENDED(ASTERISK_GPL_KEY,
        "Retrieve data from a respoke session's metadata");
