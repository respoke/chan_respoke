/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2014, Digium, Inc.
 *
 * Joshua Colp <jcolp@digium.com>
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

/*!
 * \file \brief Test Respoke module registering and unregistering.
 * \author\verbatim Joshua Colp <jcolp@digium.com> \endverbatim
 *
 * \ingroup tests
 */

/*** MODULEINFO
	<depend>TEST_FRAMEWORK</depend>
	<depend>res_respoke</depend>
	<support_level>extended</support_level>
 ***/

#include "asterisk.h"

#if AST_VERSION_MAJOR >= 13 && AST_VERSION_MAJOR < 15
ASTERISK_REGISTER_FILE()
#endif

#include "asterisk/module.h"
#include "asterisk/test.h"

#include "asterisk/respoke_message.h"
#include "asterisk/respoke_endpoint.h"
#include "asterisk/respoke_transport.h"

const struct respoke_transport_protocol test_transport_protocol = {
	.type = "Test",
};

const struct respoke_transport_protocol test_transport_protocol_no_type = {
};

const struct respoke_endpoint_identifier test_identifier = {
};

const struct respoke_message_handler test_handler = {
	.types = "test",
};

AST_TEST_DEFINE(transport_register)
{
	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = "/res/respoke/";
		info->summary = "Test Respoke transport registration.";
		info->description = "Test Respoke transport registration.";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	ast_test_validate(test, !respoke_register_transport_protocol(&test_transport_protocol));
	respoke_unregister_transport_protocol(&test_transport_protocol);

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(transport_register_duplicate)
{
	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = "/res/respoke/";
		info->summary = "Test Respoke transport registration when colliding.";
		info->description = "Test Respoke transport registration when colliding.";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	ast_test_validate(test, !respoke_register_transport_protocol(&test_transport_protocol));
	ast_test_validate(test, respoke_register_transport_protocol(&test_transport_protocol));
	respoke_unregister_transport_protocol(&test_transport_protocol);

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(transport_register_without_type)
{
	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = "/res/respoke/";
		info->summary = "Test Respoke transport registration without type.";
		info->description = "Test Respoke transport registration without type.";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	ast_test_validate(test, respoke_register_transport_protocol(&test_transport_protocol_no_type));

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(endpoint_identifier_register)
{
	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = "/res/respoke/";
		info->summary = "Test Respoke endpoint identifier registration.";
		info->description = "Test Respoke endpoint identifier registration.";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	ast_test_validate(test, !respoke_register_endpoint_identifier(&test_identifier));
	respoke_unregister_endpoint_identifier(&test_identifier);

	return AST_TEST_PASS;
}

AST_TEST_DEFINE(message_handler_register)
{
	switch (cmd) {
	case TEST_INIT:
		info->name = __func__;
		info->category = "/res/respoke/";
		info->summary = "Test Respoke message handler registration.";
		info->description = "Test Respoke message handler registration.";
		return AST_TEST_NOT_RUN;
	case TEST_EXECUTE:
		break;
	}

	ast_test_validate(test, !respoke_register_message_handler(&test_handler));
	respoke_unregister_message_handler(&test_handler);

	return AST_TEST_PASS;
}

static int unload_module(void)
{
	AST_TEST_UNREGISTER(transport_register_without_type);
	AST_TEST_UNREGISTER(transport_register_duplicate);
	AST_TEST_UNREGISTER(transport_register);
	AST_TEST_UNREGISTER(endpoint_identifier_register);
	AST_TEST_UNREGISTER(message_handler_register);
	return 0;
}

static int load_module(void)
{
	AST_TEST_REGISTER(message_handler_register);
	AST_TEST_REGISTER(endpoint_identifier_register);
	AST_TEST_REGISTER(transport_register_without_type);
	AST_TEST_REGISTER(transport_register_duplicate);
	AST_TEST_REGISTER(transport_register);
	return AST_MODULE_LOAD_SUCCESS;
}

#undef AST_BUILDOPT_SUM
#define AST_BUILDOPT_SUM ""
AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT, "Respoke module testing",
	.support_level = AST_MODULE_SUPPORT_EXTENDED,
	.load = load_module,
	.unload = unload_module,
	.nonoptreq = "res_respoke",
	);
