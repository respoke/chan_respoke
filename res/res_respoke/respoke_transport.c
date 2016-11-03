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
#include "asterisk/respoke_transport.h"
#include "include/respoke_private.h"

#include "asterisk/json.h"
#include "asterisk/utils.h"
#include "asterisk/linkedlists.h"

struct transport_protocol_list {
	const struct respoke_transport_protocol *protocol;
	AST_RWLIST_ENTRY(transport_protocol_list) list;
};

static AST_RWLIST_HEAD_STATIC(transport_protocols, transport_protocol_list);

int respoke_register_transport_protocol(
	const struct respoke_transport_protocol *protocol)
{
	struct transport_protocol_list *transport_protocol_list_item;
	SCOPED_LOCK(lock, &transport_protocols, AST_RWLIST_WRLOCK, AST_RWLIST_UNLOCK);

	if (ast_strlen_zero(protocol->type)) {
		ast_log(LOG_ERROR, "Unable to add transport as it has no type.\n");
		return -1;
	}

	AST_LIST_TRAVERSE(&transport_protocols, transport_protocol_list_item, list) {
		if (!strcmp(transport_protocol_list_item->protocol->type,
			    protocol->type)) {
			ast_log(LOG_ERROR, "Unable to add transport protocol '%s'. This "
				"type is already registered.\n", protocol->type);
			return -1;
		}
	}

	transport_protocol_list_item = ast_calloc(
		1, sizeof(*transport_protocol_list_item));
	if (!transport_protocol_list_item) {
		return -1;
	}
	transport_protocol_list_item->protocol = protocol;

	AST_RWLIST_INSERT_TAIL(&transport_protocols, transport_protocol_list_item, list);
	ast_debug(1, "Registered transport protocol type '%s'\n", protocol->type);

	ast_module_ref(respoke_get_module_info()->self);

	return 0;
}

void respoke_unregister_transport_protocol(
	const struct respoke_transport_protocol *protocol)
{
	struct transport_protocol_list *iter;
	SCOPED_LOCK(lock, &transport_protocols, AST_RWLIST_WRLOCK, AST_RWLIST_UNLOCK);

	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&transport_protocols, iter, list) {
		if (iter->protocol == protocol) {
			AST_RWLIST_REMOVE_CURRENT(list);
			ast_free(iter);
			ast_debug(1, "Unregistered transport protocol type '%s'\n",
				  protocol->type);
			ast_module_unref(respoke_get_module_info()->self);
			break;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;
}

static const struct respoke_transport_protocol *respoke_transport_get_protocol(
	const char *protocol)
{
	struct transport_protocol_list *iter;
	SCOPED_LOCK(lock, &transport_protocols, AST_RWLIST_RDLOCK, AST_RWLIST_UNLOCK);

	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&transport_protocols, iter, list) {
		if (!strcmp(iter->protocol->type, protocol)) {
			return iter->protocol;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;

	ast_log(LOG_ERROR, "Configured transport protocol '%s' "
		"does not match a known protocol\n", protocol);
	return NULL;
}

/*! \brief Transport state definition. */
struct respoke_transport_state {
	/*! Current status of the transport */
	enum respoke_transport_status status;
	/*! A transport protocol implementation */
	const struct respoke_transport_protocol *protocol;
	/*! Transport state data */
	void *data;
	/*! Optional callback to invoke on status changes */
	respoke_transport_callback callback;
	/*! Optional data to pass to callback */
	void *callback_data;
};

static void respoke_transport_state_destroy(void *obj)
{
	struct respoke_transport_state *state = obj;

	ao2_cleanup(state->data);
	ao2_cleanup(state->callback_data);
}

static struct respoke_transport_state *respoke_transport_state_create(
	const struct respoke_transport_protocol *protocol, void *data)
{
	struct respoke_transport_state *state = ao2_alloc(
		sizeof(*state), respoke_transport_state_destroy);

	if (!state) {
		ast_log(LOG_ERROR, "Unable to allocate a respoke "
			"transport state\n");
		return NULL;
	}

	state->protocol = protocol;
	state->data = data;

	return state;
}

void *respoke_transport_state_data(const struct respoke_transport *transport)
{
	return transport->state->data;
}

static void respoke_transport_destroy(void *obj)
{
	struct respoke_transport *transport = obj;
	ast_string_field_free_memory(transport);
	ao2_cleanup(transport->state);
}

static void *respoke_transport_alloc(const char *name)
{
	struct respoke_transport *transport = ast_sorcery_generic_alloc(
		sizeof(*transport), respoke_transport_destroy);

	if (!transport) {
		return NULL;
	}

	if (ast_string_field_init(transport, 128)) {
		ao2_ref(transport, -1);
		return NULL;
	}

	return transport;
}

struct respoke_transport_state *respoke_transport_create_instance(struct respoke_transport *transport)
{
	void *data;
	const struct respoke_transport_protocol *protocol =
		respoke_transport_get_protocol(transport->protocol);
	struct respoke_transport_state *state;

	if (!protocol) {
		return NULL;
	}

	if (!(data = protocol->create(transport))) {
		ast_log(LOG_ERROR, "Unable to instantiate a transport of "
			"protocol type '%s'\n", transport->protocol);
		return NULL;
	}

	if (!(state = respoke_transport_state_create(
		      protocol, data))) {
		ao2_ref(data, -1);
		return NULL;
	}

	return state;
}

int respoke_transport_start(struct respoke_transport *transport)
{
	return transport->state->protocol->start(transport);
}

void respoke_transport_set_callback(struct respoke_transport_state *state,
	respoke_transport_callback callback, void *data)
{
	ao2_cleanup(state->callback_data);
	state->callback = callback;
	state->callback_data = ao2_bump(data);
}

void respoke_transport_invoke_callback(struct respoke_transport *transport, enum respoke_transport_status status)
{
	if (!transport->state->callback || (transport->state->status == status)) {
		return;
	}

	transport->state->status = status;
	transport->state->callback(transport, transport->state->callback_data, status);
}

int respoke_transport_emit(struct respoke_transport *transport,
			   const char *name, const struct ast_json *json,
			   respoke_transport_response_callback callback, void *obj)
{
	return transport->state->protocol->emit_message(transport, name, json, callback, obj);
}

int respoke_transport_initialize(void)
{
	struct ast_sorcery *sorcery = respoke_get_sorcery();

	if (respoke_transport_socket_io_initialize()) {
		return -1;
	}

	ast_sorcery_apply_default(sorcery, "transport", "config",
				  "respoke.conf,criteria=type=transport");

	if (ast_sorcery_internal_object_register(
		    sorcery, "transport", respoke_transport_alloc,
		    NULL, NULL)) {
		return -1;
	}

	/* These are purposely marked as nodoc as documentation will
	   not be included with the running Asterisk */
	ast_sorcery_object_field_register_nodoc(
		sorcery, "transport", "type", "", OPT_NOOP_T, 0, 0);
	ast_sorcery_object_field_register_nodoc(
		sorcery, "transport", "protocol", "", OPT_STRINGFIELD_T, 0,
		STRFLDSET(struct respoke_transport, protocol));
	ast_sorcery_object_field_register_nodoc(
		sorcery, "transport", "uri", "https://api.respoke.io", OPT_STRINGFIELD_T, 0,
		STRFLDSET(struct respoke_transport, uri));
	ast_sorcery_object_field_register_nodoc(
		sorcery, "transport", "uri_api", "https://api.respoke.io/v1", OPT_STRINGFIELD_T, 0,
		STRFLDSET(struct respoke_transport, uri_api));

	return 0;
}

void respoke_transport_deinitialize(void)
{
	respoke_transport_socket_io_deinitialize();
}
