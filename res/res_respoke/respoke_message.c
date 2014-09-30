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

#include "asterisk/utils.h"
#include "asterisk/linkedlists.h"
#include "asterisk/json.h"
#include "asterisk/rtp_engine.h"

#include "asterisk/respoke.h"
#include "asterisk/respoke_endpoint.h"
#include "asterisk/respoke_message.h"
#include "asterisk/respoke_transport.h"

#include "include/respoke_private.h"
#include "include/respoke_transaction.h"
#include "include/respoke_general.h"

struct message_handler_list {
	const struct respoke_message_handler *handler;
	AST_RWLIST_ENTRY(message_handler_list) list;
};

static AST_RWLIST_HEAD_STATIC(message_handlers, message_handler_list);

int respoke_register_message_handler(const struct respoke_message_handler *handler)
{
	struct message_handler_list *message_handler_list_item;
	SCOPED_LOCK(lock, &message_handlers, AST_RWLIST_WRLOCK, AST_RWLIST_UNLOCK);

	message_handler_list_item = ast_calloc(1, sizeof(*message_handler_list_item));
	if (!message_handler_list_item) {
		return -1;
	}
	message_handler_list_item->handler = handler;

	AST_RWLIST_INSERT_TAIL(&message_handlers, message_handler_list_item, list);
	ast_debug(1, "Registered message handler of types '%s'\n", handler->types);

	ast_module_ref(respoke_get_module_info()->self);

	return 0;
}

void respoke_unregister_message_handler(const struct respoke_message_handler *handler)
{
	struct message_handler_list *iter;
	SCOPED_LOCK(lock, &message_handlers, AST_RWLIST_WRLOCK, AST_RWLIST_UNLOCK);

	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&message_handlers, iter, list) {
		if (iter->handler == handler) {
			AST_RWLIST_REMOVE_CURRENT(list);
			ast_free(iter);
			ast_debug(1, "Unregistered message handler of types '%s'\n", handler->types);
			ast_module_unref(respoke_get_module_info()->self);
			break;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;
}

static const char *respoke_status_map[] = {
	[RESPOKE_STATUS_FINAL] = "final",
	[RESPOKE_STATUS_RINGING] = "ringing",
	[RESPOKE_STATUS_BUSY] = "busy",
	[RESPOKE_STATUS_UNAVAILABLE] = "service unavailable",
	[RESPOKE_STATUS_INCOMPLETE] = "incomplete address",
	[RESPOKE_STATUS_TRYING] = "trying",
	[RESPOKE_STATUS_PROGRESS] = "in progress",
	[RESPOKE_STATUS_REDIRECTING] = "redirecting",
	[RESPOKE_STATUS_HANGUP] = "hangup",
	[RESPOKE_STATUS_DISCONNECTED] = "disconnected",
	[RESPOKE_STATUS_UNKNOWN] = "unknown"
};

enum respoke_status respoke_str_to_status(const char *status)
{
	int i;

	if (ast_strlen_zero(status)) {
		return RESPOKE_STATUS_UNKNOWN;
	}

	for (i = 0; i < ARRAY_LEN(respoke_status_map); ++i) {
		if (!strcmp(respoke_status_map[i], status)) {
			return i;
		}
	}
	return RESPOKE_STATUS_UNKNOWN;
}

const char *respoke_status_to_str(enum respoke_status status)
{
	return ARRAY_IN_BOUNDS(status, respoke_status_map) ?
		respoke_status_map[status] : "unknown";
}

static void respoke_message_destroy(void *obj)
{
	struct respoke_message *message = obj;

	ao2_cleanup(message->endpoint);
	ao2_cleanup(message->transport);
	ast_free(message->contents);
	ast_variables_destroy(message->headers);
	ast_json_unref(message->json);
	ast_free(message->url);
}

struct respoke_message *respoke_message_alloc(
	struct respoke_transport *transport, const char *contents,
	struct ast_json *json, struct respoke_endpoint *endpoint,
	const char *url)
{
	struct respoke_message *message = ao2_alloc(
		sizeof(*message), respoke_message_destroy);

	if (!message) {
		return NULL;
	}

	message->transport = ao2_bump(transport);
	message->endpoint = ao2_bump(endpoint);

	message->contents = ast_strdup(contents);
	message->url = ast_strdup(url);

	if (json) {
		message->json = ast_json_ref(json);
	}

	return message;
}


int respoke_message_set_header(struct respoke_message *message, const char *name,
	const char *value)
{
	struct ast_variable *existing = message->headers, *header;

	header = ast_variable_new(name, value, "");
	if (!header) {
		return -1;
	}
	header->next = existing;
	message->headers = header;

	return 0;
}

const char *respoke_message_get_header(const struct respoke_message *message,
	const char *name)
{
	const struct ast_variable *header;

	for (header = message->headers; header; header = header->next) {
		if (!strcmp(header->name, name)) {
			return header->value;
		}
	}

	return NULL;
}

static int message_dispatcher(void *data)
{
	SCOPED_LOCK(lock, &message_handlers, AST_RWLIST_RDLOCK, AST_RWLIST_UNLOCK);
	RAII_VAR(struct respoke_transaction *, transaction, data, ao2_cleanup);
	struct respoke_message *message = respoke_transaction_get_message(transaction);
	const char *type, *signal_type = NULL;
	struct message_handler_list *handler;
	unsigned int found = 0;

	if (!(message->endpoint = respoke_endpoint_identify(message))) {
		respoke_transaction_log_packet(transaction, message->json, NULL, 0);
		respoke_message_send_error_from_message(message, NULL, NULL, "Endpoint not found");
		return 0;
	}

	respoke_transaction_log_packet(transaction, message->json, message->endpoint, 0);

	type = respoke_message_type_get(message);
	if (ast_strlen_zero(type)) {
		respoke_message_send_error_from_message(
			message, NULL, NULL, "Invalid or missing header");
		return 0;
	}

	/* If this message is relating to signaling go a little deeper and get the signaling type */
	if (!strcmp(type, "signal")) {
		signal_type = respoke_message_signal_type_get(message);
	}

	/* Go through all registered signal handlers seeing if any will accept this message */
	AST_LIST_TRAVERSE(&message_handlers, handler, list) {
		if (strcasestr(type, handler->handler->types) &&
			(!signal_type || !handler->handler->signaltypes ||
				strcasestr(signal_type, handler->handler->signaltypes))) {
			found = 1;
			if (handler->handler->receive_message(transaction, message)) {
				break;
			}
		}
	}

	if (!found) {
		respoke_message_send_error_from_message(
			message, NULL, NULL, "Unknown signal type received");
	}

	return 0;
}

void respoke_message_receive(struct respoke_transaction *transaction)
{
	struct respoke_message *message = respoke_transaction_get_message(transaction);

	/* This is a very thin receive function which has the goal of quickly getting the message off to
	 * elsewhere to be parsed and dispatched.
	 */
	if (!message->transport || !message->json ||
		respoke_push_task(NULL, message_dispatcher, ao2_bump(transaction))) {
		ao2_ref(transaction, -1);
		return;
	}
}

int respoke_message_send(struct respoke_message *message, respoke_transaction_callback callback,
	void *obj)
{
	if (!message || !message->transport) {
		return -1;
	}

	if (respoke_message_sail(message)) {
		return -1;
	}

	return respoke_transaction_send(message, callback, obj);
}

int respoke_message_send_and_release(struct respoke_message *message, respoke_transaction_callback callback,
	void *obj)
{
	int res = respoke_message_send(message, callback, obj);

	if (res) {
		ast_log(LOG_ERROR, "Unable to send message of type: %s - "
			"signalType: %s\n", respoke_message_type_get(message),
			respoke_message_signal_type_get(message));
	}

	ao2_cleanup(message);
	return res;
}

int respoke_message_send_error_va(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint,
	respoke_transaction_callback callback, void *obj,
	const char *from, const char *from_type,
	const char *from_connection, const char *to, const char *to_type,
	const char *to_connection, const char *to_appid, const char *session_id,
	const char *format, va_list ap)
{
	RAII_VAR(char *, detail, NULL, ast_free);
	struct respoke_message *error;

	if (ast_vasprintf(&detail, format, ap) < 0) {
		return -1;
	}

	if (!(error = respoke_message_create_error(
		      transport, endpoint, from, from_type, from_connection, to, to_type,
		      to_connection, to_appid, S_OR(session_id, "-"), detail))) {
		return -1;
	}

	ast_debug(3, "Sending error (session_id=%s) - %s\n", session_id, detail);
	return respoke_message_send_and_release(error, callback, obj);
}

int respoke_message_send_error(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint,
	respoke_transaction_callback callback, void *obj,
	const char *from, const char *from_type,
	const char *from_connection, const char *to, const char *to_type,
	const char *to_connection, const char *to_appid, const char *session_id,
	const char *format, ...)
{
	int res;
	va_list ap;

	va_start(ap, format);
	res = respoke_message_send_error_va(
		transport, endpoint, callback, obj, from, from_type, from_connection, to, to_type,
		to_connection, to_appid, session_id, format, ap);
	va_end(ap);
	return res;
}

int respoke_message_send_error_from_message(const struct respoke_message *message,
	respoke_transaction_callback callback, void *obj, const char *format,
	...)
{
	int res;
	va_list ap;

	va_start(ap, format);
	res = respoke_message_send_error_va(
		message->transport,
		message->endpoint,
		callback, obj,
		respoke_message_to_get(message),
		respoke_message_to_type_get(message),
		respoke_message_to_connection_get(message),
		respoke_message_from_get(message),
		respoke_message_from_type_get(message),
		respoke_message_from_connection_get(message),
		respoke_message_to_appid_get(message),
		respoke_message_session_id_get(message), format, ap);
	va_end(ap);
	return res;
}

