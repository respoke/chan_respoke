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

#include "asterisk/json.h"

#include "asterisk/respoke.h"
#include "asterisk/respoke_endpoint.h"
#include "asterisk/respoke_message.h"
#include "asterisk/respoke_transport.h"
#include "include/respoke_private.h"
#include "include/respoke_transaction.h"
#include "include/respoke_general.h"

/*! \brief Incremental number used for transactions, useful for associating things in logging in the future */
static int transaction_id;

struct respoke_transaction {
	/*! \brief Unique identifier for this transaction */
	unsigned int id;
	/*! \brief Current state of the transaction */
	enum respoke_transaction_state state;
	/*! \brief The callback to invoke */
	respoke_transaction_callback callback;
	/*! \brief The original message that was sent */
	struct respoke_message *message;
	/*! \brief Object to pass to the callback */
	void *obj;
	/*! \brief Optional parent transaction */
	struct respoke_transaction *parent;
};

/*! \brief Helper function which turns a state into a string */
static const char *transaction_state2str(enum respoke_transaction_state state)
{
	switch (state) {
	case RESPOKE_TRANSACTION_STATE_CREATED:
		return "Created";
	case RESPOKE_TRANSACTION_STATE_RECEIVED:
		return "Message Received";
	case RESPOKE_TRANSACTION_STATE_SENT:
		return "Message Sent";
	case RESPOKE_TRANSACTION_STATE_RESPONSE_ERROR:
		return "Received Error Response";
	case RESPOKE_TRANSACTION_STATE_RESPONSE_SUCCESS:
		return "Received Success Response";
	case RESPOKE_TRANSACTION_STATE_DESTROYED:
		return "Destroyed";
	}

	/* This will never get reached */
	return "";
}

/*! \brief Helper function which changes state of a transaction and invokes callback */
static void transaction_set_state(struct respoke_transaction *transaction, enum respoke_transaction_state state,
	struct ast_json *data)
{
	if (transaction->state == state) {
		return;
	}

	ast_debug(1, "Transaction '%d' is transitioning from state '%d(%s)' to '%d(%s)'\n",
		transaction->id, transaction->state, transaction_state2str(transaction->state),
		state, transaction_state2str(state));
	transaction->state = state;

	if (transaction->callback) {
		transaction->callback(transaction, transaction->obj, data);
	}

	if (transaction->parent && (state != RESPOKE_TRANSACTION_STATE_DESTROYED)) {
		ast_debug(1, "Transaction '%d' has parent transaction '%d', also transitioning\n",
			transaction->id, transaction->parent->id);
		transaction_set_state(transaction->parent, state, data);
	}
}

static void transaction_on_response(void *obj, struct ast_json *data)
{
	struct respoke_transaction *transaction = obj;
	struct ast_json *error;
	enum respoke_transaction_state state;

	respoke_transaction_log_packet(transaction, data, transaction->message->endpoint, 0);

	/* For testing purposes this implements pre-sails.js changes */
	error = ast_json_object_get(data, "error");
	if (error) {
		state = RESPOKE_TRANSACTION_STATE_RESPONSE_ERROR;
	} else {
		state = RESPOKE_TRANSACTION_STATE_RESPONSE_SUCCESS;
	}

	transaction_set_state(transaction, state, data);

	/* The transaction reference is held by the event and will be destroyed when it is
	 * destroyed
	 */
}

struct respoke_message *respoke_transaction_get_message(struct respoke_transaction *transaction)
{
	return transaction->message;
}

unsigned int respoke_transaction_get_id(const struct respoke_transaction *transaction)
{
	return transaction->id;
}

enum respoke_transaction_state respoke_transaction_get_state(const struct respoke_transaction *transaction)
{
	return transaction->state;
}

void *respoke_transaction_get_object(const struct respoke_transaction *transaction)
{
	return transaction->obj;
}

void respoke_transaction_set_callback(struct respoke_transaction *transaction,
	respoke_transaction_callback callback, void *obj)
{
	ao2_cleanup(transaction->obj);

	transaction->callback = callback;
	transaction->obj = ao2_bump(obj);
}

struct respoke_transaction *respoke_transaction_get_parent(const struct respoke_transaction *transaction)
{
	return transaction->parent;
}

static void transaction_destroy(void *obj)
{
	struct respoke_transaction *transaction = obj;

	transaction_set_state(transaction, RESPOKE_TRANSACTION_STATE_DESTROYED, NULL);

	ao2_cleanup(transaction->message);
	ao2_cleanup(transaction->obj);
	ao2_cleanup(transaction->parent);
}

static struct respoke_transaction *transaction_alloc(respoke_transaction_callback callback,
	struct respoke_message *message, void *obj)
{
	struct respoke_transaction *transaction;

	transaction = ao2_alloc(sizeof(*transaction), transaction_destroy);

	if (!transaction) {
		return NULL;
	}

	transaction->state = RESPOKE_TRANSACTION_STATE_CREATED;
	transaction->id = ast_atomic_fetchadd_int(&transaction_id, +1);
	transaction->callback = callback;
	transaction->message = ao2_bump(message);
	transaction->obj = ao2_bump(obj);

	return transaction;
}

static int transaction_send(struct respoke_transaction *parent, struct respoke_message *message,
	respoke_transaction_callback callback, void *obj)
{
	struct respoke_transaction *transaction;
	int res;

	transaction = transaction_alloc(callback, message, obj);

	if (!transaction) {
		return -1;
	}

	respoke_transaction_log_packet(transaction, message->json, message->endpoint, 1);

	transaction->parent = ao2_bump(parent);
	transaction_set_state(transaction, RESPOKE_TRANSACTION_STATE_SENT, NULL);

	res = respoke_transaction_retransmit(transaction);

	/* The underlying transport layer bumps the ref of the object passed in, so we need to unref it here */
	ao2_ref(transaction, -1);

	return res;
}

int respoke_transaction_send(struct respoke_message *message, respoke_transaction_callback callback,
	void *obj)
{
	return transaction_send(NULL, message, callback, obj);
}

int respoke_transaction_retransmit(struct respoke_transaction *transaction)
{
	return respoke_transport_emit(transaction->message->transport, "post", transaction->message->json,
		transaction_on_response, transaction);
}

void respoke_transaction_receive(struct respoke_transport *transport, struct ast_json *json)
{
	struct respoke_message *message = respoke_message_alloc(
		transport, NULL, json, NULL, NULL);
	struct respoke_transaction *transaction;

	if (!message) {
		return;
	}

	transaction = transaction_alloc(NULL, message, NULL);

	if (!transaction) {
		ao2_ref(message, -1);
		return;
	}

	transaction_set_state(transaction, RESPOKE_TRANSACTION_STATE_RECEIVED, NULL);

	respoke_message_receive(transaction);

	ao2_ref(transaction, -1);
}

int respoke_transaction_respond(struct respoke_transaction *transaction,
	struct respoke_message *message, respoke_transaction_callback callback,
	void *obj)
{
	return transaction_send(transaction, message, callback, obj);
}

void respoke_transaction_log_packet(struct respoke_transaction *transaction,
				    struct ast_json *json, struct respoke_endpoint *endpoint,
				    unsigned int transmitting)
{
	if (respoke_get_packet_logging()) {
		char *contents;

		contents = ast_json_dump_string_format(json, AST_JSON_PRETTY);
		if (contents) {
			const char *send_recv = "Received";
			const char *msg_resp = "response";

			if (transmitting) {
				send_recv = "Transmitting";
				msg_resp = "message";
			}

			ast_verbose("<--- %s transaction '%d' Respoke %s (%zd bytes)%s%s "
				    "--->\n%s\n", send_recv, transaction->id, msg_resp,
				    strlen(contents), endpoint ? " on endpoint " : "",
				    endpoint ? ast_sorcery_object_get_id(endpoint) : "",
				    contents);
			ast_json_free(contents);
		}
	}
}
