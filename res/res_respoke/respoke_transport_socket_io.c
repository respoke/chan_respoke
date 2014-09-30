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

#include "asterisk.h"

#include <signal.h>

#include "asterisk/json.h"
#include "asterisk/res_socket_io.h"
#include "asterisk/uri.h"

#include "asterisk/respoke_message.h"
#include "asterisk/respoke_transport.h"

struct socket_io_state {
	pthread_t recv_thread;
	unsigned int stop;
	struct ast_socket_io_session *session;
	struct ast_socket_io_namespace *namespace;
};

static void socket_io_state_destroy(void *obj)
{
	struct socket_io_state *state = obj;

	/* tell the messaging thread to stop */
	ast_socket_io_stop(state->session);
	state->stop = 1;
	pthread_kill(state->recv_thread, SIGURG);
	pthread_join(state->recv_thread, NULL);

	ao2_ref(state->namespace, -1);
	ao2_ref(state->session, -1);
}

static void on_signal(struct ast_socket_io_namespace *ns,
	struct ast_json *data, void *obj)
{
	/* data should be a json array and the the signal should
	   always be in the first element */
	struct ast_json *json = ast_json_array_get(data, 0);

	respoke_transaction_receive(ns->obj, json);
}

static void *transport_socket_io_create(const struct respoke_transport *transport)
{
	struct socket_io_state *state;
	struct ast_socket_io_namespace *namespace;
	struct ast_socket_io_session *session = ast_socket_io_create(
		transport->uri);

	if (!session) {
		return NULL;
	}

	/* transport doesn't need a ref bump here since before being it is freed
	   the items using it (session/namespace) will be freed first. */
	if (!(namespace = ast_socket_io_namespace_create(
		      ast_uri_path(ast_socket_io_uri(session)), (void *)transport))) {
		ao2_ref(session, -1);
		return NULL;
	}

	if (ast_socket_io_namespace_event_add(namespace, "signal", on_signal) ||
	    ast_socket_io_namespace_add(session, namespace)) {
		ao2_ref(session, -1);
		return NULL;
	}

	if (!(state = ao2_alloc(sizeof(*state), socket_io_state_destroy))) {
		ao2_ref(namespace, -1);
		ao2_ref(session, -1);
		return NULL;
	}

	state->recv_thread = AST_PTHREADT_NULL;
	state->session = session;
	state->namespace = namespace;
	return state;
}

static void *receive_messages(void *obj)
{
	struct respoke_transport *transport = obj;
	struct socket_io_state *state = respoke_transport_state_data(transport);

	while (!state->stop) {
		respoke_transport_invoke_callback(transport, RESPOKE_TRANSPORT_STATUS_DISCONNECTED);
		if (ast_socket_io_client_connect(state->session, NULL) != SOCKET_IO_OK) {
			/* wait a bit and try to reconnect */
			sleep(1);
			continue;
		}

		respoke_transport_invoke_callback(obj, RESPOKE_TRANSPORT_STATUS_CONNECTED);

		/* once the message processing loop starts it runs until there
		   is either an error or it is told to stop. if told to stop
		   SOCKET_IO_OK is returned and we want to quit the thread,
		   otherwise (on error) try to reconnect/reset and try again. */
		if (ast_socket_io_repl(state->session) == SOCKET_IO_OK) {
			break;
		}
	}

	respoke_transport_invoke_callback(transport, RESPOKE_TRANSPORT_STATUS_DISCONNECTED);

	return NULL;
}

static int transport_socket_io_start(const struct respoke_transport *transport)
{
	struct socket_io_state *state = respoke_transport_state_data(transport);
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	/* don't need to bump the ref on the session since the thread
	   will be stopped before releasing the it */
	if (ast_pthread_create(
		    &state->recv_thread, &attr, receive_messages, (struct respoke_transport*)transport)) {
		ast_log(LOG_ERROR, "Unable to start socket IO messaging "
			"for client namespace '%s'\n", state->namespace->path);
		pthread_attr_destroy(&attr);
		return -1;
	}
	pthread_attr_destroy(&attr);
	return 0;
}

struct transport_callback_params {
	/*! \brief The callback to invoke */
	respoke_transport_response_callback callback;
	/*! \brief Object to pass to the callback */
	void *obj;
};

static void transport_callback_params_destroy(void *obj)
{
	struct transport_callback_params *params = obj;

	ao2_cleanup(params->obj);
}

static void transport_callback(struct ast_socket_io_namespace *ns,
	struct ast_json *data, void *obj)
{
	struct transport_callback_params *params = obj;
	/* data should be a json array and the the signal should
	   always be in the first element */
	struct ast_json *json = ast_json_array_get(data, 0);

	/* however the first element is still a string, so convert to json */
	if (json) {
		if (!strcmp(ast_json_string_get(json), "null")) {
			ast_json_unref(json);
			json = NULL;
		} else if (!(json = ast_json_load_string(ast_json_string_get(json), NULL))) {
			ast_log(LOG_ERROR, "Unable to load signal: %s\n", ast_json_string_get(
					ast_json_array_get(data, 0)));
			return;
		}
	}

	if (params->callback) {
		params->callback(params->obj, json);
	}
	ast_json_unref(json);
}

static int transport_socket_io_emit_message(
	const struct respoke_transport *transport, const char *name,
	const struct ast_json *json, respoke_transport_response_callback callback,
	void *obj)
{
	struct socket_io_state *state = respoke_transport_state_data(transport);
	struct transport_callback_params *params = NULL;
	int res;

	if (callback) {
		params = ao2_alloc(sizeof(*params), transport_callback_params_destroy);

		if (!params) {
			return -1;
		}
		params->callback = callback;
		params->obj = ao2_bump(obj);
	}

	res = ast_socket_io_emit(state->namespace, name, (struct ast_json *)json,
		transport_callback, params);
	ao2_cleanup(params);

	return res != SOCKET_IO_OK ? -1 : 0;
}

struct respoke_transport_protocol respoke_transport_socket_io = {
	.type = "socket.io",
	.create = transport_socket_io_create,
	.start = transport_socket_io_start,
	.emit_message = transport_socket_io_emit_message
};

int respoke_transport_socket_io_initialize(void)
{
	if (respoke_register_transport_protocol(&respoke_transport_socket_io)) {
		return -1;
	}

	return 0;
}

void respoke_transport_socket_io_deinitialize(void)
{
	respoke_unregister_transport_protocol(&respoke_transport_socket_io);
}
