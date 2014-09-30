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

#include "asterisk/astobj2.h"
#include "asterisk/http_websocket.h"
#include "asterisk/module.h"
#include "asterisk/strings.h"
#include "asterisk/uri.h"
#include "asterisk/res_socket_io.h"

/*** MODULEINFO
	<depend>res_socket_io</depend>
	<support_level>extended</support_level>
 ***/

static void *transport_websocket_init(const struct ast_socket_io_session *session)
{
	struct ast_websocket *ws;
	struct ast_str *uri = ast_str_create(128);
	enum ast_websocket_result result;
	struct ast_uri *session_uri = ast_socket_io_uri(session);
	struct ast_tls_config *tls_cfg = NULL;

	if (!uri) {
		ast_log(LOG_ERROR, "Unable to allocate websocket uri\n");
		return NULL;
	}

	ast_str_set(&uri, 0, "%s://%s:%s/socket.io/%s/websocket/%s",
		    ast_uri_is_secure(session_uri) ? "wss" : "ws",
		    ast_uri_host(session_uri), ast_uri_port(session_uri),
		    SOCKET_IO_VERSION, ast_socket_io_id(session));

	if (!ast_strlen_zero(ast_uri_query(session_uri))) {
		ast_str_append(&uri, 0, "?%s", ast_uri_query(session_uri));
	}

	if (ast_uri_is_secure(session_uri)) {
		/* The websocket client expects a copy of the TLS configuration so provide it */
		tls_cfg = ast_calloc(1, sizeof(*tls_cfg));
		ast_set_flag(&tls_cfg->flags, AST_SSL_DONT_VERIFY_SERVER);
	}

	ws = ast_websocket_client_create(
		ast_str_buffer(uri), "socket.io",
			tls_cfg, &result);
	ast_free(uri);

	if (ws) {
		struct protoent *p;

		p = getprotobyname("tcp");
		if (p) {
			int arg = 1;

			if (setsockopt(ast_websocket_fd(ws), p->p_proto, TCP_NODELAY, (char *) &arg, sizeof(arg) ) < 0) {
				ast_log(LOG_WARNING, "Failed to set TCP_NODELAY on HTTP connection: %s\n", strerror(errno));
				ast_log(LOG_WARNING, "Some HTTP requests may be slow to respond.\n");
			}
		}

		ast_websocket_set_nonblock(ws);
	}

	return ws;
}

static int transport_websocket_send(void *obj, const char *data)
{
	return ast_websocket_write_string(obj, data);
}

static int transport_websocket_recv(void *obj, char **data)
{
	int res;

	res = ast_wait_for_input(ast_websocket_fd(obj), -1);
	if (res <= 0) {
		ast_log(LOG_WARNING, "WebSocket poll error: %s\n",
			strerror(errno));
		return -1;
	}

	res = ast_websocket_read_string(obj, data);

	return res;
}

static const struct ast_module_info *transport_websocket_module_info(void)
{
	return ast_module_info;
}

struct ast_socket_io_transport transport_websocket = {
	.type = "websocket",
	.init = transport_websocket_init,
	.send = transport_websocket_send,
	.recv = transport_websocket_recv,
	.module_info = transport_websocket_module_info
};

static int load_module(void)
{
	if (ast_socket_io_transport_register(&transport_websocket)) {
		return AST_MODULE_LOAD_FAILURE;
	}
	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_socket_io_transport_unregister(&transport_websocket);
	return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Socket IO Transport Websocket",
		.support_level = AST_MODULE_SUPPORT_EXTENDED,
		.load = load_module,
		.unload = unload_module,
		.load_pri = AST_MODPRI_DEFAULT,
);


