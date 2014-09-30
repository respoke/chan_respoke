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

#include <curl/curl.h>

#include "asterisk/astobj2.h"
#include "asterisk/json.h"
#include "asterisk/module.h"
#include "asterisk/sched.h"
#include "asterisk/strings.h"
#include "asterisk/uri.h"
#include "asterisk/http_websocket.h"
#include "asterisk/res_socket_io.h"

/*** MODULEINFO
	<depend>res_http_websocket</depend>
	<depend>curl</depend>
	<support_level>extended</support_level>
 ***/

/*! \brief number of transport buckets */
#define MAX_TRANSPORT_BUCKETS 5
/*! \brief number of event buckets */
#define MAX_EVENT_BUCKETS 17
/*! \brief number of namespace buckets */
#define MAX_NAMESPACE_BUCKETS 5

/*! Scheduling context for heartbeats */
static struct ast_sched_context *sched;

/*! \brief Details for a socket IO event. */
struct socket_io_event {
	/*! called when named event needs to be raised */
	ast_socket_io_event callback;
	/*! object to associate with the event (passed to callback) */
	void *obj;
	/*! name of the event */
	char name[0];
};

static int socket_io_event_hash(const void *obj, int flags)
{
	const struct socket_io_event *object;
	const char *key;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_KEY:
		key = obj;
		break;
	case OBJ_SEARCH_OBJECT:
		object = obj;
		key = object->name;
		break;
	default:
		ast_assert(0);
		return 0;
	}
	return ast_str_hash(key);
}

static int socket_io_event_cmp(void *obj, void *arg, int flags)
{
	const struct socket_io_event *object_left = obj;
	const struct socket_io_event *object_right = arg;
	const char *right_key = arg;
	int cmp;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
		right_key = object_right->name;
		/* Fall through */
	case OBJ_SEARCH_KEY:
		cmp = strcmp(object_left->name, right_key);
		break;
	case OBJ_SEARCH_PARTIAL_KEY:
		/* Not supported by container. */
		ast_assert(0);
		return 0;
	default:
		cmp = 0;
		break;
	}
	if (cmp) {
		return 0;
	}
	return CMP_MATCH;
}

static void socket_io_event_remove(struct ao2_container *events, const char *name)
{
	ao2_find(events, name, OBJ_SEARCH_KEY | OBJ_NODATA | OBJ_UNLINK);
}

static void socket_io_event_destroy(void *obj)
{
	struct socket_io_event *event = obj;
	ao2_cleanup(event->obj);
}

static int socket_io_event_add(struct ao2_container *events, const char *name,
			       ast_socket_io_event callback, void *obj)
{
	SCOPED_AO2LOCK(lock, events);
	struct socket_io_event *event;
	int size;

	if (!callback) {
		/* no reason to have an event with an empty callback */
		return 0;
	}

	if ((event = ao2_find(events, name, OBJ_SEARCH_KEY))) {
		ast_log(LOG_ERROR, "Event '%s' already added\n", name);
		ao2_ref(event, -1);
		return -1;
	}

	size = strlen(name) + 1;
	if (!(event = ao2_alloc(sizeof(*event) + size, socket_io_event_destroy))) {
		ast_log(LOG_ERROR, "Unable to create socket IO event\n");
		return -1;
	}
	ast_copy_string(event->name, name, size);

	event->callback = callback;
	event->obj = ao2_bump(obj);

	ao2_link(events, event);
	ao2_ref(event, -1);
	return 0;
}

/*! Internal details for a socket IO transport. */
struct socket_io_transport {
	/*! the instantiated transport type ao2 object */
	void *obj;
	/*! id generator for an event callbacks */
	unsigned int id;
	/*! holds response events */
	struct ao2_container *events;
	/*! the transport object/methods */
	struct ast_socket_io_transport *transport;
};

static void socket_io_transport_destroy(void *obj)
{
	struct socket_io_transport *transport = obj;

	ao2_cleanup(transport->obj);
	ao2_cleanup(transport->events);
	ast_module_unref(transport->transport->module_info()->self);
}

static AST_RWLIST_HEAD_STATIC(socket_io_transports, ast_socket_io_transport);

static struct ast_socket_io_transport *socket_io_transport_find(const char *type)
{
	struct ast_socket_io_transport *item;
	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&socket_io_transports, item, item) {
		if (!strcmp(item->type, type)) {
			break;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;
	return item;
}

int ast_socket_io_transport_register(struct ast_socket_io_transport *transport)
{
	struct ast_socket_io_transport *item;

	SCOPED_LOCK(lock, &socket_io_transports, AST_RWLIST_WRLOCK, AST_RWLIST_UNLOCK);
	if ((item = socket_io_transport_find(transport->type))) {
		ast_log(LOG_ERROR, "Transport type '%s' already "
			"registered\n", transport->type);
		return -1;
	}
	AST_RWLIST_INSERT_TAIL(&socket_io_transports, transport, item);
	ast_module_ref(ast_module_info->self);
	return 0;
}

void ast_socket_io_transport_unregister(struct ast_socket_io_transport *transport)
{
	struct ast_socket_io_transport *item;

	SCOPED_LOCK(lock, &socket_io_transports, AST_RWLIST_WRLOCK, AST_RWLIST_UNLOCK);
	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&socket_io_transports, item, item) {
		if (item == transport) {
			AST_RWLIST_REMOVE_CURRENT(item);
			ast_module_unref(ast_module_info->self);
			break;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;
}

static struct socket_io_transport *socket_io_transport_get(const char *type)
{
	struct socket_io_transport *res;
	struct ast_socket_io_transport *item;

	SCOPED_LOCK(lock, &socket_io_transports, AST_RWLIST_RDLOCK, AST_RWLIST_UNLOCK);
	if (!(item = socket_io_transport_find(type))) {
		ast_log(LOG_WARNING, "Transport type '%s' not registered\n", type);
		return NULL;
	}

	if (!(res = ao2_alloc(sizeof(*res), socket_io_transport_destroy))) {
		ast_log(LOG_WARNING, "Unable to allocate transport "
			"type '%s'\n", type);
		return NULL;
	}

	if (!(res->events = ao2_container_alloc(
		     MAX_EVENT_BUCKETS, socket_io_event_hash, socket_io_event_cmp))) {
		ast_log(LOG_ERROR, "Unable to allocate events container on "
			" transport type '%s'\n", type);
		ao2_ref(res, -1);
		return NULL;
	}

	ast_module_ref(item->module_info()->self);
	res->transport = item;

	return res;
}

static struct socket_io_transport *socket_io_transport_match(
	const char *client_protocols, const char *server_protocols)
{
	char *protocols = ast_strdupa(client_protocols);
	char *rest, *protocol = strtok_r(protocols, ",", &rest);

	while (protocol) {
		if (!strstr(protocol, server_protocols)) {
			return socket_io_transport_get(protocol);
		}
		protocol = strtok_r(NULL, ",", &rest);
	}

	ast_log(LOG_WARNING, "Could not match any client protocols, '%s', to "
		"any server protocols, '%s'\n", client_protocols, server_protocols);
	return NULL;
}

static int socket_io_namespace_hash(const void *obj, int flags)
{
	const struct ast_socket_io_namespace *object;
	const char *key;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_KEY:
		key = obj;
		break;
	case OBJ_SEARCH_OBJECT:
		object = obj;
		key = object->path;
		break;
	default:
		ast_assert(0);
		return 0;
	}
	return ast_str_hash(key);
}

static int socket_io_namespace_cmp(void *obj, void *arg, int flags)
{
	const struct ast_socket_io_namespace *object_left = obj;
	const struct ast_socket_io_namespace *object_right = arg;
	const char *right_key = arg;
	int cmp;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
		right_key = object_right->path;
		/* Fall through */
	case OBJ_SEARCH_KEY:
		cmp = strcmp(object_left->path, right_key);
		break;
	case OBJ_SEARCH_PARTIAL_KEY:
		/* Not supported by container. */
		ast_assert(0);
		return 0;
	default:
		cmp = 0;
		break;
	}
	if (cmp) {
		return 0;
	}
	return CMP_MATCH;
}

/*! \brief Namespace destructor. */
static void socket_io_namespace_destroy(void *obj)
{
	struct ast_socket_io_namespace *ns = obj;
	ao2_cleanup(ns->events);
}

struct ast_socket_io_namespace *ast_socket_io_namespace_create(
	const char *path, void *obj)
{
	struct ast_socket_io_namespace *ns;
	int size = strlen(S_OR(path, "")) + 1;

	if (!(ns = ao2_alloc(sizeof(*ns) + size, socket_io_namespace_destroy))) {
		return NULL;
	}

	if (!(ns->events = ao2_container_alloc(
		     MAX_EVENT_BUCKETS, socket_io_event_hash, socket_io_event_cmp))) {
		ast_log(LOG_ERROR, "Unable to allocate events container on "
			"namespace '%s'\n", path);
		ao2_ref(ns, -1);
		return NULL;
	}

	ns->obj = obj;

	ast_copy_string(ns->path, S_OR(path, ""), size);
	return ns;
}

void ast_socket_io_namespace_event_remove(
	struct ast_socket_io_namespace *ns, const char *name)
{
	socket_io_event_remove(ns->events, name);
}

int ast_socket_io_namespace_event_add(
	struct ast_socket_io_namespace *ns, const char *name,
	ast_socket_io_event callback)
{
	return socket_io_event_add(ns->events, name, callback, NULL);
}

static enum ast_socket_io_result socket_io_disconnect(
	struct ast_socket_io_namespace *ns);
static enum ast_socket_io_result socket_io_connect(
	struct ast_socket_io_namespace *ns);

static int socket_io_namespace_disconnect(void *obj, void *arg, int flags)
{
	socket_io_disconnect(obj);
	return 0;
}

static int socket_io_namespace_connect(void *obj, void *arg, int flags)
{
	struct ast_socket_io_namespace *ns = obj;

	if (!ast_strlen_zero(ns->path)) {
		socket_io_connect(ns);
	}

	return 0;
}

struct sched_heartbeat_data {
	/*! heartbeat's schedule id */
	int id;
	/*! heartbeat's schedule timeout */
	int timeout;
	/*! transport used to send heartbeat */
	struct socket_io_transport *transport;
};

static void sched_heartbeat_data_destroy(void *obj)
{
	struct sched_heartbeat_data* data = obj;
	ao2_cleanup(data->transport);
}

static void socket_io_unschedule_heartbeat(struct ast_socket_io_session *session);

/*! \brief Details for a socket io session. */
struct ast_socket_io_session {
	/*! unique session id */
	char *id;
	/*! comma separate string of supported transports */
	char *transports;
	/*! closing timeout */
	unsigned int closing_timeout;
	/*! negotiated heartbeat timeout */
	unsigned int heartbeat_timeout;
	/*! uri to connected to */
	struct ast_uri *uri;
	/*! the client/server negotiated transport to use */
	struct socket_io_transport *transport;
	/*! collection of path mapped namespaces */
	struct ao2_container *namespaces;
	/*! data passed to the heartbeat scheduler collection of path mapped namespaces */
	struct sched_heartbeat_data *heartbeat_data;
	/*! flag set when the session needs to stop */
	int stop;
};

/*! \brief Session destructor. */
static void socket_io_session_destroy(void *obj)
{
	struct ast_socket_io_session *session = obj;

	socket_io_unschedule_heartbeat(session);

	ao2_callback(session->namespaces, OBJ_NODATA,
		     socket_io_namespace_disconnect, NULL);
	ao2_cleanup(session->namespaces);

	ao2_cleanup(session->uri);

	ast_free(session->transports);
	ast_free(session->id);

	ao2_cleanup(session->transport);
}

struct ast_socket_io_session *ast_socket_io_create(
	const char *uri)
{
	struct ast_socket_io_session *session = ao2_alloc(
		sizeof(*session), socket_io_session_destroy);

	if (!session) {
		ast_log(LOG_ERROR, "Unable to allocate socket_io session\n");
		return NULL;
	}

	if (!(session->uri = ast_uri_parse_http(uri))) {
		ao2_ref(session, -1);
		return NULL;
	}

	if (!(session->namespaces = ao2_container_alloc(
		      MAX_NAMESPACE_BUCKETS, socket_io_namespace_hash,
		      socket_io_namespace_cmp))) {
		ast_log(LOG_ERROR, "Unable to create session namespaces container\n");
		ao2_ref(session, -1);
		return NULL;
	}

	return session;
}

const char *ast_socket_io_id(const struct ast_socket_io_session *session)
{
	return session->id;
}

struct ast_uri *ast_socket_io_uri(
	const struct ast_socket_io_session *session)
{
	return session->uri;
}

void ast_socket_io_stop(struct ast_socket_io_session *session)
{
	session->stop = 1;
}

int ast_socket_io_namespace_remove(
	struct ast_socket_io_session *session, struct ast_socket_io_namespace *ns)
{
	struct ast_socket_io_namespace *found = ao2_find(
		session->namespaces, ns->path, OBJ_SEARCH_KEY | OBJ_UNLINK);

	if (!found) {
		ast_log(LOG_WARNING, "Cannot remove namespace '%s' "
			"not found\n", ns->path);
		return -1;
	}

	if (socket_io_disconnect(found)) {
		ast_log(LOG_ERROR, "Unable to disconnect namespace '%s' "
			"from session\n", ns->path);
		return -1;
	}
	found->session = NULL;
	ao2_ref(found, -1);
	return 0;
}

int ast_socket_io_namespace_add(
	struct ast_socket_io_session *session, struct ast_socket_io_namespace *ns)
{
	struct ast_socket_io_namespace *found = ao2_find(
		session->namespaces, ns->path, OBJ_SEARCH_KEY);

	if (found) {
		ast_log(LOG_WARNING, "Cannot add namespace '%s' "
			"already registered\n", ns->path);
		ao2_ref(found, -1);
		return -1;
	}

	ns->session = session;
	ao2_link(session->namespaces, ns);
	return 0;
}

enum socket_io_message_type {
	SOCKET_IO_DISCONNECT,
	SOCKET_IO_CONNECT,
	SOCKET_IO_HEARTBEAT,
	SOCKET_IO_MESSAGE,
	SOCKET_IO_JSON,
	SOCKET_IO_EVENT,
	SOCKET_IO_ACK,
	SOCKET_IO_ERROR,
	SOCKET_IO_NOOP
};

static enum ast_socket_io_result socket_io_send(
	struct socket_io_transport *transport, int code, const char *path,
	const char *data, ast_socket_io_event callback, void *obj)
{
	char id[64];
	/* example packet form - code:[id]:[path]:[data] */
	struct ast_str *packet;

	if (!transport || !transport->obj) {
		ast_log(LOG_WARNING, "Cannot send outgoing socket IO packet "
			"transport not set  - code: '%d' - path: '%s' \n", code, path);
		return SOCKET_IO_NO_TRANSPORT;
	}

	if (callback) {
		ast_atomic_fetchadd_int((int *)&transport->id, 1);

		if (sprintf(id, "%u", transport->id) < 0) {
			ast_log(LOG_ERROR, "Unable to generate message id "
				"for code: '%d' - path: '%s' \n", code, path);
			return SOCKET_IO_CONVERSION_ERROR;
		}

		if (socket_io_event_add(transport->events, id, callback, obj)) {
			ast_log(LOG_ERROR, "Unable to add response event callback "
				"for code: '%d' - path: '%s' \n", code, path);
			return SOCKET_IO_BAD_EVENT;
		}
	}

	if (!(packet = ast_str_create(256))) {
		ast_log(LOG_ERROR, "Unable to create outgoing socket IO packet "
			"for code: '%d' - path: '%s' \n", code, path);
		if (callback) {
			socket_io_event_remove(transport->events, id);
		}
		return SOCKET_IO_ALLOC_ERROR;
	}

	ast_str_set(&packet, 0, "%d:%s%s:%s", code, callback ? id : "", callback ? "+" : "", S_OR(path, ""));

	if (data) {
		ast_str_append(&packet, 0, ":%s", data);
	}

	if (transport->transport->send(transport->obj, ast_str_buffer(packet))) {
		if (callback) {
			socket_io_event_remove(transport->events, id);
		}
		ast_free(packet);
		return SOCKET_IO_SEND_ERROR;
	}

	ast_debug(3, "Socket IO packet sent: '%s'\n", ast_str_buffer(packet));
	ast_free(packet);
	return SOCKET_IO_OK;
}

static enum ast_socket_io_result socket_io_recv(
	struct socket_io_transport *transport, enum socket_io_message_type *type,
	unsigned int *id, struct ast_str **path, struct ast_str **data)
{
	char *p1, *p2;
	RAII_VAR(char *, packet, NULL, ast_free);

	*type = -1;
	*id = 0;
	ast_str_reset(*path);
	ast_str_reset(*data);

	if (transport->transport->recv(transport->obj, &packet) < 0) {
		return SOCKET_IO_RECV_ERROR;
	}

	p1 = packet;
	ast_debug(3, "Socket IO packet recv: '%s'\n", p1);

	/* the type of message */
	if (!(p2 = strchr(p1, ':'))) {
		/* anytime the expected colon is missing the message is invalid */
		ast_log(LOG_WARNING, "Socket IO received an malformed "
			"packet: '%s'\n", p1);
		return SOCKET_IO_INVALID_PACKET;
	}
	*p2++ = '\0';

	if (sscanf(p1, "%u", type) != 1) {
		ast_log(LOG_WARNING, "Socket IO could not read packet "
			"type: '%s'\n", p1);
		return SOCKET_IO_CONVERSION_ERROR;
	}

	if (*type == SOCKET_IO_NOOP) {
		/* a noop type should have no other relevant data */
		return SOCKET_IO_OK;
	}

	/* message id */
	if (!(p1 = strchr(p2, ':'))) {
		ast_log(LOG_WARNING, "Socket IO received a malformed "
			"packet: '%s'\n", p2);
		return SOCKET_IO_INVALID_PACKET;
	}
	*p1++ = '\0';

	/* only read in if available */
	if (*p2 && (sscanf(p2, "%u", id) != 1)) {
		ast_log(LOG_WARNING, "Socket IO could not read packet "
			"id: '%s'\n", p2);
		return SOCKET_IO_CONVERSION_ERROR;
	}

	if (*type == SOCKET_IO_CONNECT) {
		/* connect type has no message data element */
		ast_str_set(path, 0, "%s", p1 ? p1 : "");
		return SOCKET_IO_OK;
	}

	/* named path */
	if (*type != SOCKET_IO_HEARTBEAT) {
		if (!(p2 = strchr(p1, ':'))) {
			ast_log(LOG_WARNING, "Socket IO received a malformed "
				"packet: '%s'\n", p1);
			return SOCKET_IO_INVALID_PACKET;
		}
		*p2++ = '\0';
		/* actual data*/
		ast_str_set(data, 0, "%s", p2);
	}

	ast_str_set(path, 0, "%s", p1);
	return SOCKET_IO_OK;
}

static int on_scheduled_heartbeat(const void *obj)
{
	struct sched_heartbeat_data* data = (struct sched_heartbeat_data *)obj;

	if (socket_io_send(data->transport, SOCKET_IO_HEARTBEAT,
			   NULL, NULL, NULL, NULL) != SOCKET_IO_OK) {
		ao2_ref(data, -1);
		return 0;
	}
	return data->timeout;
}

static void socket_io_unschedule_heartbeat(struct ast_socket_io_session *session)
{
	if (session->heartbeat_data && session->heartbeat_data->id > 0) {
		AST_SCHED_DEL_UNREF(sched, session->heartbeat_data->id,
				    ao2_cleanup(session->heartbeat_data));
	}
	ao2_cleanup(session->heartbeat_data);
	session->heartbeat_data = NULL;
}

static enum ast_socket_io_result socket_io_schedule_heartbeat(
	struct ast_socket_io_session *session)
{
	/* start the heartbeat if timeout given */
	if (!session->heartbeat_timeout) {
		return SOCKET_IO_OK;
	}

	socket_io_unschedule_heartbeat(session);

	if (!(session->heartbeat_data = ao2_alloc(
		      sizeof(*session->heartbeat_data),
		      sched_heartbeat_data_destroy))) {
		return SOCKET_IO_ALLOC_ERROR;
	}

	session->heartbeat_data->timeout = (int)(session->heartbeat_timeout - 30) * 1000;
	session->heartbeat_data->transport = ao2_bump(session->transport);

	/* add a ref since the scheduler will point to it too */
	ao2_ref(session->heartbeat_data, +1);
	if ((session->heartbeat_data->id = ast_sched_add_variable(
		      sched, session->heartbeat_data->timeout,
		      on_scheduled_heartbeat, session->heartbeat_data, 1)) < 0) {
		ao2_ref(session->heartbeat_data, -1);
		return SOCKET_IO_SCHED_ERROR;
	}

	return SOCKET_IO_OK;
}

static enum ast_socket_io_result socket_io_disconnect(
	struct ast_socket_io_namespace *ns)
{
	if (!ns->session) {
		ast_debug(3, "Socket IO cannot disconnect namespace '%s' - "
			"session not established\n", ns->path);
		return SOCKET_IO_NO_SESSION;
	}

	return socket_io_send(ns->session->transport, SOCKET_IO_DISCONNECT,
			      ns->path, NULL, NULL, NULL);
}

static enum ast_socket_io_result socket_io_connect(
	struct ast_socket_io_namespace *ns)
{
	if (!ns->session) {
		ast_debug(3, "Socket IO cannot connect namespace '%s' - "
			"session not established\n", ns->path);
		return SOCKET_IO_NO_SESSION;
	}

	return socket_io_send(ns->session->transport, SOCKET_IO_CONNECT,
			      ns->path, NULL, NULL, NULL);
}

enum ast_socket_io_result ast_socket_io_message(
	struct ast_socket_io_namespace *ns, const char *data,
	ast_socket_io_event callback, void *obj)
{
	if (!ns->session) {
		ast_log(LOG_WARNING, "Socket IO cannot send message for "
			"namespace '%s' - session not established\n", ns->path);
		return SOCKET_IO_NO_SESSION;
	}

	return socket_io_send(ns->session->transport, SOCKET_IO_MESSAGE,
			      ns->path, data, callback, obj);
}

enum ast_socket_io_result ast_socket_io_json(
	struct ast_socket_io_namespace *ns, struct ast_json *data,
	ast_socket_io_event callback, void *obj)
{
	enum ast_socket_io_result res;
	char *json_str = NULL;

	if (!ns->session) {
		ast_log(LOG_WARNING, "Socket IO cannot send json for "
			"namespace '%s' - session not established\n", ns->path);
		return SOCKET_IO_NO_SESSION;
	}

	if (data && !(json_str = ast_json_dump_string(data))) {
		ast_log(LOG_WARNING, "Socket IO unable to dump json to send "
			"for namespace '%s'\n", ns->path);
		return SOCKET_IO_JSON_ERROR;
	}

	res = socket_io_send(ns->session->transport, SOCKET_IO_JSON, ns->path,
			     json_str, callback, obj);
	ast_json_free(json_str);
	return res;
}

enum ast_socket_io_result ast_socket_io_emit(
	struct ast_socket_io_namespace *ns, const char *name,
	struct ast_json *args, ast_socket_io_event callback, void *obj)
{
	enum ast_socket_io_result res;
	struct ast_json *data, *array;
	char *json_str;

	if (!ns->session) {
		ast_log(LOG_WARNING, "Socket IO cannot emit message for "
			"namespace '%s' - session not established\n", ns->path);
		return SOCKET_IO_NO_SESSION;
	}

	if (!(array = ast_json_array_create())) {
		ast_log(LOG_ERROR, "Socket IO cannot emit message for namespace "
			"'%s' - error creating json array\n", ns->path);
		return SOCKET_IO_JSON_ERROR;
	}

	json_str = ast_json_dump_string(args);
	if (!json_str) {
		ast_log(LOG_ERROR, "Socket IO cannot emit message for namespace "
			"'%s' - error dumping args\n", ns->path);
		ast_json_unref(array);
		return SOCKET_IO_JSON_ERROR;
	}

	ast_json_array_append(array, ast_json_string_create(json_str));
	ast_json_free(json_str);

	data = ast_json_pack(
		"{s:s,s:o}", "name", name, "args", array);

	if (!data || !(json_str = ast_json_dump_string(data))) {
		ast_log(LOG_WARNING, "Socket IO unable to dump json to emit "
			"for namespace '%s'\n", ns->path);
		ast_json_unref(data);
		return SOCKET_IO_JSON_ERROR;
	}

	res = socket_io_send(ns->session->transport, SOCKET_IO_EVENT, ns->path,
			     json_str, callback, obj);
	ast_json_free(json_str);
	ast_json_unref(data);
	return res;
}

enum ast_socket_io_result ast_socket_io_ack(struct ast_socket_io_namespace *ns,
					    const char *id, struct ast_json *args)
{
	enum ast_socket_io_result res;
	struct ast_str *data;
	char *json_str;

	if (!ns->session) {
		ast_log(LOG_WARNING, "Socket IO cannot send ACK for "
			"namespace '%s' - session not established\n", ns->path);
		return SOCKET_IO_NO_SESSION;
	}

	if (!args) {
		return socket_io_send(ns->session->transport, SOCKET_IO_ACK,
				      ns->path, id, NULL, NULL);
	}

	if (!(data = ast_str_create(256))) {
		ast_log(LOG_ERROR, "Unable to create ack packet string\n");
		return SOCKET_IO_ALLOC_ERROR;
	}

	if (args && !(json_str = ast_json_dump_string(args))) {
		ast_log(LOG_WARNING, "Socket IO unable to dump json to ack "
			"for namespace '%s'\n", ns->path);
		ast_free(data);
		return SOCKET_IO_JSON_ERROR;
	}

	ast_str_set(&data, 0, "%s+%s", id, json_str ? json_str : "");
	res = socket_io_send(ns->session->transport, SOCKET_IO_ACK, ns->path,
			     ast_str_buffer(data), NULL, NULL);
	ast_json_free(json_str);
	ast_free(data);
	return res;
}

enum ast_socket_io_result ast_socket_io_noop(struct ast_socket_io_namespace *ns)
{
	if (!ns->session) {
		ast_log(LOG_WARNING, "Socket IO cannot send noop for "
			"namespace '%s' - session not established\n", ns->path);
		return SOCKET_IO_NO_SESSION;
	}

	return socket_io_send(ns->session->transport, SOCKET_IO_NOOP,
			      ns->path, NULL, NULL, NULL);
}

static void socket_io_on_disconnect(struct ast_socket_io_namespace *ns)
{
	ast_debug(3, "Socket IO on disconnect: %s\n", ns->path);

	if (ns->on_disconnect) {
		ns->on_disconnect(ns);
	}
}

static void socket_io_on_connect(struct ast_socket_io_namespace *ns)
{
	ast_debug(3, "Socket IO on connect: %s\n", ns->path);

	if (ns->on_connect) {
		ns->on_connect(ns);
	}
}

static void socket_io_on_heartbeat(struct ast_socket_io_namespace *ns)
{
	ast_debug(3, "Socket IO on heartbeat: %s\n", ns->path);

	if (ns->on_heartbeat) {
		ns->on_heartbeat(ns);
	}
}

static void socket_io_on_message(struct ast_socket_io_namespace *ns,
				 struct ast_str *data)
{
	ast_debug(3, "Socket IO on message: %s - %s\n",
		  ns->path, ast_str_buffer(data));

	if (ns->on_message) {
		ns->on_message(ns, data);
	}
}

static void socket_io_on_json(struct ast_socket_io_namespace *ns,
			      struct ast_str *data)
{
	ast_debug(3, "Socket IO on json: %s - %s\n",
		  ns->path, ast_str_buffer(data));

	if (ns->on_json) {
		struct ast_json *json = ast_json_load_str(data, NULL);
		ns->on_json(ns, json);
		ast_json_unref(json);
	}
}

static void socket_io_on_event(struct ast_socket_io_namespace *ns,
			       struct ast_str *data)
{
	struct socket_io_event *event;

	struct ast_json *name;
	struct ast_json *args;
	struct ast_json *encoded_event = ast_json_load_str(data, NULL);

	ast_debug(3, "Socket IO on event: %s - %s\n",
		  ns->path, ast_str_buffer(data));

	if (!encoded_event) {
		ast_log(LOG_ERROR, "Unable to convert message to JSON\n");
		return;
	}

	if (!(name = ast_json_object_get(encoded_event, "name"))) {
		ast_log(LOG_ERROR, "Encoded event missing name\n");
		ast_json_unref(encoded_event);
		return;
	}
	args = ast_json_object_get(encoded_event, "args");

	if (!(event = ao2_find(ns->events,
			       ast_json_string_get(name), OBJ_SEARCH_KEY))) {
		/* received a non registered event - do nothing */
		ast_debug(3, "Socket IO event not found/registered: %s - %s\n",
			  ns->path, ast_json_string_get(name));
		ast_json_unref(encoded_event);
		return;
	}

	event->callback(ns, args, event->obj);
	ao2_ref(event, -1);
	ast_json_unref(encoded_event);
}

static void socket_io_on_ack(struct ast_socket_io_namespace *ns,
			     struct ast_str *data)
{
	struct socket_io_event *event;
	struct ast_json *args = NULL;
	char *id = ast_str_buffer(data);
	char *p = strchr(id, '+');

	ast_debug(3, "Socket IO on ack: %s - %s\n",
		  ns->path, ast_str_buffer(data));

	if (p) {
		*p++ = '\0';
		if (!(args = ast_json_load_string(p, NULL))) {
			ast_log(LOG_ERROR, "Socket IO on ack: %s - unable "
				"to load arguments '%s'\n", ns->path, p);
			return;
		}
	}

	if ((event = ao2_find(ns->session->transport->events, id,
			      OBJ_SEARCH_KEY | OBJ_UNLINK))) {
		event->callback(ns, args, event->obj);
		ao2_ref(event, -1);
	}
	ast_json_unref(args);
}

static void socket_io_on_error(struct ast_socket_io_namespace *ns,
			       struct ast_str *data)
{
	char *reason = ast_str_buffer(data);
	char *advice = strchr(reason, '+');

	if (advice) {
		*advice++ = '\0';
	}

	ast_log(LOG_ERROR, "Socket IO error: %s - reason = %s, "
		"advice = %s\n", ns->path, reason, S_OR(advice, ""));

	if (ns->on_error) {
		ns->on_error(ns, reason, S_OR(advice, ""));
	}
}

static void socket_io_on_noop(struct ast_socket_io_namespace *ns)
{
	ast_debug(3, "Socket IO on noop: %s\n", ns->path);

	if (ns->on_noop) {
		ns->on_noop(ns);
	}
}

enum ast_socket_io_result ast_socket_io_repl(struct ast_socket_io_session *session)
{
	enum ast_socket_io_result res = SOCKET_IO_OK;
	enum socket_io_message_type type;
	unsigned int id;
	struct ast_str *path = ast_str_create(128);
	struct ast_str *data = ast_str_create(1024);

	while (!session->stop && (res = socket_io_recv(
					  session->transport, &type, &id,
					  &path, &data)) != SOCKET_IO_RECV_ERROR) {
		struct ast_socket_io_namespace *ns;

		if (res != SOCKET_IO_OK) {
			/* received a malformed message so skip */
			continue;
		}

		if (!(ns = ao2_find(session->namespaces, ast_str_buffer(path),
				    OBJ_SEARCH_KEY))) {
			/* received a message mapped to a non-registered
			   namespace, so just ignore and go on */
			ast_debug(3, "Socket IO namespace not found: %s\n",
				  ast_str_buffer(path));
			continue;
		}

		switch (type) {
		case SOCKET_IO_DISCONNECT:
			socket_io_on_disconnect(ns);
			break;
		case SOCKET_IO_CONNECT:
			socket_io_on_connect(ns);
			break;
		case SOCKET_IO_HEARTBEAT:
			socket_io_on_heartbeat(ns);
			break;
		case SOCKET_IO_MESSAGE:
			socket_io_on_message(ns, data);
			break;
		case SOCKET_IO_JSON:
			socket_io_on_json(ns, data);
			break;
		case SOCKET_IO_EVENT:
			socket_io_on_event(ns, data);
			break;
		case SOCKET_IO_ACK:
			socket_io_on_ack(ns, data);
			break;
		case SOCKET_IO_ERROR:
			socket_io_on_error(ns, data);
			break;
		case SOCKET_IO_NOOP:
			socket_io_on_noop(ns);
			break;
		default:
			ast_log(LOG_WARNING, "Invalid message type "
				"'%d' received\n", type);
		}
		ao2_ref(ns, -1);
	}
	ast_free(path);
	ast_free(data);

	socket_io_unschedule_heartbeat(session);

	return session->stop ? SOCKET_IO_OK : res;
}

static size_t client_session_create(void *ptr, size_t size, size_t nmemb, void *data)
{
	struct ast_socket_io_session *session = data;
	char *end, *start = ptr;
	char timeout[64];

	/* session id */
	if (!(end = strchr(start, ':'))) {
		ast_log(LOG_ERROR, "Session id not found in %s\n", start);
		return 0;
	}
	session->id = ast_strndup(start, end - start);

	start = end + 1;
	/* heartbeat timeout */
	if (!(end = strchr(start, ':'))) {
		ast_log(LOG_ERROR, "Session heartbeat timeout not "
			"found in %s\n", start);
		return 0;
	}

	if ((end - start > 1)) {
		ast_copy_string(timeout, start, end - start + 1);
		if (sscanf(timeout, "%u", &session->heartbeat_timeout) != 1) {
			ast_log(LOG_ERROR, "Could not read client session heartbeat "
				"timeout: %s", timeout);
			return 0;
		}
	}

	start = end + 1;
	/* connection closing timeout */
	if (!(end = strchr(start, ':'))) {
		ast_log(LOG_ERROR, "Connection closing timeout not "
			"found in %s\n", start);
		return 0;
	}

	if ((end - start > 1)) {
		ast_copy_string(timeout, start, end - start + 1);
		if (sscanf(timeout, "%u", &session->closing_timeout) != 1) {
			ast_log(LOG_ERROR, "Could not read client session closing "
				"timeout: %s", timeout);
			return 0;
		}
	}

	start = end + 1;
	/* server supported transports */
	session->transports = ast_strdup(start);
	return size * nmemb;
}

static enum ast_socket_io_result socket_io_client_session_establish(
	struct ast_socket_io_session *session)
{
	char curl_error[CURL_ERROR_SIZE];
	CURL *curl = curl_easy_init();
	struct ast_str *uri;

	if (!curl) {
		ast_log(LOG_ERROR, "Unable to initialize http client\n");
		return SOCKET_IO_HTTP_ERROR;
	}

	if (!(uri = ast_str_create(128))) {
		ast_log(LOG_ERROR, "Unable to allocate client connection uri\n");
		curl_easy_cleanup(curl);
		return SOCKET_IO_ALLOC_ERROR;
	}

	ast_str_set(&uri, 0, "%s://%s:%s/socket.io/%s",
		    ast_uri_scheme(session->uri), ast_uri_host(session->uri),
		    ast_uri_port(session->uri), SOCKET_IO_VERSION);

	if (!ast_strlen_zero(ast_uri_query(session->uri))) {
		ast_str_append(&uri, 0, "/?%s", ast_uri_query(session->uri));
	}

	curl_easy_setopt(curl, CURLOPT_URL, ast_str_buffer(uri));
	curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, session);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, client_session_create);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_error);

	if (curl_easy_perform(curl)) {
		ast_log(LOG_ERROR, "Socket IO [curl]: %s\n", curl_error);
		curl_easy_cleanup(curl);
		ast_free(uri);
		return SOCKET_IO_HTTP_ERROR;
	}

	curl_easy_cleanup(curl);
	ast_free(uri);

	if (ast_strlen_zero(session->transports)) {
		ast_log(LOG_ERROR, "Unable to establish client session\n");
		return SOCKET_IO_HTTP_ERROR;
	}
	return SOCKET_IO_OK;
}

enum ast_socket_io_result ast_socket_io_client_connect(
	struct ast_socket_io_session *session, const char *transports)
{
	enum ast_socket_io_result res;

	if ((res = socket_io_client_session_establish(session)) != SOCKET_IO_OK) {
		return res;
	}

	if (ast_strlen_zero(transports)) {
		/* if none is given then default to websocket */
		transports = "websocket";
	}

	ao2_cleanup(session->transport);
	if (!(session->transport = socket_io_transport_match(
		      transports, session->transports))) {
		return SOCKET_IO_NO_TRANSPORT;
	}

	/* session established and a supported transport found
	   now initialize the transport */
	if (!(session->transport->obj =
	     session->transport->transport->init(session))) {
		ast_log(LOG_ERROR, "Unable to initialize transport type '%s'\n",
			session->transport->transport->type);
		return SOCKET_IO_NO_TRANSPORT;
	}

	/* connect the namespace(s) */
	ao2_callback(session->namespaces, OBJ_NODATA,
		     socket_io_namespace_connect, NULL);

	if ((res = socket_io_schedule_heartbeat(session)) != SOCKET_IO_OK) {
		ast_log(LOG_WARNING, "Unable to schedule heartbeart on client "
			"host '%s'\n", ast_uri_host(session->uri));
		return res;
	}

	return SOCKET_IO_OK;
}

static int load_module(void)
{
	if ((!(sched = ast_sched_context_create()))) {
		return AST_MODULE_LOAD_FAILURE;
	}

	if (ast_sched_start_thread(sched)) {
		ast_sched_context_destroy(sched);
		return AST_MODULE_LOAD_FAILURE;
	}

	curl_global_init(CURL_GLOBAL_ALL);
	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_sched_context_destroy(sched);
	curl_global_cleanup();
	return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS | AST_MODFLAG_LOAD_ORDER, "Socket IO Support",
		.support_level = AST_MODULE_SUPPORT_EXTENDED,
		.load = load_module,
		.unload = unload_module,
		.load_pri = AST_MODPRI_DEFAULT - 1,
);
