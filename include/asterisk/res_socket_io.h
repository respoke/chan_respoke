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

#ifndef _RES_SOCKET_IO_H
#define _RES_SOCKET_IO_H

#include "asterisk/linkedlists.h"

struct ast_uri;
struct ast_json;
struct ast_module_info;
struct ast_str;

#define SOCKET_IO_VERSION "1"

/*! \brief Socket IO session. */
struct ast_socket_io_session;

/*!
 * \brief Create a socket IO session.
 *
 * \param uri the uri to connect to
 * \retval a socket IO client session or NULL on failure.
 */
struct ast_socket_io_session *ast_socket_io_create(
	const char *uri);

/*!
 * \brief Retrieve the session's id.
 *
 * \param session a socket IO session
 * \retval the session id.
 */
const char *ast_socket_io_id(const struct ast_socket_io_session *session);

/*!
 * \brief Retrieve the session's uri.
 *
 * \param session a socket IO session
 * \retval the uri object associated with the session.
 */
struct ast_uri *ast_socket_io_uri(
	const struct ast_socket_io_session *session);

/*!
 * \brief Set the session to stop.
 *
 * \param session a socket IO session
 */
void ast_socket_io_stop(struct ast_socket_io_session *session);

/*! A socket IO transport. */
struct ast_socket_io_transport {
	/*! type of transport */
	const char *type;
	/*!
	 * \brief Initialize the transport.
	 *
	 * \note The returned pointer needs to be an 'ao2' allocated object as
	 *       it will be released upon transport destruction.
	 */
	void *(*init)(const struct ast_socket_io_session *session);
	/*!
	 * \brief Send data over the transport.
	 */
	int (*send)(void *obj, const char *buf);
	/*!
	 * \brief Receive data over the transport.
	 */
	int (*recv)(void *obj, char **buf, unsigned int timeout_secs);
	/*!
	 * \brief Retrieves the transport's module.
	 */
	const struct ast_module_info *(*module_info)(void);
	/*! list item pointer */
	AST_RWLIST_ENTRY(ast_socket_io_transport) item;
};

/*!
 * \brief Register a transport to use with socket IO.
 *
 * \param transport the transport to register
 * \retval -1 on error, 0 otherwise.
 */
int ast_socket_io_transport_register(struct ast_socket_io_transport *transport);

/*!
 * \brief Unregister a transport from socket IO.
 *
 * \param transport the transport to unregister
 */
void ast_socket_io_transport_unregister(struct ast_socket_io_transport *transport);

/*!
 * \brief Structure for a socket IO namespace.
 *
 * \details A namespace maintains a list of associated registered event
 *          callbacks that get called when a message containing the given
 *          name is received. Any of the specific structured events
 *          may also be overridden per implementation.
 */
struct ast_socket_io_namespace {
	/*! The session for the namespace */
	struct ast_socket_io_session *session;
	/*! dictionary of registered named events */
	struct ao2_container *events;
	/*! called when a server disconnects */
	void (*on_disconnect)(struct ast_socket_io_namespace *ns);
	/*! called when a server connects */
	void (*on_connect)(struct ast_socket_io_namespace *ns);
	/*! called when a heartbeat is received */
	void (*on_heartbeat)(struct ast_socket_io_namespace *ns);
	/*! called when a message containing string data is received */
	void (*on_message)(struct ast_socket_io_namespace *ns, struct ast_str *data);
	/*! called when a message containing json data is received */
	void (*on_json)(struct ast_socket_io_namespace *ns, struct ast_json *data);
	/*! called when an error occurred */
	void (*on_error)(struct ast_socket_io_namespace *ns, const char *reason,
			 const char *advice);
	/*! no operation (for example: used to close a poll) */
	void (*on_noop)(struct ast_socket_io_namespace *ns);
	/*! A data object to associate with the namespace */
	void *obj;
	/*! path name for the namespace */
	char path[0];
};

/*!
 * \brief Create a namespace.
 *
 * \note If a data object is not given the created namespace is used and will be
 *       passed to all callbacks as obj.
 *
 * \param path the path name used to associate incoming messages to the namespace
 * \param obj a data object to associate with the namespace
 * \retval A namespace object or NULL on error.
 */
struct ast_socket_io_namespace *ast_socket_io_namespace_create(
	const char *path, void *obj);

/*!
 * \brief Callback for when an event message is received.
 *
 * \param ns the namespace the event was received in
 * \param data string data received
 * \param obj an object that was associated with the event
 */
typedef void (*ast_socket_io_event)(struct ast_socket_io_namespace *ns,
				    struct ast_json *data, void *obj);

/*!
 * \brief Add an event callback to a namespace.
 *
 * \param ns the namespace to add the event to
 * \param name the key name associated with the callback
 * \param callback the function raised when the named event is received
 * \retval -1 if unable to register.
 */
int ast_socket_io_namespace_event_add(struct ast_socket_io_namespace *ns, const char *name,
				      ast_socket_io_event callback);

/*!
 * \brief Remove an event callback from a namespace.
 *
 * \param ns the namespace to remove the event from
 * \param name the key name associated with the callback
 */
void ast_socket_io_namespace_event_remove(struct ast_socket_io_namespace *ns,
					  const char *name);

/*!
 * \brief Add a namespace to the session.
 *
 * \param session the socket io session
 * \param ns the namespace to add
 * \retval -1 if namespace can not be added.
 */
int ast_socket_io_namespace_add(
	struct ast_socket_io_session *session, struct ast_socket_io_namespace *ns);

/*!
 * \brief Remove a namespace from the session.
 *
 * \param session the socket io session
 * \param ns the namespace to remove
 * \retval -1 if namespace can not be removed or disconnected.
 */
int ast_socket_io_namespace_remove(
	struct ast_socket_io_session *session, struct ast_socket_io_namespace *ns);

/*! \brief Result codes for socket IO. */
enum ast_socket_io_result {
	/*! result is okay */
	SOCKET_IO_OK,
	/*! a heartbeat scheduling error has occurred */
	SOCKET_IO_SCHED_ERROR,
	/*! a transport cannot be found */
	SOCKET_IO_NO_TRANSPORT,
	/*! unable to convert value (string->int, int->string, etc...) */
	SOCKET_IO_CONVERSION_ERROR,
	/*! could not create event */
	SOCKET_IO_BAD_EVENT,
	/*! could not create/allocate memory */
	SOCKET_IO_ALLOC_ERROR,
	/*! error while sending data over a transport */
	SOCKET_IO_SEND_ERROR,
	/*! error while receiving/reading data from a transport */
	SOCKET_IO_RECV_ERROR,
	/*! packet received was malformed */
	SOCKET_IO_INVALID_PACKET,
	/*! the session is not available */
	SOCKET_IO_NO_SESSION,
	/*! error handling json */
	SOCKET_IO_JSON_ERROR,
	/*! error while connecting http */
	SOCKET_IO_HTTP_ERROR,
};

/*!
 * \brief Send a message.
 *
 * \note if a callback is given then it will be raised upon response receipt.
 * \note the data object associated with the callback must be an ao2 object.
 *
 * \param ns the namespace
 * \param data the data to send
 * \param callback a callback to call when a response is received
 * \param obj an ao2 object to associate with the callback (passed to callback)
 * \retval SOCKET_IO_OK if client connected.
 * \retval on failure a SOCKET_IO_[NO_SESSION | NO_TRANSPORT |
 *          CONVERSION_ERROR | BAD_EVENT | ALLOC_ERROR]
 */
enum ast_socket_io_result ast_socket_io_message(
	struct ast_socket_io_namespace *ns, const char *data,
	ast_socket_io_event callback, void *obj);

/*!
 * \brief Send a JSON formatted message.
 *
 * \note if a callback is given then it will be raised upon response receipt.
 * \note the data object associated with the callback must be an ao2 object.
 *
 * \param ns the namespace
 * \param data the data to send
 * \param callback a callback to call when a response is received
 * \param obj an ao2 object to associate with the callback (passed to callback)
 * \retval SOCKET_IO_OK if client connected.
 * \retval on failure a SOCKET_IO_[NO_SESSION | NO_TRANSPORT |
 *          CONVERSION_ERROR | BAD_EVENT | ALLOC_ERROR | JSON_ERROR]
 */
enum ast_socket_io_result ast_socket_io_json(
	struct ast_socket_io_namespace *ns, struct ast_json *data,
	ast_socket_io_event callback, void *obj);

/*!
 * \brief Emit a message.
 *
 * \details Similar to sending a regular JSON message except that the data is
 *          contained within a JSON object that has the following format:
 *          { name : args }.
 *
 * \note if a callback is given then it will be raised upon response receipt.
 * \note the data object associated with the callback must be an ao2 object.
 *
 * \param ns the namespace
 * \param name the key name for the associated arguments
 * \param args optional arguments to send
 * \param callback a callback to call when a response is received
 * \param obj an ao2 object to associate with the callback (passed to callback)
 * \retval SOCKET_IO_OK if client connected.
 * \retval on failure a SOCKET_IO_[NO_SESSION | NO_TRANSPORT |
 *          CONVERSION_ERROR | BAD_EVENT | ALLOC_ERROR | JSON_ERROR]
 */
enum ast_socket_io_result ast_socket_io_emit(
	struct ast_socket_io_namespace *ns, const char *name,
	struct ast_json *args, ast_socket_io_event callback, void *obj);

/*!
 * \brief Send a acknowledgment.
 *
 * \note If 'args' is specified a more complex acknowledgment is sent that
 *       contains those arguments.
 *
 * \param ns the namespace
 * \param id the message id
 * \param args optional arguments to associate with the acknowledgment
 * \retval SOCKET_IO_OK if client connected.
 * \retval on failure a SOCKET_IO_[NO_SESSION | NO_TRANSPORT |
 *          CONVERSION_ERROR | ALLOC_ERROR | JSON_ERROR]
 */
enum ast_socket_io_result ast_socket_io_ack(
	struct ast_socket_io_namespace *ns, const char *id, struct ast_json *args);

/*!
 * \brief Send a 'no operation'.
 *
 * \param ns the namespace
 * \retval SOCKET_IO_OK if client connected.
 * \retval on failure a SOCKET_IO_[NO_SESSION | NO_TRANSPORT |
 *          CONVERSION_ERROR | ALLOC_ERROR]
 */
enum ast_socket_io_result ast_socket_io_noop(struct ast_socket_io_namespace *ns);

/*!
 * \brief Socket IO session's blocking read, evaluate, print/process loop.
 *
 * \detail Continually read and evaluate incoming messages and dispatch them
 *         to the appropriate handlers.
 *
 * \param session the socket io session
 * \retval a SOCKET_IO_RECV_ERROR result if there is a problem.
 */
enum ast_socket_io_result ast_socket_io_repl(
	struct ast_socket_io_session *session);

/*!
 * \brief Connect the client session to a socket IO server.
 *
 * \note Blocks while connecting.
 *
 * \param client the socket io client session
 * \param transports a comma separated list of client supported transports
 * \retval SOCKET_IO_OK if client connected.
 * \retval SOCKET_IO_[HTTP_ERROR | NO_TRANSPORT | ALLOC_ERROR] on failure.
 */
enum ast_socket_io_result ast_socket_io_client_connect(
	struct ast_socket_io_session *session, const char *transports);

#endif /* _RES_SOCKET_IO_H */
