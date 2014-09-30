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

struct ast_channel;
struct ast_format_cap;
struct ast_rtp_instance;
struct ast_taskprocessor;

struct respoke_endpoint;
struct respoke_message;
enum respoke_status;

/*!
 * \brief Respoke session.
 */
struct respoke_session {
	AST_DECLARE_STRING_FIELDS(
		/*! the local target/exten */
		AST_STRING_FIELD(local);
		/*! the local resource type */
		AST_STRING_FIELD(local_type);
		/*! the local connection id */
		AST_STRING_FIELD(local_connection);
		/*! the remote target */
		AST_STRING_FIELD(remote);
		/*! the remote resource type */
		AST_STRING_FIELD(remote_type);
		/*! the remote connection */
		AST_STRING_FIELD(remote_connection);
		/*! the remote application */
		AST_STRING_FIELD(remote_appid);
		/*! the unique session identifier */
		AST_STRING_FIELD(session_id);
	);
	/*! underlying transport being used */
	struct respoke_transport *transport;
	/*! an associated endpoint */
	struct respoke_endpoint *endpoint;
	/*! whether or not addressing is ipv6 */
	unsigned int rtp_ipv6;
	/*! audio rtp instance */
	struct ast_rtp_instance *audio_rtp;
	/*! video rtp instance */
	struct ast_rtp_instance *video_rtp;
	/*! true if the session should be terminated */
	unsigned int terminated;
	/*! current message data */
	struct ast_taskprocessor *serializer;
	/*! the active channel */
	struct ast_channel *channel;
	/*! valid capabilities for the session */
	struct ast_format_cap *capabilities;
	/* session endpoint identity */
	struct ast_party_id party_id;
};

/*!
 * \brief Create a session object.
 *
 * \param transport the transport to associate with the session
 * \param endpoint an endpoint to associate with the session
 * \param from the from address
 * \param from_type the type of resource of the from address
 * \param from_connection the from connection
 * \param to the to address
 * \param to_type the type of resource of the to address
 * \param to_connection the to connection
 * \param to_appid the to application id
 * \param session_id the id of the session
 * \param caps capabilities the session possibly supports
 * \retval A session object.
 */
struct respoke_session *respoke_session_create(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint,
	const char *from, const char *from_type, const char *from_connection,
	const char *to, const char *to_type, const char *to_connection,
	const char *to_appid, const char *session_id, struct ast_format_cap *caps);

/*!
 * \brief Retrieve the incoming dialplan destination extension.
 *
 * \param session a session object
 * \retval The destination extension.
 */
const char *respoke_session_get_exten(const struct respoke_session *session);

/*!
 * \brief Session handling callbacks.
 */
struct respoke_session_handler {
	/*! Raised when a session receives an offer message */
	int (*on_offer)(struct respoke_session *session);
	/*! Raised when a session receives an answer message */
	int (*on_answer)(struct respoke_session *session, enum respoke_status status);
	/*! Raised when a session receives a status message */
	int (*on_status)(struct respoke_session *session, enum respoke_status status);
	/*! Raised when a session is ending (receives a bye message) */
	int (*on_end)(struct respoke_session *session, enum respoke_status status, const struct respoke_message *message);
	/*! The next item in the list */
	AST_RWLIST_ENTRY(respoke_session_handler) item;
};

/*!
 * \brief Register a session handler.
 *
 * \param handler a session handler to register
 * \retval 0 on success, -1 on failure
 */
int respoke_session_register_handler(struct respoke_session_handler *handler);

/*!
 * \brief Unregister a session handler.
 *
 * \param handler a session handler to unregister
 */
void respoke_session_unregister_handler(struct respoke_session_handler *handler);

/*!
 * \brief Send an offer using the the given session.
 *
 * \param session the session in which to send the offer
 * \retval 0 on success, -1 on failure
 */
int respoke_session_offer(struct respoke_session *session);

/*!
 * \brief Answer an offer on the given session.
 *
 * \param session the session in which to send the answer
 * \retval 0 on success, -1 on failure
 */
int respoke_session_answer(struct respoke_session *session);

/*!
 * \brief Send a status message on the session.
 *
 * \param session the session in which to send the status
 * \param status the status
 * \retval 0 on success, -1 on failure
 */
int respoke_session_status(struct respoke_session *session, enum respoke_status status);

/*!
 * \brief Signal a "bye" on the session.
 *
 * \param session the session in which to send the bye
 * \param status the reason for the bye
 * \retval 0 on success, -1 on failure
 */
int respoke_session_bye(struct respoke_session *session, enum respoke_status status);

/*!
 * \brief Send an error on the session.
 *
 * \param session the session in which to send the error
 * \param format the error message
 * \retval 0 on success, -1 on failure
 */
int respoke_session_error(const struct respoke_session *session,
			 const char *format, ...)  __attribute__((format(printf, 2, 3)));

/*!
 * \brief Send a session message
 *
 * \param message The message itself
 * \param callback Optional callback that is invoked when transaction state changes occur
 * \param obj Optional object to pass to the above callback (must be ao2)
 *
 * \retval 0 success
 * \retval -1 failure
 */
int respoke_session_message_send(struct respoke_session *session, struct respoke_message *message);

/*!
 * \brief Send a session message and then free it.
 *
 * \param session The session to send the message on
 * \param message The message to send
 *
 * \retval 0 success
 * \retval -1 failure
 */
int respoke_session_message_send_and_release(struct respoke_session *session, struct respoke_message *message);
