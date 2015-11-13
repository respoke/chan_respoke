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

#ifndef RESPOKE_MESSAGE_H_
#define RESPOKE_MESSAGE_H_

#include "asterisk/stringfields.h"
#include "respoke_transaction.h"

struct ast_json;
struct ast_format_cap;
struct ast_rtp_codecs;
struct ast_rtp_instance;
struct ast_sockaddr;

struct respoke_endpoint;
struct respoke_transport;

/*!
 * \brief Respoke status types.
 */
enum respoke_status {
	RESPOKE_STATUS_FINAL,
	RESPOKE_STATUS_RINGING,
	RESPOKE_STATUS_BUSY,
	RESPOKE_STATUS_UNAVAILABLE,
	RESPOKE_STATUS_INCOMPLETE,
	RESPOKE_STATUS_TRYING,
	RESPOKE_STATUS_PROGRESS,
	RESPOKE_STATUS_REDIRECTING,
	RESPOKE_STATUS_HANGUP,
	RESPOKE_STATUS_DISCONNECTED,
	RESPOKE_STATUS_UNKNOWN
};

/*!
 * \brief Convert the given string to a status type.
 *
 * \param status a string version of the type
 * \retval A status type
 */
enum respoke_status respoke_str_to_status(const char *status);

/*!
 * \brief Convert the given status type to a string.
 *
 * \param status the status to convert
 * \retval A type string.
 */
const char *respoke_status_to_str(enum respoke_status status);

/*!
 * \brief Convert a string media type to equivalent enumeration.
 *
 * \param type the type to convert
 * \retval A matching enumeration for the given type, 0 otherwise.
 */
enum ast_media_type respoke_str_to_media_type(const char *type);

/*!
 * \brief A Respoke signaling message
 */
struct respoke_message {
	/*! Associated endpoint */
	struct respoke_endpoint *endpoint;
	/*! Transport the message was received on */
	struct respoke_transport *transport;
	/*! Un-parsed version of the message */
	char *contents;
	/*! Any HTTP request headers */
	struct ast_variable *headers;
	/*! JSON version of the message */
	struct ast_json *json;
	/*! The URL to send the message to */
	char *url;
	/*! Whether this message has a sail wrapper or not */
	unsigned int sailed;
};

/*!
 * \brief Retrieve the message type.
 *
 * \param message the message object
 * \retval The message type.
 */
const char *respoke_message_type_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the message from parameter.
 *
 * \param message the message object
 * \retval The message from parameter.
 */
const char *respoke_message_from_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the message from type.
 *
 * \param message the message object
 * \retval The message from type.
 */
const char *respoke_message_from_type_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the message from connection.
 *
 * \param message the message object
 * \retval The message from connection.
 */
const char *respoke_message_from_connection_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the message from app id.
 *
 * \param message the message object
 * \retval The message from app id.
 */
const char *respoke_message_from_appid_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the message to parameter.
 *
 * \param message the message object
 * \retval The message to parameter.
 */
const char *respoke_message_to_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the message to type.
 *
 * \param message the message object
 * \retval The message to type.
 */
const char *respoke_message_to_type_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the message to connection.
 *
 * \param message the message object
 * \retval The message to connection.
 */
const char *respoke_message_to_connection_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the message to app id.
 *
 * \param message the message object
 * \retval The message to app id.
 */
const char *respoke_message_to_appid_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the message signal type.
 *
 * \param message the message object
 * \retval The message signal type.
 */
const char *respoke_message_signal_type_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the message session id.
 *
 * \param message the message object
 * \retval The message session id.
 */
const char *respoke_message_session_id_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the message connection id.
 *
 * \param message the message object
 * \retval The message connection id.
 */
const char *respoke_message_connection_id_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the message metadata.
 *
 * \param message the message object
 * \retval The message metadata.
 */
struct ast_json *respoke_message_metadata_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the DTLS setup value from a media stream.
 *
 * \param message the message object
 * \retval the setup value.
 */
const char *respoke_message_setup_get(const struct respoke_message *message, const char *type);

/*!
 * \brief Retrieve the DTLS fingerprint hash type.
 *
 * \param message the message object
 * \retval the hash type.
 */
const char *respoke_message_fingerprint_type_get(const struct respoke_message *message, const char *type);

/*!
 * \brief Retrieve the DTLS fingerprint hash value.
 *
 * \param message the message object
 * \retval the hash value.
 */
const char *respoke_message_fingerprint_hash_get(const struct respoke_message *message, const char *type);

/*!
 * \brief Retrieve the message reason (from a "bye" message).
 *
 * \param message the message object
 * \retval The reason/status type.
 */
enum respoke_status respoke_message_reason_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the message answer.
 *
 * \param message the message object
 * \retval The message answer status.
 */
enum respoke_status respoke_message_answer_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the message status.
 *
 * \param message the message object
 * \retval The message status.
 */
enum respoke_status respoke_message_status_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the message error details.
 *
 * \param message the message object
 * \retval The message error details.
 */
const char *respoke_message_error_detail_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the if sdp address is IPv4 or not.
 *
 * \param message the message object
 * \retval True if IPv4.
 */
int respoke_message_is_ipv6(const struct respoke_message *message);

/*!
 * \brief Retrieve the media address for the given type from the
 *        SDP contained in the message.
 *
 * \param message the message object
 * \param type type of media
 * \param addr address structure to fill
 * \retval 0 on success, -1 if not found or failure.
 */
int respoke_message_media_address_get(
	const struct respoke_message *message,
	const char *type, struct ast_sockaddr *addr);

/*!
 * \brief Retrieve the codecs from the SDP contained in the message.
 *
 * \param message the message object
 * \param type type of media
 * \param codecs codecs structure to fill
 * \retval 0 on success, -1 if not found or failure.
 */
int respoke_message_codecs_get(
	const struct respoke_message *message, const char *type,
	struct ast_rtp_codecs *codecs);

/*!
 * \brief Retrieve the ice ufrag from the SDP contained in the message.
 *
 * \param message the message object
 * \param type type of media
 * \retval The message ice ufrag value or NULL if not found.
 */
const char *respoke_message_ice_ufrag_get(
	const struct respoke_message *message, const char *type);

/*!
 * \brief Retrieve the ice password from the SDP contained in the message.
 *
 * \param message the message object
 * \param type type of media
 * \retval The message ice password value or NULL if not found.
 */
const char *respoke_message_ice_pwd_get(
	const struct respoke_message *message, const char *type);

/*!
 * \brief Retrieve the message ice candidates.
 *
 * \param message the message object
 * \param type type of media
 * \param instance rtp instance to add candidates to
 * \retval 0 on success, -1 on error.
 */
int respoke_message_ice_candidates_get(
	const struct respoke_message *message, const char *type,
	struct ast_rtp_instance *instance);

/*!
 * \brief Retrieve the endpoint that a session has been redirected to.
 *
 * \param message the message object
 * \retval The name of the endpoint.
 */
const char *respoke_message_redirected_endpoint_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the endpoint type that a session has been redirected to.
 *
 * \param message the message object
 * \retval The type of the endpoint.
 */
const char *respoke_message_redirected_type_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the app that a session has been redirected to.
 *
 * \param message the message object
 * \retval The name of the app.
 */
const char *respoke_message_redirected_app_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the callerid name within a message.
 *
 * \param emssage the message object
 * \retval The callerid name if present.
 */
const char *respoke_message_callerid_name_get(const struct respoke_message *message);

/*!
 * \brief Retrieve the callerid number within a message.
 *
 * \param emssage the message object
 * \retval The callerid number if present.
 */
const char *respoke_message_callerid_number_get(const struct respoke_message *message);

/*!
 * \brief Interface to Respoke message handlers
 */
struct respoke_message_handler {
	/*! A comma separated list of types of messages this handler handles */
	const char *types;
	/*! A comma separated list of signal types this handler handles (optional) */
	const char *signaltypes;
	/*! Callback for when a message is received matching the above types, returns non-NULL if handled */
	unsigned int (*receive_message)(struct respoke_transaction *transaction, struct respoke_message *message);
};

/*!
 * \brief Register a Respoke message handler
 *
 * \param handler The handler to register
 * \retval 0 Success
 * \retval -1 Failure
 */
int respoke_register_message_handler(const struct respoke_message_handler *handler);

/*!
 * \brief Unregister a Respoke message handler
 *
 * \param handler The handler to unregister
 */
void respoke_unregister_message_handler(const struct respoke_message_handler *handler);

/*!
 * \brief Allocate a message
 *
 * \param transport associated transport
 * \param contents the message data: form of string
 * \param json the message data: form of json
 * \param endpoint associated endpoint
 * \param url url to send the message to
 *
 * \retval non-NULL success
 * \retval NULL failure
 */
struct respoke_message *respoke_message_alloc(
	struct respoke_transport *transport, const char *contents,
	struct ast_json *json, struct respoke_endpoint *endpoint,
	const char *url);

/*!
 * \brief Receive and dispatch a transaction+message to the threadpool for handling
 *
 * \param transaction The transaction with the message
 */
void respoke_message_receive(struct respoke_transaction *transaction);

/*!
 * \brief Set an HTTP header on a message.
 *
 * \param message the message to set the header on
 * \param name the name of the header
 * \param value the value of the header
 * \retval 0 on success, -1 otherwise
 */
int respoke_message_set_header(struct respoke_message *message, const char *name,
	const char *value);

/*!
 * \brief Retrieve the value of an HTTP header on a message.
 *
 * \param message the message to get the header from
 * \param name the name of the header
 * \retval non-NULL if found, NULL if not found
 */
const char *respoke_message_get_header(const struct respoke_message *message,
	const char *name);

/*!
 * \brief Wrap/Create the final object for sending.
 *
 * \param message the message containing the object to wrap
 * \retval 0 on success, -1 otherwise
 */
int respoke_message_sail(struct respoke_message *message);

/*!
 * \brief Send a message out
 *
 * \param message The message itself
 * \param callback Optional callback that is invoked when transaction state changes occur
 * \param obj Optional object to pass to the above callback (must be ao2)
 *
 * \retval 0 success
 * \retval -1 failure
 */
int respoke_message_send(struct respoke_message *message, respoke_transaction_callback callback,
	void *obj);

/*!
 * \brief Send a message and then free it.
 *
 * \param message The message to send
 * \param callback Optional callback that is invoked when transaction state changes occur
 * \param obj Optional object to pass to the above callback (must be ao2)
 *
 * \retval 0 success
 * \retval -1 failure
 */
int respoke_message_send_and_release(struct respoke_message *message, respoke_transaction_callback callback,
	void *obj);

/*!
 * \brief Create and send an error message.
 *
 * \param transport the transport to associate with the message
 * \param endpoint an endpoint to associate with the message
 * \param callback Optional callback that is invoked when transaction state changes occur
 * \param obj Optional object to pass to the above callback (must be ao2)
 * \param from the from address
 * \param from_type the type of resource of the from address
 * \param from_connection the from connection
 * \param to the to address
 * \param to_type the type of resource of the to address
 * \param to_connection the to connection
 * \param to_appid the to application id
 * \param format detailed error information
 *
 * \retval 0 success
 * \retval -1 failure
 */
int respoke_message_send_error_va(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint,
	respoke_transaction_callback callback, void *obj,
	const char *from, const char *from_type,
	const char *from_connection, const char *to, const char *to_type,
	const char *to_connection, const char *to_appid, const char *session_id,
	const char *format, va_list ap)	__attribute__((format(printf, 10, 0)));

/*!
 * \brief Create and send an error message.
 *
 * \param transport the transport to associate with the message
 * \param endpoint an endpoint to associate with the message
 * \param callback Optional callback that is invoked when transaction state changes occur
 * \param obj Optional object to pass to the above callback (must be ao2)
 * \param from the from address
 * \param from_type the type of resource of the from address
 * \param from_connection the from connection
 * \param to the to address
 * \param to_type the type of resource of the to address
 * \param to_connection the to connection
 * \param to_appid the to application id
 * \param format detailed error information
 *
 * \retval 0 success
 * \retval -1 failure
 */
int respoke_message_send_error(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint,
	respoke_transaction_callback callback, void *obj,
	const char *from, const char *from_type,
	const char *from_connection, const char *to, const char *to_type,
	const char *to_connection, const char *to_appid, const char *session_id,
	const char *format, ...) __attribute__((format(printf, 13, 14)));

/*!
 * \brief Create and send a generic error message.
 *
 * \param message The message used to build the error
 * \param callback Optional callback that is invoked when transaction state changes occur
 * \param obj Optional object to pass to the above callback (must be ao2)
 * \param detail The reason for the error message
 *
 * \retval 0 success
 * \retval -1 failure
 */
int respoke_message_send_error_from_message(
	const struct respoke_message *message,
	respoke_transaction_callback callback, void *obj,
	const char *format,
	...) __attribute__((format(printf, 4, 5)));

/*!
 * \brief Create an offer message from the given session.
 *
 * \param transport the transport to associate with the message
 * \param endpoint an endpoint to associate with the message
 * \param rtp_ipv6 is the address ipv6 or not
 * \param from the from address
 * \param from_type the type of resource of the from address
 * \param from_connection the from connection
 * \param to the to address
 * \param to_type the type of resource of the to address
 * \param to_connection the to connection
 * \param to_appid the to application id
 * \param session_id the id of the session
 * \param caps the session capabilities
 * \param audio_rtp the audio rtp instance
 * \param video_rtp the video rtp instance
 * \param callerid_name name to put as the callerid name
 * \param callerid_number number to put as the callerid number
 * \retval An offer message, NULL otherwise.
 */
struct respoke_message *respoke_message_create_offer(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint,
	int rtp_ipv6, const char *from, const char *from_type,
	const char *from_connection, const char *to, const char *to_type,
	const char *to_connection, const char *to_appid, const char *session_id,
	struct ast_format_cap *caps, struct ast_rtp_instance *audio_rtp,
	struct ast_rtp_instance *video_rtp, const char *callerid_name,
	const char *callerid_number);

/*!
 * \brief Create an answer message from the given session.
 *
 * \param transport the transport to associate with the message
 * \param endpoint an endpoint to associate with the message
 * \param rtp_ipv6 is the address ipv6 or not
 * \param from the from address
 * \param from_type the type of resource of the from address
 * \param from_connection the from connection
 * \param to the to address
 * \param to_type the type of resource of the to address
 * \param to_connection the to connection
 * \param to_appid the to application id
 * \param session_id the id of the session
 * \param caps the session capabilities
 * \param audio_rtp the audio rtp instance
 * \param video_rtp the video rtp instance
 * \retval An answer message, NULL otherwise.
 */
struct respoke_message *respoke_message_create_answer(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint,
	int rtp_ipv6, const char *from, const char *from_type,
	const char *from_connection, const char *to, const char *to_type,
	const char *to_connection, const char *to_appid, const char *session_id,
	struct ast_format_cap *caps, struct ast_rtp_instance *audio_rtp,
	struct ast_rtp_instance *video_rtp);

/*!
 * \brief Create a status message from the given session.
 *
 * \param transport the transport to associate with the message
 * \param endpoint an endpoint to associate with the message
 * \param from the from address
 * \param from_type the type of resource of the from address
 * \param from_connection the from connection
 * \param to the to address
 * \param to_type the type of resource of the to address
 * \param to_connection the to connection
 * \param to_appid the to application id
 * \param session_id the id of the session
 * \param status the status value to use
 * \retval A status message, NULL otherwise.
 */
struct respoke_message *respoke_message_create_status(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint,
	const char *from, const char *from_type,
	const char *from_connection, const char *to, const char *to_type,
	const char *to_connection, const char *to_appid, const char *session_id,
	enum respoke_status status);

/*!
 * \brief Create a bye message from the given session.
 *
 * \param transport the transport to associate with the message
 * \param endpoint an endpoint to associate with the message
 * \param from the from address
 * \param from_type the type of resource of the from address
 * \param from_connection the from connection
 * \param to the to address
 * \param to_type the type of resource of the to address
 * \param to_connection the to connection
 * \param to_appid the to application id
 * \param session_id the id of the session
 * \param status the reason for the bye
 * \retval A bye message, NULL otherwise.
 */
struct respoke_message *respoke_message_create_bye(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint,
	const char *from, const char *from_type,
	const char *from_connection, const char *to, const char *to_type,
	const char *to_connection, const char *to_appid, const char *session_id,
	enum respoke_status status);

/*!
 * \brief Create an error message from the given session.
 *
 * \param transport the transport to associate with the message
 * \param endpoint an endpoint to associate with the message
 * \param from the from address
 * \param from_type the type of resource of the from address
 * \param from_connection the from connection
 * \param to the to address
 * \param to_type the type of resource of the to address
 * \param to_connection the to connection
 * \param to_appid the to application id
 * \param session_id the id of the session
 * \param detail the error details
 * \retval An error message, NULL otherwise.
 */
struct respoke_message *respoke_message_create_error(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint,
	const char *from, const char *from_type,
	const char *from_connection, const char *to, const char *to_type,
	const char *to_connection, const char *to_appid, const char *session_id,
	const char *detail);

#endif /* RESPOKE_MESSAGE_H_ */
