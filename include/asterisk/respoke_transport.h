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

#ifndef RESPOKE_TRANSPORT_H_
#define RESPOKE_TRANSPORT_H_

#include "asterisk/sorcery.h"
#include "asterisk/stringfields.h"

struct ast_json;

/*! \brief Transport state. */
struct respoke_transport_state;

/*!
 * \brief Transport definition.
 */
struct respoke_transport {
	/*! Sorcery object details */
	SORCERY_OBJECT(details);

	AST_DECLARE_STRING_FIELDS(
		/*! Protocol type of transport to use */
		AST_STRING_FIELD(protocol);
		/*! Location to connect to */
		AST_STRING_FIELD(uri);
		/*! The App-Secret to use */
		AST_STRING_FIELD(app_secret);
		/*! API Location to connect to */
		AST_STRING_FIELD(uri_api);
		);
	/*! State associated with a transport */
	struct respoke_transport_state *state;
};

/*!
 * \brief Current status of the transport
 */
enum respoke_transport_status {
	RESPOKE_TRANSPORT_STATUS_INITIALIZATING,
	RESPOKE_TRANSPORT_STATUS_DISCONNECTED,
	RESPOKE_TRANSPORT_STATUS_CONNECTED,
};

/*!
 * \brief Retrieve the state data associated with the transport.
 *
 * \param transport a transport
 * \retval the transport state's data object.
 */
void *respoke_transport_state_data(const struct respoke_transport *transport);

/*! \brief Callback invoked on transport status changes */
typedef void (*respoke_transport_callback)(struct respoke_transport *transport, void *data,
	enum respoke_transport_status status);

/*! \brief Callback invoked on receiving a response to a message */
typedef void (*respoke_transport_response_callback)(void *obj, struct ast_json *json);

/*!
 * \brief Protocol interface to Respoke transports.
 */
struct respoke_transport_protocol {
	/*! Type of transport */
	const char *type;
	/*! Create a transport protocol */
	void *(*create)(const struct respoke_transport *transport);
	/*! Start the transport protocol */
	int (*start)(const struct respoke_transport *transport);
	/*! Callback function to send/emit a message */
	int (*emit_message)(const struct respoke_transport *transport,
			    const char *name, const struct ast_json *json,
			    respoke_transport_response_callback callback, void *obj);
};

/*!
 * \brief Create an individual transport instance using the provided transport configuration
 *
 * \param transport The transport configuration to use
 * \retval non-NULL success
 * \retval NULL failure
 */
struct respoke_transport_state *respoke_transport_create_instance(struct respoke_transport *transport);

/*!
 * \brief Start a transport
 *
 * \param transport The transport itself
 * \retval 0 Success
 * \retval -1 Failure
 */
int respoke_transport_start(struct respoke_transport *transport);

/*!
 * \brief Invoke callbacks present on a transport for a status change
 *
 * \param transport The transport itself
 * \param status The status of the transport
 */
void respoke_transport_invoke_callback(struct respoke_transport *transport, enum respoke_transport_status status);

/*!
 * \brief Set a callback to be invoked on transport status changes (connected/disconnected)
 *
 * \param state The transport state structure
 * \param callback The callback to invoke
 * \param data AO2 reference counted object to pass to the callback
 */
void respoke_transport_set_callback(struct respoke_transport_state *state,
	respoke_transport_callback callback, void *data);

/*!
 * \brief Register a Respoke transport protocol.
 *
 * \param protocol The protocol to register
 * \retval 0 Success
 * \retval -1 Failure
 */
int respoke_register_transport_protocol(const struct respoke_transport_protocol *protocol);

/*!
 * \brief Unregister a Respoke transport protocol.
 *
 * \param protocol The protocol to unregister
 */
void respoke_unregister_transport_protocol(const struct respoke_transport_protocol *protocol);

/*!
 * \brief Emit a message out a Respoke transport
 *
 * \param transport The transport to send out on
 * \param name the name for the json argument
 * \param json the json to send/emit
 * \param callback optional callback which is invoked when a response to this message occurs
 * \param obj optional object to pass to the above callback
 * \retval 0 Success
 * \retval -1 Failure
 */
int respoke_transport_emit(struct respoke_transport *transport, const char *name,
			   const struct ast_json *json, respoke_transport_response_callback callback,
			   void *obj);

/*!
 * \brief Initialize the respoke transport unit.
 *
 * \retval -1 if initialization failed, 0 if successful.
 */
int respoke_transport_initialize(void);

/*!
 * \brief De-initialize the transport unit.
 */
void respoke_transport_deinitialize(void);

/*!
 * \brief Initialize the socket IO transport protocol.
 *
 * \retval -1 if initialization failed, 0 if successful.
 */
int respoke_transport_socket_io_initialize(void);

/*!
 * \brief De-initialize the socket IO transport protocol.
 */
void respoke_transport_socket_io_deinitialize(void);

#endif /* RESPOKE_TRANSPORT_H_ */
