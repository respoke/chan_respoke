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

#ifndef RESPOKE_ENDPOINT_H_
#define RESPOKE_ENDPOINT_H_

#include "asterisk/netsock2.h"
#include "asterisk/sorcery.h"
#include "asterisk/stringfields.h"
#include "asterisk/rtp_engine.h"
#include "asterisk/channel.h"

struct respoke_message;
struct respoke_app;

/*!
 * \brief Endpoint specific state information
 */
struct respoke_endpoint_state {
	/*! The transport the endpoint is configured with */
	struct respoke_transport *transport;
	/*! The application the endpoint is configured with */
	struct respoke_app *app;
};

/*!
 * \brief Respoke endpoint media.
 */
struct respoke_endpoint_media {
	AST_DECLARE_STRING_FIELDS(
		/*! RTP engine for an endpoint */
		AST_STRING_FIELD(rtp_engine);
		/*! The SDP session name */
		AST_STRING_FIELD(sdp_session);
		/*! The SDP origin name */
		AST_STRING_FIELD(sdp_owner);
	);
	/*! Configured codecs */
	struct ast_format_cap *codecs;
	/*! The SDP origin/media address */
	struct ast_sockaddr addr;
	/*! True if address is ipv6 */
	unsigned int rtp_ipv6;
	/*! True if TURN support should be enabled */
	unsigned int turn;
	/*! DTLS configuration */
	struct ast_rtp_dtls_cfg dtls_cfg;
};

#define RESPOKE_ENDPOINT "endpoint"

/*!
 * \brief How to handle redirects
 */
enum respoke_endpoint_redirect {
	/*! Target is as a dial string for handling */
	RESPOKE_REDIRECT_CORE,
	/*! Channel remains up and a new offer is sent to the new target */
	RESPOKE_REDIRECT_INTERNAL,
};

/*!
 * \brief Respoke endpoint.
 */
struct respoke_endpoint {
	SORCERY_OBJECT(details);
	AST_DECLARE_STRING_FIELDS(
		/*! Context to send incoming calls to */
		AST_STRING_FIELD(context);
		/*! The name of the application this endpoint is associated with */
		AST_STRING_FIELD(app_name);
		/*! Default from user to from field */
		AST_STRING_FIELD(from);
		/*! Default from type to from type field */
		AST_STRING_FIELD(from_type);
		/*! The name of the transport configuration to use */
		AST_STRING_FIELD(transport_name);
	);
	/*! Callerid information of this endpoint */
	struct ast_party_id callerid;
	/*! Register with the service */
	unsigned int register_with_service;
	/*! Media configuration */
	struct respoke_endpoint_media media;
	/*! Optional state information, if registering with service */
	struct respoke_endpoint_state *state;
	/*! How to handle redirects received */
	enum respoke_endpoint_redirect redirect;
};

/*!
 * \brief Interface to Respoke endpoint identifier
 */
struct respoke_endpoint_identifier {
	/*! Identify an endpoint for the given message */
	struct respoke_endpoint *(*identify)(struct respoke_message *message);
};

/*!
 * \brief Initialize the endpoint unit.
 *
 * \retval -1 if initialization failed, 0 if successful.
 */
int respoke_endpoint_initialize(void);

/*!
 * \brief De-initialize the endpoint unit.
 */
void respoke_endpoint_deinitialize(void);

/*!
 * \brief Register a Respoke endpoint identifier
 *
 * \param identifier The identifier to register
 * \retval 0 Success
 * \retval -1 Failure
 */
int respoke_register_endpoint_identifier(const struct respoke_endpoint_identifier *identifier);

/*!
 * \brief Unregister a Respoke endpoint identifier
 *
 * \param identifier The identifier to unregister
 */
void respoke_unregister_endpoint_identifier(const struct respoke_endpoint_identifier *identifier);

/*!
 * \brief Find the endpoint based upon the incoming message.
 *
 * Call each registered endpoint identifier until one successfully locates
 * an associated endpoint.
 *
 * \note If an endpoint is found an ao2 object is returned and the caller
 *       is responsible for decrementing the reference count.
 *
 * \param message The inbound message used for identification
 * \retval An endpoint or NULL if not found
 */
struct respoke_endpoint *respoke_endpoint_identify(
	struct respoke_message *message);

#endif /* RESPOKE_ENDPOINT_H_ */
