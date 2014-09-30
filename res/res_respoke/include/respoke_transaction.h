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

#ifndef RESPOKE_TRANSACTION_H_
#define RESPOKE_TRANSACTION_H_

struct ast_json;
struct respoke_endpoint;
struct respoke_message;
struct respoke_transport;

/*! \brief Opaque structure representing a transaction */
struct respoke_transaction;

/*! \brief Transaction states */
enum respoke_transaction_state {
	/*! \brief Transaction has just been created */
	RESPOKE_TRANSACTION_STATE_CREATED,
	/*! \brief Message has been received */
	RESPOKE_TRANSACTION_STATE_RECEIVED,
	/*! \brief Message has been sent */
	RESPOKE_TRANSACTION_STATE_SENT,
	/*! \brief An error was received in response to the message */
	RESPOKE_TRANSACTION_STATE_RESPONSE_ERROR,
	/*! \brief Message was accepted */
	RESPOKE_TRANSACTION_STATE_RESPONSE_SUCCESS,
	/*! \brief Transaction has been destroyed */
	RESPOKE_TRANSACTION_STATE_DESTROYED,
};

/*! \brief Callback invoked on a transaction state change */
typedef void (*respoke_transaction_callback)(struct respoke_transaction *transaction,
	void *obj, struct ast_json *json);

/*!
 * \brief Retrieve the message sent on a transaction
 *
 * \param transaction The transaction
 *
 * \return the message
 */
struct respoke_message *respoke_transaction_get_message(struct respoke_transaction *transaction);

/*!
 * \brief Retrieve the identifier for a transaction
 *
 * \param transaction The transaction
 *
 * \return the identifier
 */
unsigned int respoke_transaction_get_id(const struct respoke_transaction *transaction);

/*!
 * \brief Retrieve the current state of a transaction
 *
 * \param transaction The transaction
 *
 * \return the current state
 */
enum respoke_transaction_state respoke_transaction_get_state(const struct respoke_transaction *transaction);

/*!
 * \brief Retrieve the optional callback object
 *
 * \param transaction The transaction
 *
 * \return the callback object
 */
void *respoke_transaction_get_object(const struct respoke_transaction *transaction);

/*!
 * \brief Change the callback on a transaction for future state changes
 *
 * \param transaction The transaction
 * \param callback Optional callback to invoke
 * \param obj Optional object to pass to the above callback
 */
void respoke_transaction_set_callback(struct respoke_transaction *transaction,
	respoke_transaction_callback callback, void *obj);

/*!
 * \brief Retrieve the parent transaction if present
 *
 * \param transaction The transaction
 *
 * \return the parent transaction
 */
struct respoke_transaction *respoke_transaction_get_parent(const struct respoke_transaction *transaction);

/*!
 * \brief Send a message and create a transaction track it.
 *
 * \param message The message to send
 * \param callback Optional callback to invoke on message response
 * \param obj Optional object to pass to above callback
 *
 * \retval 0 success
 * \retval -1 failure
 */
int respoke_transaction_send(struct respoke_message *message, respoke_transaction_callback callback,
	void *obj);

/*!
 * \brief Retransmit a message from an existing transaction.
 *
 * \param transaction The transaction to retransmit
 *
 * \retval 0 success
 * \retval -1 failure
 */
int respoke_transaction_retransmit(struct respoke_transaction *transaction);

/*!
 * \brief Receive a message into the transaction layer.
 *
 * \param transport The transport the message came in on
 * \param json JSON version of the message itself
 */
void respoke_transaction_receive(struct respoke_transport *transport, struct ast_json *json);

/*!
 * \brief Send a message in response to an already existing transaction.
 *
 * \param message The message to send
 * \param callback Optional callback to invoke on message response
 * \param obj Optional object to pass to above callback
 *
 * \retval 0 success
 * \retval -1 failure
 */
int respoke_transaction_respond(struct respoke_transaction *transaction,
	struct respoke_message *message, respoke_transaction_callback callback,
	void *obj);

/*!
 * \brief Log the json message packet.
 *
 * \param transaction the transaction object
 * \param json the json data to log
 * \param endpoint optional endpoint to log with data
 * \param transmitting true if message is being transmitted
 */
void respoke_transaction_log_packet(struct respoke_transaction *transaction,
				    struct ast_json *json,
				    struct respoke_endpoint *endpoint,
				    unsigned int transmitting);

#endif
