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

#ifndef RESPOKE_APP_H_
#define RESPOKE_APP_H_

#include "asterisk/sorcery.h"
#include "asterisk/stringfields.h"

#define RESPOKE_APP "app"

/*!
 * \brief Respoke application.
 */
struct respoke_app {
	SORCERY_OBJECT(details);
	AST_DECLARE_STRING_FIELDS(
		/*! The application secret for authentication */
		AST_STRING_FIELD(secret);
	);
};

/*!
 * \brief Initialize the app unit.
 *
 * \retval -1 if initialization failed, 0 if successful.
 */
int respoke_app_initialize(void);

#endif /* RESPOKE_APP_H_ */
