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

#ifndef RESPOKE_PRIVATE_H_
#define RESPOKE_PRIVATE_H_

#include "asterisk/module.h"
#include "asterisk/compat.h"

/*!
 * \brief Initialize the configuration for res_respoke
 */
int respoke_initialize_configuration(void);

/*!
 * \brief Annihilate the configuration objects
 */
void respoke_destroy_configuration(void);

/*!
 * \brief Reload the configuration
 */
int respoke_reload_configuration(void);

/*!
 * \brief Get the module info for res_respoke
 */
const struct ast_module_info *respoke_get_module_info(void);

#endif /* RESPOKE_PRIVATE_H_ */
