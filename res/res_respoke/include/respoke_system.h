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

#ifndef RESPOKE_SYSTEM_H_
#define RESPOKE_SYSTEM_H_

#include "asterisk/sorcery.h"

struct ast_threadpool_options;

/*!
 * \brief System configuration definition
 */
struct respoke_system {
	/*! Sorcery object details */
	SORCERY_OBJECT(details);
	/*! Threadpool configuration */
	struct {
		/*! Initial number of threads in the threadpool */
		int initial_size;
		/*! The amount by which the number of threads is incremented when necessary */
		int auto_increment;
		/*! Thread idle timeout in seconds */
		int idle_timeout;
		/*! Maxumum number of threads in the threadpool */
		int max_size;
	} threadpool;
};

/*!
 * \brief Initialize system configuration support
 */
int respoke_initialize_system(void);

/*!
 * \brief Get threadpool options
 */
void respoke_get_threadpool_options(struct ast_threadpool_options *threadpool_options);

#endif /* RESPOKE_SYSTEM_H_ */
