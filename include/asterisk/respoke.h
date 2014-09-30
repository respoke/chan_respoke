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

#ifndef _RESPOKE_H
#define _RESPOKE_H

struct ast_sorcery;

/*!
 * \brief Get a pointer to the Respoke sorcery structure.
 *
 * \retval NULL sorcery has not been initialized
 * \retval non-NULL sorcery structure
 */
struct ast_sorcery *respoke_get_sorcery(void);

/*!
 * \brief Create a new serializer for Respoke tasks
 *
 * See \ref ast_threadpool_serializer for more information on serializers.
 * Respoke creates serializers so that tasks operating on similar data will run
 * in sequence.
 *
 * \retval NULL Failure
 * \retval non-NULL Newly-created serializer
 */
struct ast_taskprocessor *respoke_create_serializer(void);

/*!
 * \brief Pushes a task to Respoke servants
 *
 * This uses the serializer provided to determine how to push the task.
 * If the serializer is NULL, then the task will be pushed to the
 * servants directly. If the serializer is non-NULL, then the task will be
 * queued behind other tasks associated with the same serializer.
 *
 * \param serializer The serializer to which the task belongs. Can be NULL
 * \param respoke_task The task to execute
 * \param task_data The parameter to pass to the task when it executes
 * \retval 0 Success
 * \retval -1 Failure
 */
int respoke_push_task(struct ast_taskprocessor *serializer, int (*respoke_task)(void *), void *task_data);

/*!
 * \brief Push a task to Respoke servants and wait for it to complete
 *
 * Like \ref respoke_push_task except that it blocks until the task completes.
 *
 * \warning \b Never use this function in a Respoke servant thread. This can potentially
 * cause a deadlock. If you are in a Respoke servant thread, just call your function
 * in-line.
 *
 * \param serializer The Respoke serializer to which the task belongs. May be NULL.
 * \param respoke_task The task to execute
 * \param task_data The parameter to pass to the task when it executes
 * \retval 0 Success
 * \retval -1 Failure
 */
int respoke_push_task_synchronous(struct ast_taskprocessor *serializer, int (*respoke_task)(void *), void *task_data);

#endif /* _RESPOKE_H */
