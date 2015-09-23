/*
 * Respoke - Web communications made easy
 *
 * Copyright (C) 2015, D.C.S. LLC
 *
 * Chad McElligott <cmcelligott@digium.com> 
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

#ifndef RESPOKE_SDK_HEADER_H_
#define RESPOKE_SDK_HEADER_H_

#include <stddef.h>

int respoke_get_sdk_header(char *buf, size_t len);

#endif /* RESPOKE_SDK_HEADER_H_ */
