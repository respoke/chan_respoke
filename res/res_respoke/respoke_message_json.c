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

#include "asterisk.h"

#include "asterisk/json.h"
#include "asterisk/lock.h"
#include "asterisk/logger.h"
#include "asterisk/netsock2.h"
#include "asterisk/rtp_engine.h"
#include "asterisk/strings.h"

#include "asterisk/respoke.h"
#include "asterisk/respoke_endpoint.h"
#include "asterisk/respoke_message.h"
#include "asterisk/respoke_transport.h"
#include "include/respoke_app.h"

#define HEADER "header"
#define HEADER_TYPE "type"
#define HEADER_REQUEST_ID "requestId"
#define HEADER_FROM "from"
#define HEADER_FROM_CONNECTION "fromConnection"
#define HEADER_FROM_TYPE "fromType"
#define HEADER_FROM_APPID "fromAppId"
#define HEADER_TO "to"
#define HEADER_TO_CONNECTION "toConnection"
#define HEADER_TO_TYPE "toType"
#define HEADER_TO_APPID "toAppId"

#define BODY "body"
#define BODY_VERSION "version"
#define BODY_SIGNAL_TYPE "signalType"
#define BODY_SESSION_ID "sessionId"
#define BODY_CALLER_ID "callerId"
#define BODY_PARSED_SDP "parsedSDP"
#define BODY_ICE_CANDIDATES "iceCandidates"
#define BODY_CONNECTION_ID "connectionId"
#define BODY_REASON "reason"
#define BODY_ANSWER "answer"
#define BODY_STATUS "status"
#define BODY_DETAIL "detail"

#define SIGNAL "signal"

#define REDIRECTIONINFO "redirectionInfo"
#define ENDPOINTID "endpointId"
#define ENDPOINTTYPE "endpointType"
#define APPID "appId"

#define VERSION "1.0"

static int object_set(struct ast_json *json, const char *key,
		      struct ast_json *obj)
{
	if (!json) {
		ast_json_unref(obj);
		return 0;
	}

	if (!obj || ast_json_object_set(json, key, obj)) {
		ast_log(LOG_ERROR, "Unable to set message value on "
			"key: %s\n", key);
		ast_json_unref(obj);
		return -1;
	}
	return 0;
}

static struct ast_json *object_get(const struct ast_json *json, const char *key)
{
	struct ast_json *obj;

	if (!json) {
		return NULL;
	}

	if (!(obj = ast_json_object_get((struct ast_json *)json, key))) {
		ast_debug(5, "Unable to get value for key: %s\n", key);
	}
	return obj;
}

static int string_set(struct ast_json *json, const char *key, const char *value)
{
	return object_set(json, key, ast_json_string_create(value));
}

static const char *string_get(const struct ast_json *json, const char *key)
{
	struct ast_json *obj = object_get(json, key);
	return obj ? ast_json_string_get(obj) : NULL;
}

static int integer_set(struct ast_json *json, const char *key, int value)
{
	return object_set(json, key, ast_json_integer_create(value));
}

static intmax_t integer_get(
	const struct ast_json *json, const char *key)
{
	struct ast_json *obj = object_get(json, key);
	return obj ? ast_json_integer_get(obj) : 0;
}

static int address_version_get(const struct ast_sockaddr *addr)
{
	return addr->ss.ss_family == AF_INET ? 4 : 6;
}

static int sockaddr_to_address_port(
	const struct ast_sockaddr *addr, char **address, unsigned int *port,
	unsigned int default_port)
{
	char *port_str;

	if (!ast_sockaddr_split_hostport(
		    ast_sockaddr_stringify(addr),
		    address, &port_str, 0)) {
		ast_log(LOG_ERROR, "Unable to get address:[port]\n");
		return -1;
	}

	if (ast_strlen_zero(port_str)) {
		*port = default_port;
	} else if (sscanf(port_str, "%d", port) != 1) {
		ast_log(LOG_ERROR, "Unable to convert port\n");
		return -1;
	}
	return 0;
}

static int address_port_to_sockaddr(const char *address, int port,
				    struct ast_sockaddr *out_addr)
{
	struct ast_sockaddr *addr;

	if (ast_strlen_zero(address)) {
		return 1;
	}

	if (!ast_sockaddr_resolve(&addr, address, 0, 0)) {
		ast_log(LOG_ERROR, "Unable to resolve address %s\n",
			address);
		return -1;
	}
	ast_sockaddr_copy(out_addr, addr);
	ast_free(addr);

	if (port > 0) {
		ast_sockaddr_set_port(out_addr, port);
	}

	return 0;
}

const char *respoke_message_type_get(const struct respoke_message *message)
{
	return string_get(object_get(message->json, HEADER), HEADER_TYPE);
}

const char *respoke_message_from_get(const struct respoke_message *message)
{
	return string_get(object_get(message->json, HEADER), HEADER_FROM);
}

const char *respoke_message_from_type_get(const struct respoke_message *message)
{
	return string_get(object_get(message->json, HEADER), HEADER_FROM_TYPE);
}

const char *respoke_message_from_connection_get(const struct respoke_message *message)
{
	return string_get(object_get(message->json, HEADER), HEADER_FROM_CONNECTION);
}

const char *respoke_message_from_appid_get(const struct respoke_message *message)
{
	return string_get(object_get(message->json, HEADER), HEADER_FROM_APPID);
}

const char *respoke_message_to_get(const struct respoke_message *message)
{
	return string_get(object_get(message->json, HEADER), HEADER_TO);
}

const char *respoke_message_to_type_get(const struct respoke_message *message)
{
	return string_get(object_get(message->json, HEADER), HEADER_TO_TYPE);
}

const char *respoke_message_to_connection_get(const struct respoke_message *message)
{
	return string_get(object_get(message->json, HEADER), HEADER_TO_CONNECTION);
}

const char *respoke_message_to_appid_get(const struct respoke_message *message)
{
	return string_get(object_get(message->json, HEADER), HEADER_TO_APPID);
}

const char *respoke_message_signal_type_get(const struct respoke_message *message)
{
	return string_get(object_get(message->json, BODY), BODY_SIGNAL_TYPE);
}

const char *respoke_message_session_id_get(const struct respoke_message *message)
{
	return string_get(object_get(message->json, BODY), BODY_SESSION_ID);
}

const char *respoke_message_connection_id_get(const struct respoke_message *message)
{
	return string_get(object_get(message->json, BODY), BODY_CONNECTION_ID);
}


static struct ast_json *message_parsed_sdp_get(const struct respoke_message *message)
{
	return object_get(object_get(message->json, BODY), BODY_PARSED_SDP);
}

static int json_media_get(const struct respoke_message *message,
			  const char *type, struct ast_json **json_media)
{
	int i;
	struct ast_json *media_array =
		object_get(message_parsed_sdp_get(message), "media");

	if (!media_array) {
		return -1;
	}

	for (i = 0; i < ast_json_array_size(media_array); ++i) {
		*json_media = ast_json_array_get(media_array, i);

		if (!strcmp(string_get(*json_media, "type"), type)) {
			return 0;
		}
	}
	return -1;
}

const char *respoke_message_setup_get(
	const struct respoke_message *message, const char *type)
{
	struct ast_json *json_media;

	if (json_media_get(message, type, &json_media)) {
		return NULL;
	}

	return string_get(json_media, "setup");
}

const char *respoke_message_fingerprint_type_get(
	const struct respoke_message *message, const char *type)
{
	struct ast_json *json_media;
	const char *res;

	if (json_media_get(message, type, &json_media)) {
		return NULL;
	}

	res = string_get(object_get(json_media, "fingerprint"), "type");

	return res ? res : string_get(object_get(message_parsed_sdp_get(message), "fingerprint"), "type");
}

const char *respoke_message_fingerprint_hash_get(
	const struct respoke_message *message, const char *type)
{
	struct ast_json *json_media;
	const char *res;

	if (json_media_get(message, type, &json_media)) {
		return NULL;
	}

	res = string_get(object_get(json_media, "fingerprint"), "hash");

	return res ? res : string_get(object_get(message_parsed_sdp_get(message), "fingerprint"), "hash");
}

enum respoke_status respoke_message_reason_get(const struct respoke_message *message)
{
        return respoke_str_to_status(
		string_get(object_get(message->json, BODY), BODY_REASON));
}

enum respoke_status respoke_message_answer_get(const struct respoke_message *message)
{
	return respoke_str_to_status(
		string_get(object_get(message->json, BODY), BODY_ANSWER));
}

enum respoke_status respoke_message_status_get(const struct respoke_message *message)
{
	return respoke_str_to_status(
		string_get(object_get(message->json, BODY), BODY_STATUS));
}

const char *respoke_message_error_detail_get(const struct respoke_message *message)
{
	return string_get(object_get(message->json, BODY), BODY_DETAIL);
}

int respoke_message_is_ipv6(const struct respoke_message *message)
{
	return integer_get(object_get(message_parsed_sdp_get(message),
				      "origin"), "ipVer") == 6;
}

int respoke_message_media_address_get(
	const struct respoke_message *message,
	const char *type, struct ast_sockaddr *addr)
{
	struct ast_json *json_media = NULL;
	const char *address = NULL;

	if (!message->json) {
		ast_sockaddr_copy(addr, &message->endpoint->media.addr);
		return 0;
	}

	if (!json_media_get(message, type, &json_media)) {
		/* if media try to get the address there */
		address = string_get(object_get(json_media, "connection"), "ip");
	}

	/* if not found on media use origin */
	if (ast_strlen_zero(address)) {
		address = string_get(object_get(message_parsed_sdp_get(message),
						"origin"), "address");
	}

	/* if still not found then error out */
	if (ast_strlen_zero(address)) {
		return -1;
	}

	if (address_port_to_sockaddr(
		    address, integer_get(json_media, "port"), addr) < 0) {
		return -1;
	}

	return 0;
}

static int json_codecs_get(const struct ast_json *rtp_array,
			   const struct ast_json *fmtp_array,
			   const char *type,
			   struct ast_rtp_codecs *codecs)
{
	int i, j;

	if (!rtp_array) {
		return 0;
	}

	for (i = 0; i < ast_json_array_size(rtp_array); ++i) {
		struct ast_json *json_rtp = ast_json_array_get(rtp_array, i);
		int payload = integer_get(json_rtp, "payload");

		ast_rtp_codecs_payloads_set_m_type(
			codecs, NULL, payload);

		ast_rtp_codecs_payloads_set_rtpmap_type_rate(
			codecs, NULL, payload, (char *)type,
			(char *)string_get(json_rtp, "codec"),
			0, integer_get(json_rtp, "rate"));

		if (!fmtp_array) {
			continue;
		}

		for (j = 0; j < ast_json_array_size(fmtp_array); ++j) {
			struct ast_json *json_fmtp =
				ast_json_array_get(fmtp_array, j);
			struct ast_format *format, *parsed;

			if (payload != integer_get(
				    json_fmtp, "payload")) {
				continue;
			}

			if (!(format = ast_rtp_codecs_get_payload_format(
				      codecs, payload))) {
				ast_rtp_codecs_payloads_unset(
					codecs, NULL, payload);
				break;
			}

			if ((parsed = ast_format_parse_sdp_fmtp(
				     format, string_get(json_fmtp, "config")))) {
				ast_rtp_codecs_payload_replace_format(
					codecs, payload, parsed);
				ao2_ref(parsed, -1);
			}
			ao2_ref(format, -1);
			break;
		}
	}
	return 0;
}

int respoke_message_codecs_get(
	const struct respoke_message *message, const char *type,
	struct ast_rtp_codecs *codecs)
{
	struct ast_json *json_media;

	if (json_media_get(message, type, &json_media)) {
		return -1;
	}

	if (json_codecs_get(
		    object_get(json_media, "rtp"),
		    object_get(json_media, "fmtp"),
		    type, codecs)) {
		return -1;
	}

	return 0;
}

const char *respoke_message_ice_ufrag_get(
	const struct respoke_message *message, const char *type)
{
	struct ast_json *json_media;
	const char *res;

	if (json_media_get(message, type, &json_media)) {
		return NULL;
	}

	res = string_get(json_media, "iceUfrag");

	return res ? res : string_get(message_parsed_sdp_get(message), "iceUfrag");
}

const char *respoke_message_ice_pwd_get(
	const struct respoke_message *message, const char *type)
{
	struct ast_json *json_media;
	const char *res;

	if (json_media_get(message, type, &json_media)) {
		return NULL;
	}

	res = string_get(json_media, "icePwd");

	return res ? res : string_get(message_parsed_sdp_get(message), "icePwd");
}

static int handle_ice_candidate(struct ast_json *json, struct ast_rtp_instance *instance)
{
	unsigned int foundation;
	char foundation_str[32];
	const char *value;
	struct ast_rtp_engine_ice *ice = ast_rtp_instance_get_ice(instance);
	struct ast_rtp_engine_ice_candidate candidate = { 0, };

	if (!ice) {
		return 0;
	}

	foundation = integer_get(json, "foundation");
	if (snprintf(foundation_str, sizeof(foundation_str) - 1, "%u", foundation) < 0) {
		return -1;
	}

	candidate.foundation = foundation_str;
	candidate.id = integer_get(json, "component");
	candidate.transport = (char *)string_get(json, "transport");
	candidate.priority = integer_get(json, "priority");

	if ((value = string_get(json, "ip"))) {
		ast_sockaddr_parse(&candidate.address, value, PARSE_PORT_FORBID);
		ast_sockaddr_set_port(&candidate.address, integer_get(json, "port"));
	}

	value = string_get(json, "type");
	if (!strcasecmp(value, "host")) {
		candidate.type = AST_RTP_ICE_CANDIDATE_TYPE_HOST;
	} else if (!strcasecmp(value, "srflx")) {
		candidate.type = AST_RTP_ICE_CANDIDATE_TYPE_SRFLX;
	} else if (!strcasecmp(value, "relay")) {
		candidate.type = AST_RTP_ICE_CANDIDATE_TYPE_RELAYED;
	} else {
		return 0;
	}

	if ((value = string_get(json, "raddr"))) {
		ast_sockaddr_parse(&candidate.relay_address, value, PARSE_PORT_FORBID);
		ast_sockaddr_set_port(&candidate.relay_address, integer_get(json, "rport"));
	}

	ice->add_remote_candidate(instance, &candidate);

	return 0;
}

int respoke_message_ice_candidates_get(
	const struct respoke_message *message, const char *type,
	struct ast_rtp_instance *instance)
{
	int i;
	struct ast_json *json_media;
	struct ast_json *candidate_array = object_get(object_get(message->json, BODY), BODY_ICE_CANDIDATES);

	/* if candidates not found on body then check in sdp */
	if (!candidate_array) {
		if (json_media_get(message, type, &json_media)) {
			return 0;
		}

		if (!(candidate_array = object_get(json_media, "candidates"))) {
			return 0;
		}
	}

	for (i = 0; i < ast_json_array_size(candidate_array); ++i) {
		if (handle_ice_candidate(
			    ast_json_array_get(candidate_array, i), instance)) {
			return -1;
		}
	}

	return 0;
}

const char *respoke_message_redirected_endpoint_get(const struct respoke_message *message)
{
	return string_get(object_get(object_get(message->json, BODY), REDIRECTIONINFO), ENDPOINTID);
}

const char *respoke_message_redirected_type_get(const struct respoke_message *message)
{
	return string_get(object_get(object_get(message->json, BODY), REDIRECTIONINFO), ENDPOINTTYPE);
}

const char *respoke_message_redirected_app_get(const struct respoke_message *message)
{
	return string_get(object_get(object_get(message->json, BODY), REDIRECTIONINFO), APPID);
}

const char *respoke_message_callerid_name_get(const struct respoke_message *message)
{
	return string_get(object_get(object_get(message->json, BODY), BODY_CALLER_ID), "name");
}

const char *respoke_message_callerid_number_get(const struct respoke_message *message)
{
	return string_get(object_get(object_get(message->json, BODY), BODY_CALLER_ID), "number");
}

static struct ast_json *sdp_origin_to_json(
	const char *username, const struct ast_sockaddr *addr, unsigned int ip_version)
{
	char session_id_str[64];
	unsigned int session_id = ast_random();

	snprintf(session_id_str, sizeof(session_id_str), "%u", session_id);

	return ast_json_pack(
		"{s:s,s:s,s:i,s:s,s:i,s:s}",
		"username", username,
		"sessionId", session_id_str,
		"sessionVersion", 2,
		"netType", "IN",
		"ipVer", ip_version,
		"address", ast_sockaddr_stringify_addr(addr));
}

static struct ast_json *sdp_media_connection_to_json(const struct ast_sockaddr *addr)
{
	return ast_json_pack(
		"{s:i,s:s}",
		"version", address_version_get(addr),
		"ip", ast_sockaddr_stringify_addr(addr));
}

static struct ast_json *sdp_media_rtcp_to_json(const struct ast_sockaddr *addr)
{
	char *address;
	unsigned int port;

	if (ast_sockaddr_isnull(addr)) {
		return NULL;
	}

	if (sockaddr_to_address_port(addr, &address, &port, 0)) {
		return NULL;
	}

	return ast_json_pack(
		"{s:i,s:s,s:i,s:s}",
		"port", port,
		"netType", "IN",
		"ipVer", address_version_get(addr),
		"address", address);
}

static const char *sdp_media_dtls_setup_to_str(struct ast_rtp_engine_dtls *dtls,
	struct ast_rtp_instance *instance)
{
	switch (dtls->get_setup(instance)) {
	case AST_RTP_DTLS_SETUP_ACTIVE:
		return "active";
	case AST_RTP_DTLS_SETUP_PASSIVE:
		return "passive";
	case AST_RTP_DTLS_SETUP_ACTPASS:
		return "actpass";
	case AST_RTP_DTLS_SETUP_HOLDCONN:
		return "holdconn";
	}

	/* This will never be reached */
	return NULL;
}

static struct ast_json *sdp_media_dtls_fingerprint_to_json(struct ast_rtp_engine_dtls *dtls,
	struct ast_rtp_instance *instance)
{
	const char *type = NULL;

	switch (dtls->get_fingerprint_hash(instance)) {
	case AST_RTP_DTLS_HASH_SHA1:
		type = "sha-1";
		break;
	case AST_RTP_DTLS_HASH_SHA256:
		type = "sha-256";
		break;
	}

	if (!type) {
		return NULL;
	}

	return ast_json_pack(
		"{s:s,s:s}",
		"type", type,
		"hash", dtls->get_fingerprint(instance));
}

static struct ast_json *sdp_media_rtp_to_json(
	int payload, const struct ast_format *format)
{
	const char *codec = ast_format_get_name(format);

	return ast_json_pack(
		"{s:i,s:s,s:i}",
		"payload", payload,
		"codec", codec,
		"rate", ast_format_get_sample_rate(format));
}

static struct ast_json *sdp_media_fmtp_to_json(
	int payload, const struct ast_format *format)
{
	struct ast_str *config = ast_str_create(128);
	struct ast_json *json;
	char *p;

	ast_format_generate_sdp_fmtp(format, payload, &config);

	if (!ast_str_strlen(config)) {
		ast_free(config);
		return NULL;
	}

	p = ast_str_buffer(config) + ast_str_strlen(config) - 1;

	/* remove any carriage return line feeds */
	while (*p == '\r' || *p == '\n') --p;
	*++p = '\0';

	/* retrieve only the value */
	if (!(p = strchr(ast_str_buffer(config), ':'))) {
		p = ast_str_buffer(config);
	} else {
		++p;
	}

	json = ast_json_pack(
		"{s:i,s:s}",
		"payload", payload,
		"config", p);

	ast_free(config);
	return json;
}

static int sdp_media_codecs_to_json(
	enum ast_media_type type, struct ast_format_cap *caps,
	struct ast_rtp_instance *instance, struct ast_json **rtp_array,
	struct ast_json **fmtp_array, struct ast_str **payloads,
	unsigned int *min_ptime, unsigned int *max_ptime)
{
	int i, payload;
	struct ast_json *json;

	if (!(*rtp_array = ast_json_array_create()) ||
	    !(*fmtp_array = ast_json_array_create())) {
		ast_log(LOG_ERROR, "Unable to create sdp media arrays\n");
		return -1;
	}

	for (i = 0; i < ast_format_cap_count(caps); ++i) {
		RAII_VAR(struct ast_format *, format,
			 ast_format_cap_get_format(caps, i), ao2_cleanup);

		if ((ast_format_get_type(format) != type) ||
		    (payload = ast_rtp_codecs_payload_code(
			    ast_rtp_instance_get_codecs(instance), 1, format, 0) == -1)) {
			continue;
		}

		if (!(json = sdp_media_rtp_to_json(payload, format))) {
			continue;
		}

		if (ast_json_array_append(*rtp_array, json)) {
			ast_json_unref(json);
			continue;
		}

		ast_str_append(payloads, 0, "%d ", payload);

		if (ast_format_get_maximum_ms(format) &&
			((ast_format_get_maximum_ms(format) < *max_ptime) || !*max_ptime)) {
			*max_ptime = ast_format_get_maximum_ms(format);
		}

		if (!(json = sdp_media_fmtp_to_json(payload, format))) {
			continue;
		}

		if (ast_json_array_append(*fmtp_array, json)) {
			ast_json_unref(json);
		}
	}

	if (!(*min_ptime = ast_rtp_codecs_get_framing(
		      ast_rtp_instance_get_codecs(instance)))) {
		*min_ptime = ast_format_cap_get_framing(caps);
	}

	if (type == AST_MEDIA_TYPE_AUDIO) {
		payload = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(instance), 0, NULL, AST_RTP_DTMF);

		if (payload != -1) {
			ast_str_append(payloads, 0, "%d ", payload);

			json = ast_json_pack("{s:i,s:s,s:i}",
				"payload", payload,
				"codec", "telephone-event",
				"rate", 8000);
			if (json && ast_json_array_append(*rtp_array, json)) {
				ast_json_unref(json);
			}
		}
	}

	ast_str_truncate(*payloads, -1);
	return 0;
}

static void media_ice_candidates_to_json(struct ast_rtp_instance *instance,
					 struct ast_json **candidate_array)
{
	struct ast_rtp_engine_ice *ice;
	struct ao2_iterator i;
	struct ao2_container *candidates;
	struct ast_rtp_engine_ice_candidate *candidate;

	if (!instance || !(ice = ast_rtp_instance_get_ice(instance)) ||
	    !(candidates = ice->get_local_candidates(instance))) {
		return;
	}

	if (!(*candidate_array) && !(*candidate_array = ast_json_array_create())) {
		ast_log(LOG_ERROR, "Unable to create sdp ice candidates array\n");
		return;
	}

	i = ao2_iterator_init(candidates, 0);
	for (; (candidate = ao2_iterator_next(&i)); ao2_ref(candidate, -1)) {
		const char *type = NULL;
		char *address;
		unsigned int port, fval;
		struct ast_json *cand = ast_json_object_create();

		if (!cand) {
			ast_log(LOG_ERROR, "Unable to JSON ice candidate object\n");
			return;
		}

		if (candidate->foundation &&
		    (sscanf(candidate->foundation, "%u", &fval) == 1)) {
			integer_set(cand, "foundation", fval);
		}

		if (candidate->id) {
			integer_set(cand, "component", candidate->id);
		}

		if (candidate->transport) {
			string_set(cand, "transport", candidate->transport);
		}

		if (candidate->priority) {
			integer_set(cand, "priority", candidate->priority);
		}

		if (!ast_sockaddr_isnull(&candidate->address) &&
		    !sockaddr_to_address_port(&candidate->address, &address, &port, 0)) {
			string_set(cand, "ip", address);
			integer_set(cand, "port", port);
		}

		switch (candidate->type) {
		case AST_RTP_ICE_CANDIDATE_TYPE_HOST:
			type = "host";
			break;
		case AST_RTP_ICE_CANDIDATE_TYPE_SRFLX:
			type = "srflx";
			break;
		case AST_RTP_ICE_CANDIDATE_TYPE_RELAYED:
			type = "relay";
			break;
		}
		if (type) {
			string_set(cand, "type", type);
		}

		if (!ast_sockaddr_isnull(&candidate->relay_address) &&
		    !sockaddr_to_address_port(&candidate->relay_address, &address, &port, 0)) {
			string_set(cand, "raddr", address);
			integer_set(cand, "rport", port);
		}

		ast_json_array_append(*candidate_array, cand);
	}

	ao2_iterator_destroy(&i);
}

enum ast_media_type respoke_str_to_media_type(const char *type)
{
	if (!strcasecmp(type, "audio")) {
		return AST_MEDIA_TYPE_AUDIO;
	} else if (!strcasecmp(type, "video")) {
		return AST_MEDIA_TYPE_VIDEO;
	}

	return 0;
}

static struct ast_json *sdp_media_to_json(
	const char *type, struct ast_format_cap *caps, struct ast_rtp_instance *instance,
	struct ast_rtp_engine_ice *ice, struct ast_rtp_engine_dtls *dtls)
{
	struct ast_json *ice_candidates = NULL;
	struct ast_json *media, *json, *rtp_array, *fmtp_array;
	struct ast_str *payloads;
	struct ast_sockaddr addr;
	char *address;
	unsigned int port, min_ptime = 0, max_ptime = 0;

	if (!instance) {
		return NULL;
	}

	ast_rtp_instance_get_local_address(instance, &addr);
	if (sockaddr_to_address_port(&addr, &address, &port, 0)) {
		return NULL;
	}

	if (!(payloads = ast_str_create(128))) {
		return NULL;
	}

	if (sdp_media_codecs_to_json(
		    respoke_str_to_media_type(type), caps, instance, &rtp_array,
		    &fmtp_array, &payloads, &min_ptime, &max_ptime)) {
		ast_free(payloads);
		return NULL;
	}

	if (!(media = ast_json_pack(
		      "{s:s,s:i,s:s,s:s,s:o,s:o}",
		      "type", type,
		      "port", port,
		      "protocol", "RTP/SAVPF",
		      "payloads", ast_str_buffer(payloads),
		      "rtp", rtp_array,
		      "fmtp", fmtp_array))) {
		ast_json_unref(rtp_array);
		ast_json_unref(fmtp_array);
		ast_free(payloads);
		return NULL;
	}

	if ((json = sdp_media_connection_to_json(&addr))) {
		object_set(media, "connection", json);
	}

	if ((json = sdp_media_rtcp_to_json(NULL))) {
		object_set(media, "rtcp", json);
	}

	if (ice) {
		string_set(media, "iceUfrag", ice->get_ufrag(instance));
		string_set(media, "icePwd", ice->get_password(instance));
	}

	if (dtls) {
		string_set(media, "setup", sdp_media_dtls_setup_to_str(dtls, instance));
		if ((json = sdp_media_dtls_fingerprint_to_json(dtls, instance))) {
			object_set(media, "fingerprint", json);
		}
	}

	if (min_ptime) {
		integer_set(media, "minptime", min_ptime);
	}

	if (max_ptime) {
		integer_set(media, "maxptime", max_ptime);
	}

	media_ice_candidates_to_json(instance, &ice_candidates);
	if (ice_candidates) {
		object_set(media, "candidates", ice_candidates);
	}

	ast_free(payloads);
	return media;
}

static struct ast_json *sdp_to_json(
	struct respoke_endpoint *endpoint, unsigned int rtp_ipv6,
	struct ast_format_cap *caps, struct ast_rtp_instance *audio_rtp,
	struct ast_rtp_instance *video_rtp)
{
	struct ast_json *sdp, *origin, *media, *media_array, *timing;

	if (!(timing = ast_json_pack(
		    "{s:i,s:i}",
		    "start", 0,
		    "stop", 0))) {
		return NULL;
	}

	if (!(origin = sdp_origin_to_json(
		      endpoint->media.sdp_owner, &endpoint->media.addr,
		      rtp_ipv6 ? 6 : 4))) {
		ast_json_unref(timing);
		return NULL;
	}

	if (!(media_array = ast_json_array_create())) {
		ast_log(LOG_ERROR, "Unable to create sdp media array\n");
		ast_json_unref(timing);
		ast_json_unref(origin);
		return NULL;
	}

	if ((media = sdp_media_to_json(
		     "audio", caps, audio_rtp,
		     audio_rtp ? ast_rtp_instance_get_ice(
			     audio_rtp) : NULL,
		     audio_rtp ? ast_rtp_instance_get_dtls(
		     	audio_rtp) : NULL))) {
		ast_json_array_append(media_array, media);
	}

	if ((media = sdp_media_to_json(
		     "video", caps, video_rtp,
		     video_rtp ? ast_rtp_instance_get_ice(
			     video_rtp) : NULL,
		     video_rtp ? ast_rtp_instance_get_dtls(
		     	video_rtp) : NULL))) {
		ast_json_array_append(media_array, media);
	}

	if (!(sdp = ast_json_pack(
		    "{s:i,s:s,s:o,s:o,s:o}",
		    "version", 0,
		    "name", endpoint->media.sdp_session,
		    "origin", origin,
		    "timing", timing,
		    "media", media_array))) {
		ast_json_unref(timing);
		ast_json_unref(origin);
		ast_json_unref(media_array);
	}

	return sdp;
}

static int parsed_sdp_set(struct ast_json *body, struct respoke_endpoint *endpoint,
			  int rtp_ipv6, struct ast_format_cap *caps,
			  struct ast_rtp_instance *audio_rtp, struct ast_rtp_instance *video_rtp)
{
	struct ast_json *parsed_sdp;

	if (!(parsed_sdp = sdp_to_json(endpoint, rtp_ipv6, caps, audio_rtp, video_rtp)) ||
	    object_set(body, BODY_PARSED_SDP, parsed_sdp)) {
		ast_log(LOG_ERROR, "Unable to create offer - error in parsed sdp\n");
		return -1;
	}

	return 0;
}

static struct ast_json *message_create_body(
	const char *signal_type, const char *session_id)
{
	struct ast_json *json;

	if (ast_strlen_zero(session_id)) {
		ast_log(LOG_ERROR, "Unable to create body object - "
			"missing required session id\n");
		return NULL;
	}

	if (!(json = ast_json_pack(
		      "{s:s,s:s,s:s}",
		      BODY_VERSION, VERSION,
		      BODY_SIGNAL_TYPE, signal_type,
		      BODY_SESSION_ID, session_id))) {
		ast_log(LOG_ERROR, "Unable to create body object "
			"for signalType: %s\n", signal_type);
	}

	return json;
}

static struct respoke_message *signaling_message_create(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint,
	const char *from, const char *from_type,
	const char *from_connection, const char *to, const char *to_type,
	const char *to_connection, const char *to_appid, struct ast_json *body)
{
	struct ast_json *data;
	struct respoke_message *message;

	if (!(data = ast_json_pack("{s:s,s:s,s:s,s:s,s:o}",
				   HEADER_TO, S_OR(to, ""),
				   HEADER_TO_TYPE, S_OR(to_type, ""),
				   HEADER_FROM, S_OR(from, ""),
				   HEADER_FROM_TYPE, S_OR(from_type, ""),
				   "signal", body))) {
		ast_json_unref(body);
		return NULL;
	}

	if (!ast_strlen_zero(to_connection)) {
		string_set(data, HEADER_TO_CONNECTION, to_connection);
	}

	if (!ast_strlen_zero(to_appid)) {
		string_set(data, HEADER_TO_APPID, to_appid);
	}

	if (!(message = respoke_message_alloc(transport, NULL, data, endpoint, "/v1/signaling"))) {
		ast_log(LOG_ERROR, "Unable to create message of signal type '%s'",
			string_get(body, BODY_SIGNAL_TYPE));
	}

	ast_json_unref(data);

	return message;
}

static int callerid_set(struct ast_json *body, const char *name, const char *number)
{
	struct ast_json *callerid;

	if (!(callerid = ast_json_pack("{s:s,s:s}", "name", S_OR(name, ""), "number", S_OR(number, "")))) {
		return -1;
	}

	return object_set(body, BODY_CALLER_ID, callerid);
}

struct respoke_message *respoke_message_create_offer(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint, int rtp_ipv6,
	const char *from, const char *from_type, const char *from_connection,
	const char *to, const char *to_type, const char *to_connection, const char *to_appid,
	const char *session_id, struct ast_format_cap *caps, struct ast_rtp_instance *audio_rtp,
	struct ast_rtp_instance *video_rtp, const char *callerid_name, const char *callerid_number)
{
	struct ast_json *body;

	if (!(body = message_create_body("offer", session_id))) {
		return NULL;
	}

	if (parsed_sdp_set(body, endpoint, rtp_ipv6, caps, audio_rtp, video_rtp)) {
		ast_json_unref(body);
		return NULL;
	}

	if (callerid_set(body, callerid_name, callerid_number)) {
		ast_json_unref(body);
		return NULL;
	}

	return signaling_message_create(transport, endpoint, from, from_type, from_connection,
			      to, to_type, to_connection, to_appid, body);
}

struct respoke_message *respoke_message_create_answer(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint, int rtp_ipv6,
	const char *from, const char *from_type, const char *from_connection,
	const char *to, const char *to_type, const char *to_connection, const char *to_appid,
	const char *session_id, struct ast_format_cap *caps, struct ast_rtp_instance *audio_rtp,
	struct ast_rtp_instance *video_rtp)
{
	struct ast_json *body;

	if (!(body = message_create_body("answer", session_id))) {
		return NULL;
	}

	if (string_set(body, BODY_ANSWER, respoke_status_to_str(RESPOKE_STATUS_FINAL)) ||
	    parsed_sdp_set(body, endpoint, rtp_ipv6, caps, audio_rtp, video_rtp)) {
		ast_json_unref(body);
		return NULL;
	}

	return signaling_message_create(transport, endpoint, from, from_type, from_connection,
			      to, to_type, to_connection, to_appid, body);
}

struct respoke_message *respoke_message_create_status(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint,
	const char *from, const char *from_type,
	const char *from_connection, const char *to, const char *to_type,
	const char *to_connection, const char *to_appid, const char *session_id,
	enum respoke_status status)
{
	struct ast_json *body;

	if (!(body = message_create_body("status", session_id))) {
		return NULL;
	}

	if (string_set(body, BODY_STATUS, respoke_status_to_str(status))) {
		ast_json_unref(body);
		return NULL;
	}

	return signaling_message_create(transport, endpoint, from, from_type, from_connection,
			      to, to_type, to_connection, to_appid, body);
}

struct respoke_message *respoke_message_create_bye(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint,
	const char *from, const char *from_type,
	const char *from_connection, const char *to, const char *to_type,
	const char *to_connection, const char *to_appid, const char *session_id,
	enum respoke_status status)
{
	struct ast_json *body;

	if (!(body = message_create_body("bye", session_id))) {
		return NULL;
	}

	if (string_set(body, BODY_REASON, respoke_status_to_str(status))) {
		ast_json_unref(body);
		return NULL;
	}

	return signaling_message_create(transport, endpoint, from, from_type, from_connection,
			      to, to_type, to_connection, to_appid, body);
}

struct respoke_message *respoke_message_create_error(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint,
	const char *from, const char *from_type,
	const char *from_connection, const char *to, const char *to_type,
	const char *to_connection, const char *to_appid, const char *session_id,
	const char *detail)
{
	struct ast_json *body;

	if (!(body = message_create_body("error", session_id))) {
		return NULL;
	}

	if (string_set(body, BODY_DETAIL, detail)) {
		ast_json_unref(body);
		return NULL;
	}

	return signaling_message_create(transport, endpoint, from, from_type, from_connection,
			      to, to_type, to_connection, to_appid, body);
}

int respoke_message_sail(struct respoke_message *message)
{
	struct ast_json *obj, *headers;
	struct ast_variable *header;

	/* In case we need to retransmit don't re-sail the message */
	if (message->sailed) {
		return 0;
	}

	if (!(headers = ast_json_pack(
		      "{s:s}",
		      "App-Secret", message->transport->app_secret))) {
		return -1;
	}

	for (header = message->headers; header; header = header->next) {
		if (string_set(headers, header->name, header->value)) {
			ast_json_unref(headers);
			return -1;
		}
	}

	if (!(obj = ast_json_pack(
		      "{s:s,s:o}",
		      "url", message->url,
		      "headers", headers))) {
		ast_json_unref(headers);
		return -1;
	}

	if (message->json) {
		struct ast_json *signal = object_get(message->json, "signal");

		/* If the data contains signaling it needs to be stringified */
		if (signal) {
			char *json_str;

			json_str = ast_json_dump_string(signal);
			if (!json_str) {
				return -1;
			}
			object_set(message->json, "signal", ast_json_string_create(json_str));
			ast_json_free(json_str);
		}

		/* This steals the reference so message->json does not need an explicit unref before overwriting */
		object_set(obj, "data", message->json);
	}

	message->json = obj;
	message->sailed = 1;

	return 0;
}
