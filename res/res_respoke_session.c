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

/*** MODULEINFO
	<depend>res_respoke</depend>
	<support_level>extended</support_level>
 ***/

#include "asterisk.h"

#include <curl/curl.h>

#include "asterisk/astobj2.h"
#include "asterisk/channel.h"
#include "asterisk/format.h"
#include "asterisk/format_cap.h"
#include "asterisk/module.h"
#include "asterisk/logger.h"
#include "asterisk/rtp_engine.h"
#include "asterisk/sched.h"
#include "asterisk/taskprocessor.h"
#include "asterisk/causes.h"
#include "asterisk/uri.h"
#include "asterisk/callerid.h"
#include "asterisk/pbx.h"

#include "asterisk/res_respoke_session.h"

#include "asterisk/respoke.h"
#include "asterisk/respoke_endpoint.h"
#include "asterisk/respoke_message.h"
#include "asterisk/respoke_transport.h"

#define TYPE_AUDIO "audio"
#define TYPE_VIDEO "video"

/*! \brief Address for IPv4 RTP */
static struct ast_sockaddr address_ipv4;

/*! \brief Address for IPv6 RTP */
static struct ast_sockaddr address_ipv6;

/*! \brief scheduler for RTCP purposes */
static struct ast_sched_context *sched;

/*! \brief number of session buckets */
#define MAX_SESSION_BUCKETS 53

static AST_RWLIST_HEAD_STATIC(session_handlers, respoke_session_handler);

int respoke_session_register_handler(struct respoke_session_handler *handler)
{
	SCOPED_LOCK(lock, &session_handlers, AST_RWLIST_WRLOCK, AST_RWLIST_UNLOCK);
	AST_RWLIST_INSERT_TAIL(&session_handlers, handler, item);
	ast_module_ref(ast_module_info->self);

	return 0;
}

void respoke_session_unregister_handler(struct respoke_session_handler *handler)
{
	struct respoke_session_handler *i;
	SCOPED_LOCK(lock, &session_handlers, AST_RWLIST_WRLOCK, AST_RWLIST_UNLOCK);

	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&session_handlers, i, item) {
		if (i == handler) {
			AST_RWLIST_REMOVE_CURRENT(item);
			ast_module_unref(ast_module_info->self);
			break;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;
}

static int session_on_offer(struct respoke_session *session)
{
	struct respoke_session_handler *i;
	SCOPED_LOCK(lock, &session_handlers, AST_RWLIST_WRLOCK, AST_RWLIST_UNLOCK);

	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&session_handlers, i, item) {
		if (i->on_offer && i->on_offer(session)) {
			return -1;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;

	return 0;
}

static int session_on_answer(struct respoke_session *session, enum respoke_status status)
{
	struct respoke_session_handler *i;
	SCOPED_LOCK(lock, &session_handlers, AST_RWLIST_WRLOCK, AST_RWLIST_UNLOCK);

	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&session_handlers, i, item) {
		if (i->on_answer && i->on_answer(session, status)) {
			return -1;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;

	return 0;
}

static int session_on_status(struct respoke_session *session, enum respoke_status status)
{
	struct respoke_session_handler *i;
	SCOPED_LOCK(lock, &session_handlers, AST_RWLIST_WRLOCK, AST_RWLIST_UNLOCK);

	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&session_handlers, i, item) {
		if (i->on_status && i->on_status(session, status)) {
			return -1;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;

	return 0;
}

static int session_on_end(struct respoke_session *session, enum respoke_status status, struct respoke_message *message)
{
	struct respoke_session_handler *i;
	SCOPED_LOCK(lock, &session_handlers, AST_RWLIST_WRLOCK, AST_RWLIST_UNLOCK);

	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&session_handlers, i, item) {
		if (i->on_end && i->on_end(session, status, message)) {
			return -1;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;

	return 0;
}

/*! \brief sessions container */
static struct ao2_container *sessions;

static int sessions_hash(const void *obj, int flags)
{
	const struct respoke_session *object;
	const char *key;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_KEY:
		key = obj;
		break;
	case OBJ_SEARCH_OBJECT:
		object = obj;
		key = object->session_id;
		break;
	default:
		ast_assert(0);
		return 0;
	}
	return ast_str_hash(key);
}

static int sessions_cmp(void *obj, void *arg, int flags)
{
	const struct respoke_session *object_left = obj;
	const struct respoke_session *object_right = arg;
	const char *right_key = arg;
	int cmp;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
		right_key = object_right->session_id;
		/* Fall through */
	case OBJ_SEARCH_KEY:
		cmp = strcmp(object_left->session_id, right_key);
		break;
	case OBJ_SEARCH_PARTIAL_KEY:
		/* Not supported by container. */
		ast_assert(0);
		return 0;
	default:
		cmp = 0;
		break;
	}
	if (cmp) {
		return 0;
	}
	return CMP_MATCH;
}

static int joint_capabilities_get(
	struct respoke_message *message, struct ast_rtp_codecs *codecs,
	struct ast_format_cap *session_caps, const char *type)
{
	RAII_VAR(struct ast_format_cap *, incoming_caps, NULL, ao2_cleanup);
	RAII_VAR(struct ast_format_cap *, endpoint_caps, NULL, ao2_cleanup);
	RAII_VAR(struct ast_format_cap *, joint_caps, NULL, ao2_cleanup);
	enum ast_media_type media_type = respoke_str_to_media_type(type);
	int fmts = 0;

	/* retrieve the codecs from the message */
	if (respoke_message_codecs_get(message, type, codecs)) {
		/* none for the given type */
		ast_debug(1, "Codecs not found for type '%s'\n", type);
		return 1;
	}

	if (!(incoming_caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT)) ||
	    !(endpoint_caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT)) ||
	    !(joint_caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT))) {
		ast_log(LOG_ERROR, "Unable to allocate "
			"capabilities for type '%s'\n", type);
		return -1;
	}

	/* get the incoming capabilities */
	ast_rtp_codecs_payload_formats(codecs, incoming_caps, &fmts);
	ast_format_cap_append_from_cap(
		endpoint_caps, message->endpoint->media.codecs, media_type);

	ast_format_cap_get_compatible(incoming_caps, endpoint_caps, joint_caps);
	if (!ast_format_cap_count(joint_caps)) {
		struct ast_str *usbuf = ast_str_alloca(64);
		struct ast_str *thembuf = ast_str_alloca(64);

		ast_log(LOG_WARNING, "No joint capabilities between our "
			"configuration(%s) and incoming SDP(%s)\n",
			ast_format_cap_get_names(endpoint_caps, &usbuf),
			ast_format_cap_get_names(incoming_caps, &thembuf));
		return -1;

	}

	/* update the session capabilities */
	ast_format_cap_remove_by_type(session_caps, media_type);
	ast_format_cap_append_from_cap(session_caps, joint_caps, AST_MEDIA_TYPE_UNKNOWN);
	return 0;
}

static void ice_start(struct respoke_session *session, enum ast_rtp_ice_role role)
{
	struct ast_rtp_engine_ice *ice;

	if (session->audio_rtp) {
		ice = ast_rtp_instance_get_ice(session->audio_rtp);

		if (ice) {
			ice->set_role(session->audio_rtp, role);
			ice->start(session->audio_rtp);
		}
	}

	if (session->video_rtp) {
		ice = ast_rtp_instance_get_ice(session->video_rtp);

		if (ice) {
			ice->set_role(session->video_rtp, role);
			ice->start(session->video_rtp);
		}
	}
}

static int ice_update(struct respoke_message *message, const char *type,
		      struct ast_rtp_instance *instance)
{
	struct ast_rtp_engine_ice *ice;
	const char *value;

	if (!(ice = ast_rtp_instance_get_ice(instance))) {
		return 0;
	}

	if ((value = respoke_message_ice_ufrag_get(message, type))) {
		ice->set_authentication(instance, value, NULL);
	}

	if ((value = respoke_message_ice_pwd_get(message, type))) {
		ice->set_authentication(instance, NULL, value);
	}

	if (respoke_message_ice_candidates_get(
		    message, type, instance)) {
		return -1;
	}

	return 0;
}

static int dtls_update(struct respoke_message *message, const char *type,
	struct ast_rtp_instance *instance)
{
	struct ast_rtp_engine_dtls *dtls;
	const char *setup, *hash_type, *hash_value;
	enum ast_rtp_dtls_hash local_hash_type;

	dtls = ast_rtp_instance_get_dtls(instance);
	if (!dtls) {
		return -1;
	}

	setup = respoke_message_setup_get(message, type);
	if (!setup) {
		return -1;
	}
	if (!strcasecmp(setup, "active")) {
		dtls->set_setup(instance, AST_RTP_DTLS_SETUP_ACTIVE);
	} else if (!strcasecmp(setup, "passive")) {
		dtls->set_setup(instance, AST_RTP_DTLS_SETUP_PASSIVE);
	} else if (!strcasecmp(setup, "actpass")) {
		dtls->set_setup(instance, AST_RTP_DTLS_SETUP_ACTPASS);
	} else if (!strcasecmp(setup, "holdconn")) {
		dtls->set_setup(instance, AST_RTP_DTLS_SETUP_HOLDCONN);
	} else {
		ast_log(LOG_ERROR, "Unsupported DTLS setup value '%s'\n", setup);
		return -1;
	}

	hash_type = respoke_message_fingerprint_type_get(message, type);
	if (!hash_type) {
		return -1;
	}
	if (!strcasecmp(hash_type, "sha-1")) {
		local_hash_type = AST_RTP_DTLS_HASH_SHA1;
	} else if (!strcasecmp(hash_type, "sha-256")) {
		local_hash_type = AST_RTP_DTLS_HASH_SHA256;
	} else {
		ast_log(LOG_ERROR, "Unsupported DTLS fingerprint hash type '%s'\n", hash_type);
		return -1;
	}

	hash_value = respoke_message_fingerprint_hash_get(message, type);
	if (!hash_value) {
		return -1;
	}

	dtls->set_fingerprint(instance, local_hash_type, hash_value);

	return 0;
}

static size_t turn_credentials_request(void *ptr, size_t size, size_t nmemb, void *data)
{
	RAII_VAR(struct ast_json *, response, NULL, ast_json_unref);
	struct ast_rtp_engine_ice *ice = ast_rtp_instance_get_ice(data);
	struct ast_json *first_uri;
	const char *username, *password, *uri;
	struct ast_uri *parsed_uri;
	int port = 0;
	enum ast_transport transport = AST_TRANSPORT_TCP;

	response = ast_json_load_string(ptr, NULL);
	if (!response) {
		return size * nmemb;
	}

	username = ast_json_string_get(ast_json_object_get(response, "username"));
	password = ast_json_string_get(ast_json_object_get(response, "password"));

	/* Only one URI is supported so use the top most */
	first_uri = ast_json_array_get(ast_json_object_get(response, "uris"), 0);
	if (ast_strlen_zero(username) || ast_strlen_zero(password) || !first_uri) {
		return size * nmemb;
	}
	uri = ast_json_string_get(first_uri);

	/* To work around an issue in the URI parser ditch the scheme if present */
	if (!strncmp(uri, "turn:", 5)) {
		uri += 5;
	}

	parsed_uri = ast_uri_parse(uri);
	if (!parsed_uri) {
		return size * nmemb;
	}

	/* If no port is present the default will get used */
	if (!ast_strlen_zero(ast_uri_port(parsed_uri))) {
		sscanf(ast_uri_port(parsed_uri), "%d", &port);
	}

	/* If any query parameters exist handle them */
	if (!ast_strlen_zero(ast_uri_query(parsed_uri))) {
		char *params = ast_strdupa(ast_uri_query(parsed_uri)), *param;

		while ((param = strsep(&params, "&"))) {
			char *name = strsep(&param, "=");

			if (!strcasecmp(name, "transport")) {
				if (!strcasecmp(param, "udp")) {
					transport = AST_TRANSPORT_UDP;
				} else if (!strcasecmp(param, "tcp")) {
					transport = AST_TRANSPORT_TCP;
				}
			}
		}
	}

	ice->turn_request(data, AST_RTP_ICE_COMPONENT_RTP, transport, ast_uri_host(parsed_uri),
		port, username, password);
	ice->turn_request(data, AST_RTP_ICE_COMPONENT_RTCP, transport, ast_uri_host(parsed_uri),
		port, username, password);

	ao2_ref(parsed_uri, -1);

	return size * nmemb;
}

static void rtp_instance_setup_turn(struct respoke_session *session, struct ast_rtp_instance *instance)
{
	char curl_error[CURL_ERROR_SIZE];
	CURL *curl;
	struct ast_str *uri, *secret;
	struct curl_slist *headers = NULL;

	if (!session->endpoint->media.turn || ast_strlen_zero(session->transport->uri_api)) {
		return;
	}

	curl = curl_easy_init();
	if (!curl) {
		return;
	}

	if (!(uri = ast_str_create(128))) {
		curl_easy_cleanup(curl);
		return;
	}

	ast_str_set(&uri, 0, "%s/turn?endpointId=%s", session->transport->uri_api,
		ast_sorcery_object_get_id(session->endpoint));

	if (!(secret = ast_str_create(128))) {
		curl_easy_cleanup(curl);
		ast_free(uri);
		return;
	}

	ast_str_set(&secret, 0, "App-Secret:%s", session->transport->app_secret);
	headers = curl_slist_append(headers, ast_str_buffer(secret));
	ast_free(secret);

	if (!headers) {
		curl_easy_cleanup(curl);
		ast_free(uri);
		return;
	}

	curl_easy_setopt(curl, CURLOPT_URL, ast_str_buffer(uri));
	curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, instance);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, turn_credentials_request);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_error);

	/* The actual setup of the RTP instance for TURN happens in the callback */
	curl_easy_perform(curl);

	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	ast_free(uri);
}

static struct ast_rtp_instance *rtp_instance_create(
	struct respoke_session *session, const char *type)
{
	struct ast_rtp_engine_dtls *dtls;
	struct ast_rtp_instance *instance;
	enum ast_media_type media_type = respoke_str_to_media_type(type);
	struct ast_rtp_engine_ice *ice;

	if (!session->capabilities || !ast_format_cap_has_type(
		    session->capabilities, media_type)) {
		return NULL;
	}

	instance = ast_rtp_instance_new(
		session->endpoint->media.rtp_engine, sched,
		session->rtp_ipv6 ? &address_ipv6 : &address_ipv4, NULL);

	if (!instance) {
		ast_log(LOG_ERROR, "Unable to create RTP instance with engine '%s' "
			"for type '%s'\n", session->endpoint->media.rtp_engine,
			type);
		return NULL;
	}

	ice = ast_rtp_instance_get_ice(instance);
	if (!ice) {
		ast_log(LOG_ERROR, "ICE support is unavailable, stream for type '%s' on session '%s' not created\n",
			type, session->session_id);
		ast_rtp_instance_destroy(instance);
		return NULL;
	}

	dtls = ast_rtp_instance_get_dtls(instance);
	if (!dtls) {
		ast_log(LOG_ERROR, "DTLS support is unavailable, stream for type '%s' on session '%s' not created\n",
			type, session->session_id);
		ast_rtp_instance_destroy(instance);
		return NULL;
	}

	dtls->set_configuration(instance, &session->endpoint->media.dtls_cfg);

	ast_rtp_instance_set_prop(instance, AST_RTP_PROPERTY_RTCP, 1);

	if (media_type == AST_MEDIA_TYPE_AUDIO) {
		ast_rtp_instance_dtmf_mode_set(instance, AST_RTP_DTMF_MODE_RFC2833);
	}

	rtp_instance_setup_turn(session, instance);

	return instance;
}

static int rtp_instance_update(
	struct respoke_session *session, struct respoke_message *message,
	const char *type, struct ast_rtp_instance **instance)
{
	struct ast_sockaddr addr;
	struct ast_rtp_codecs codecs;

	if (respoke_message_media_address_get(message, type, &addr)) {
		ast_log(LOG_ERROR, "Unable to retrieve media address - type '%s'\n", type);
		return -1;
	}

	if (ast_rtp_codecs_payloads_initialize(&codecs)) {
		ast_log(LOG_ERROR, "Unable to initialize '%s' codecs\n", type);
		return -1;
	}

	if (joint_capabilities_get(message, &codecs, session->capabilities, type)) {
		ast_debug(1, "No joint capabilities found for type '%s'\n", type);
		return 0;
	}

	if (!*instance && !(*instance = rtp_instance_create(session, type))) {
		ast_rtp_codecs_payloads_destroy(&codecs);
		return -1;
	}

	ast_rtp_instance_set_remote_address(*instance, &addr);

	/* now set the codecs on the rtp instance */
	ast_rtp_codecs_payloads_copy(
		&codecs, ast_rtp_instance_get_codecs(*instance), *instance);
	ast_rtp_codecs_payloads_destroy(&codecs);

	ice_update(message, type, *instance);
	dtls_update(message, type, *instance);

	return 0;
}

static void rtp_activate(struct respoke_session *session)
{
	/* XXX BUGBUG - if we do early media this will need revisiting */
	if (session->audio_rtp) {
		ast_rtp_instance_activate(session->audio_rtp);
	}

	if (session->video_rtp) {
		ast_rtp_instance_activate(session->video_rtp);
	}
}

static void session_destroy(void *obj)
{
	struct respoke_session *session = obj;

	ast_party_id_free(&session->party_id);
	ao2_cleanup(session->capabilities);

	ast_string_field_free_memory(session);
	ao2_cleanup(session->transport);
	ao2_cleanup(session->endpoint);

	if (session->audio_rtp) {
		ast_rtp_instance_stop(session->audio_rtp);
		ast_rtp_instance_destroy(session->audio_rtp);
	}

	if (session->video_rtp) {
		ast_rtp_instance_stop(session->video_rtp);
		ast_rtp_instance_destroy(session->video_rtp);
	}

	ast_taskprocessor_unreference(session->serializer);
}

struct respoke_session *respoke_session_create(
	struct respoke_transport *transport, struct respoke_endpoint *endpoint,
	const char *local, const char *local_type, const char *local_connection, const char *remote,
	const char *remote_type, const char *remote_connection, const char *remote_appid,
	const char *session_id, struct ast_format_cap *caps)
{
	char id[AST_UUID_STR_LEN];
	struct respoke_session *session = ao2_alloc(
		sizeof(struct respoke_session), session_destroy);

	if (!session) {
		ast_log(LOG_ERROR, "Unable to allocate session\n");
		return NULL;
	}

	if (ast_string_field_init(session, 512)) {
		ast_log(LOG_ERROR, "Unable to allocate message session strings\n");
		ao2_ref(session, -1);
		return NULL;
	}

	if (!(session->endpoint = ao2_bump(endpoint))) {
		ao2_ref(session, -1);
		return NULL;
	}

	if (!transport && endpoint->state && endpoint->state->transport) {
		transport = endpoint->state->transport;
	}

	if (!transport) {
		ast_log(LOG_ERROR, "No transport available on endpoint '%s' for sending\n",
			ast_sorcery_object_get_id(endpoint));
		ao2_ref(session, -1);
		return NULL;
	}

	session->transport = ao2_bump(transport);

	ast_string_field_set(session, local, S_OR(local, endpoint->from));
	ast_string_field_set(session, local_type, S_OR(local_type, endpoint->from_type));
	ast_string_field_set(session, local_connection, local_connection);

	ast_string_field_set(session, remote, S_OR(remote, ast_sorcery_object_get_id(endpoint)));
	ast_string_field_set(session, remote_type, S_OR(remote_type, "web"));
	ast_string_field_set(session, remote_connection, remote_connection);
	ast_string_field_set(session, remote_appid, remote_appid);

	session->rtp_ipv6 = endpoint->media.rtp_ipv6;

	ast_string_field_set(session, session_id, S_OR(
				     session_id, ast_uuid_generate_str(id, sizeof(id))));

	if (!(session->serializer = respoke_create_serializer())) {
		ast_log(LOG_ERROR, "Unable to create session serializer\n");
		ao2_ref(session, -1);
		return NULL;
	}

	ast_party_id_init(&session->party_id);

	if (!(session->capabilities = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT))) {
		ast_log(LOG_ERROR, "Unable to create session capabilities\n");
		ao2_ref(session, -1);
		return NULL;
	}

	if (caps) {
		/* if given caps it's an outgoing message, so go ahead
		   and initialize the rtp instance(s) */
		ast_format_cap_get_compatible(session->endpoint->media.codecs, caps,
					      session->capabilities);
		if (!ast_format_cap_count(session->capabilities)) {
			ast_format_cap_append_from_cap(session->capabilities, session->endpoint->media.codecs, AST_MEDIA_TYPE_UNKNOWN);
		}
		session->audio_rtp = rtp_instance_create(session, TYPE_AUDIO);
		session->video_rtp = rtp_instance_create(session, TYPE_VIDEO);

		if (!session->audio_rtp && !session->video_rtp) {
			ast_log(LOG_ERROR, "Unable to create session - "
				"no audio or video rtp\n");
			ao2_ref(session, -1);
			return NULL;
		}
	}

	return session;
}

static void session_update_callerid(struct respoke_session *session,
	struct respoke_message *message)
{
	const char *name = NULL, *number = NULL;
	struct ast_party_id id;

	ast_party_id_init(&id);

	name = S_COR(session->endpoint->callerid.name.valid, session->endpoint->callerid.name.str,
		respoke_message_callerid_name_get(message));
	if (!ast_strlen_zero(name)) {
		id.name.str = ast_strdup(name);
		id.name.valid = 1;
	}

	number = S_COR(session->endpoint->callerid.number.valid, session->endpoint->callerid.number.str,
		respoke_message_callerid_number_get(message));
	if (!ast_strlen_zero(number)) {
		id.number.str = ast_strdup(number);
		id.number.valid = 1;
	}

	/* Save to channel driver copy */
	ast_party_id_copy(&session->party_id, &id);

	/* If the channel already exists this is an update */
	if (session->channel) {
		struct ast_party_connected_line connected;
		struct ast_party_caller caller;

		/* Fill connected line information */
		ast_party_connected_line_init(&connected);
		connected.id = id;
		connected.source = AST_CONNECTED_LINE_UPDATE_SOURCE_ANSWER;

		/* Update our channel CALLERID() */
		ast_party_caller_init(&caller);
		caller.id = connected.id;
		caller.ani = connected.id;
		caller.ani2 = ast_channel_caller(session->channel)->ani2;
		ast_channel_set_caller_event(session->channel, &caller, NULL);

		/* Tell peer about the new connected line information. */
		ast_channel_queue_connected_line_update(session->channel, &connected, NULL);
	}

	ast_party_id_free(&id);
}

static int session_update(struct respoke_session *session,
			  struct respoke_message *message)
{
	if (rtp_instance_update(session, message, TYPE_AUDIO,
				&session->audio_rtp) ||
	    rtp_instance_update(session, message, TYPE_VIDEO,
				&session->video_rtp)) {
		respoke_session_error(session, "Unable to create/update session rtp");
		return -1;
	}

	if (!session->audio_rtp && !session->video_rtp) {
		respoke_session_error(session, "Unable to create/update "
				      "session rtp - no rtp");
		return -1;
	}

	session_update_callerid(session, message);

	return 0;
}

const char *respoke_session_get_exten(const struct respoke_session *session)
{
	return session->local;
}

int respoke_session_offer(struct respoke_session *session)
{
	struct ast_party_id effective_id;
	struct ast_party_id connected_id;
	const char *name, *number;
	int res;

	/* Must do a deep copy unless we hold the channel lock the entire time. */
	ast_party_id_init(&connected_id);
	ast_channel_lock(session->channel);
	effective_id = ast_channel_connected_effective_id(session->channel);
	ast_party_id_copy(&connected_id, &effective_id);
	ast_channel_unlock(session->channel);

	if (session->endpoint->callerid.name.valid) {
		name = session->endpoint->callerid.name.str;
	} else if (connected_id.name.valid) {
		name = connected_id.name.str;
	} else {
		name = "<unknown>";
	}

	if (session->endpoint->callerid.number.valid) {
		number = session->endpoint->callerid.number.str;
	} else if (connected_id.number.valid) {
		number = connected_id.number.str;
	} else {
		number = "<unknown>";
	}

	res = respoke_session_message_send_and_release(session,
		respoke_message_create_offer(
			session->transport, session->endpoint, session->rtp_ipv6,
			session->local, session->local_type, session->local_connection,
			session->remote, session->remote_type, session->remote_connection,
			session->remote_appid, session->session_id, session->capabilities,
			session->audio_rtp, session->video_rtp, name, number));

	ast_party_id_free(&connected_id);

	if (!res) {
		ao2_link(sessions, session);
	}

	return 0;
}

int respoke_session_answer(struct respoke_session *session)
{
	if (session->channel)
	{
		ast_verbose("\n\n<-- Respoke Session Answer: %s -->\n\n", ast_channel_name(session->channel));

		pbx_builtin_setvar_helper(session->channel, "respoke_session_local", session->local);
		pbx_builtin_setvar_helper(session->channel, "respoke_session_local_type", session->local_type);
		pbx_builtin_setvar_helper(session->channel, "respoke_session_local_connection", session->local_connection);
		pbx_builtin_setvar_helper(session->channel, "respoke_session_remote", session->remote);
		pbx_builtin_setvar_helper(session->channel, "respoke_session_remote_type", session->remote_type);
		pbx_builtin_setvar_helper(session->channel, "respoke_session_remote_connection", session->remote_connection);
		pbx_builtin_setvar_helper(session->channel, "respoke_session_remote_appid", session->remote_appid);
		pbx_builtin_setvar_helper(session->channel, "respoke_session_id", session->session_id);

		manager_event(EVENT_FLAG_SYSTEM, "respoke_session", "channel: %s\n"
			"id: %s\nlocal: %s\nlocal_type: %s\nlocal_connection: %s\n"
			"remote: %s\nremote_type: %s\nremote_connection: %s\nremote_appid: %s\r\n",
			ast_channel_name(session->channel), session->session_id, session->local,
			session->local_type, session->local_connection, session->remote, session->remote_type,
			session->remote_connection, session->remote_appid);

	}

	int res = respoke_session_message_send_and_release(session,
		respoke_message_create_answer(
			session->transport, session->endpoint, session->rtp_ipv6,
			session->local, session->local_type, session->local_connection,
			session->remote, session->remote_type, session->remote_connection,
			session->remote_appid, session->session_id, session->capabilities,
			session->audio_rtp, session->video_rtp));

	if (!res) {
		rtp_activate(session);
		ice_start(session, AST_RTP_ICE_ROLE_CONTROLLED);
	}

	return res;
}

int respoke_session_status(struct respoke_session *session, enum respoke_status status)
{
	return respoke_message_send_and_release(
		respoke_message_create_status(
			session->transport, session->endpoint,
			session->local, session->local_type, session->local_connection,
			session->remote, session->remote_type, session->remote_connection,
			session->remote_appid, session->session_id, status), NULL, NULL);
}

int respoke_session_bye(struct respoke_session *session, enum respoke_status status)
{
	ao2_unlink(sessions, session);

	/* if terminated we don't want to send the bye */
	if (session->terminated) {
		return 0;
	}

	return respoke_session_message_send_and_release(session,
		respoke_message_create_bye(
			session->transport, session->endpoint,
			session->local, session->local_type, session->local_connection,
			session->remote, session->remote_type, session->remote_connection,
			session->remote_appid, session->session_id, status));
}

int respoke_session_error(const struct respoke_session *session, const char *format, ...)
{
	int res;
	va_list ap;

	va_start(ap, format);
	res = respoke_message_send_error_va(
		session->transport, session->endpoint, NULL, NULL,
		session->local, session->local_type, session->local_connection,
		session->remote, session->remote_type, session->remote_connection,
		session->remote_appid, session->session_id, format, ap);
	va_end(ap);
	return res;
}

/*!
 * \brief Locate the session based upon the message's session id
 *
 * \note If the session is not found an error message is sent.
 */
static struct respoke_session *find_session_by_message_session_id(
	struct respoke_message *message)
{
	const char *id = respoke_message_session_id_get(message);
	struct respoke_session *session;

	if (ast_strlen_zero(id)) {
		respoke_message_send_error_from_message(
			message, NULL, NULL, "Missing session id on received '%s'",
			respoke_message_signal_type_get(message));
		return NULL;
	}

	if (!(session = ao2_find(sessions, id, OBJ_SEARCH_KEY))) {
		respoke_message_send_error_from_message(
			message, NULL, NULL, "Received %s, but session %s not found",
			respoke_message_signal_type_get(message),
			respoke_message_session_id_get(message));
		return NULL;
	}
	return session;
}

static unsigned int receive_offer(struct respoke_transaction *transaction, struct respoke_message *message)
{
	const char *id = respoke_message_session_id_get(message);
	RAII_VAR(struct respoke_session *, session, NULL, ao2_cleanup);

	if (ast_strlen_zero(id)) {
		respoke_message_send_error_from_message(
			message, NULL, NULL, "Missing session id on received '%s'",
			respoke_message_signal_type_get(message));
		return 0;
	}

	if ((session = ao2_find(sessions, id, OBJ_SEARCH_KEY))) {
		return session_update(session, message) ? 0 : 1;
	}

	if (!(session = respoke_session_create(
		      message->transport, message->endpoint,
		      respoke_message_to_get(message),
		      respoke_message_to_type_get(message),
		      respoke_message_to_connection_get(message),
		      respoke_message_from_get(message),
		      respoke_message_from_type_get(message),
		      respoke_message_from_connection_get(message),
		      respoke_message_from_appid_get(message),
		      respoke_message_session_id_get(message), NULL))) {
		respoke_message_send_error_from_message(
			message, NULL, NULL, "Unable to create session");
		return 0;
	}

	session->rtp_ipv6 = respoke_message_is_ipv6(message);
	if (session_update(session, message)) {
		return 0;
	}

	if (session_on_offer(session)) {
		return 0;
	}

	ao2_link(sessions, session);
	return 1;
}

struct respoke_message_handler offer_handler = {
	.types = "signal",
	.signaltypes = "offer",
	.receive_message = receive_offer
};

static unsigned int receive_answer(struct respoke_transaction *transaction, struct respoke_message *message)
{
	RAII_VAR(struct respoke_session *, session,
		 find_session_by_message_session_id(message), ao2_cleanup);

	if (!session) {
		return 0;
	}

	if (session_update(session, message)) {
		return 0;
	}

	if (session_on_answer(session, respoke_message_answer_get(message))) {
		return 0;
	}

	rtp_activate(session);

	ice_start(session, AST_RTP_ICE_ROLE_CONTROLLING);

	return 1;
}

struct respoke_message_handler answer_handler = {
	.types = "signal",
	.signaltypes = "answer",
	.receive_message = receive_answer
};

static unsigned int receive_status(struct respoke_transaction *transaction, struct respoke_message *message)
{
	RAII_VAR(struct respoke_session *, session,
		 find_session_by_message_session_id(message), ao2_cleanup);

	if (!session) {
		return 0;
	}

	if (session_on_status(session, respoke_message_status_get(message))) {
		return 0;
	}

	return 1;
}

struct respoke_message_handler status_handler = {
	.types = "signal",
	.signaltypes = "status",
	.receive_message = receive_status
};

#if 0
static unsigned int receive_ice_candidates(struct respoke_transaction *transaction, struct respoke_message *message)
{
	struct respoke_session *session = find_session_by_message_session_id(message);

	if (!session) {
		return 0;
	}

	if (session->audio_rtp) {
		respoke_message_ice_candidates_get(message, TYPE_AUDIO,
						   session->audio_rtp);
	}

	if (session->video_rtp) {
		respoke_message_ice_candidates_get(message, TYPE_VIDEO,
						   session->video_rtp);
	}

	ao2_ref(session, -1);
	return 1;
}

struct respoke_message_handler ice_candidates_handler = {
	.types = "signal",
	.signaltypes = "iceCandidates",
	.receive_message = receive_ice_candidates
};
#endif

static unsigned int receive_bye(struct respoke_transaction *transaction, struct respoke_message *message)
{
	int res;
	struct respoke_session *session =
		find_session_by_message_session_id(message);

	if (!session) {
		return 0;
	}

	session->terminated = 1;
	res = session_on_end(session, respoke_message_reason_get(message), message);

	ao2_ref(session, -1);

	return res ? 0 : 1;
}

struct respoke_message_handler bye_handler = {
	.types = "signal",
	.signaltypes = "bye",
	.receive_message = receive_bye
};

static unsigned int receive_error(struct respoke_transaction *transaction, struct respoke_message *message)
{
	int res;
	struct respoke_session *session =
		find_session_by_message_session_id(message);

	if (!session) {
		return 0;
	}

	session->terminated = 1;
	ast_log(LOG_ERROR, "%s\n", respoke_message_error_detail_get(message));
	res = session_on_end(session, RESPOKE_STATUS_UNKNOWN, message);

	ao2_unlink(sessions, session);
	ao2_ref(session, -1);

	return res ? 0 : 1;
}

struct respoke_message_handler error_handler = {
	.types = "signal",
	.signaltypes = "error",
	.receive_message = receive_error
};

/*! \brief Task which terminates the session */
static int transaction_session_terminate(void *data)
{
	struct respoke_transaction *transaction = data;
	struct respoke_session *session = respoke_transaction_get_object(transaction);

	if (!session->terminated) {
		ast_debug(1, "Received a fatal transaction response on session '%s' - terminating channel\n",
			session->session_id);

		session->terminated = 1;
		if (session->channel) {
			ast_queue_hangup_with_cause(session->channel, AST_CAUSE_SWITCH_CONGESTION);
		}
	}

	ao2_ref(transaction, -1);

	return 0;
}

static void transaction_session_fatal_without_bye(struct respoke_transaction *transaction,
	void *obj, struct ast_json *json)
{
	struct respoke_session *session = obj;

	if (respoke_transaction_get_state(transaction) != RESPOKE_TRANSACTION_STATE_RESPONSE_ERROR) {
		return;
	}

	if (respoke_push_task(session->serializer, transaction_session_terminate, ao2_bump(transaction))) {
		ao2_ref(transaction, -1);
	}
}

int respoke_session_message_send(struct respoke_session *session, struct respoke_message *message)
{
	return respoke_message_send(message, transaction_session_fatal_without_bye, session);
}

int respoke_session_message_send_and_release(struct respoke_session *session, struct respoke_message *message)
{
	return respoke_message_send_and_release(message, transaction_session_fatal_without_bye, session);
}

static int unload_module(void)
{
	respoke_unregister_message_handler(&error_handler);
	respoke_unregister_message_handler(&bye_handler);
#if 0
	respoke_unregister_message_handler(&ice_candidates_handler);
#endif
	respoke_unregister_message_handler(&status_handler);
	respoke_unregister_message_handler(&answer_handler);
	respoke_unregister_message_handler(&offer_handler);

	ao2_cleanup(sessions);

	if (sched) {
		ast_sched_context_destroy(sched);
	}

	return 0;
}

static int load_module(void)
{
	if (!(sessions = ao2_container_alloc(
		      MAX_SESSION_BUCKETS, sessions_hash, sessions_cmp))) {
		return AST_MODULE_LOAD_FAILURE;
	}

	if (respoke_register_message_handler(&offer_handler) ||
	    respoke_register_message_handler(&answer_handler) ||
	    respoke_register_message_handler(&status_handler) ||
#if 0
	    respoke_register_message_handler(&ice_candidates_handler) ||
#endif
	    respoke_register_message_handler(&bye_handler) ||
	    respoke_register_message_handler(&error_handler)) {
		unload_module();
		return AST_MODULE_LOAD_FAILURE;
	}

	if (!(sched = ast_sched_context_create()) ||
	    ast_sched_start_thread(sched)) {
		ast_log(LOG_ERROR, "Unable to create scheduler "
			"context/thread.\n");
		unload_module();
		return AST_MODULE_LOAD_FAILURE;
	}

	ast_sockaddr_parse(&address_ipv4, "0.0.0.0", 0);
	ast_sockaddr_parse(&address_ipv6, "::", 0);
	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS |
		AST_MODFLAG_LOAD_ORDER, "Respoke Session Resource",
		.support_level = AST_MODULE_SUPPORT_EXTENDED,
		.load = load_module,
		.unload = unload_module,
		.load_pri = AST_MODPRI_APP_DEPEND,
	       );
