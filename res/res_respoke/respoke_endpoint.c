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

#include "asterisk.h"

#include "asterisk/cli.h"
#include "asterisk/format.h"
#include "asterisk/format_cap.h"
#include "asterisk/sorcery.h"
#include "asterisk/utils.h"
#include "asterisk/linkedlists.h"
#include "asterisk/callerid.h"
#include "asterisk/test.h"
#include "asterisk/uri.h"

#include "asterisk/respoke.h"
#include "asterisk/respoke_endpoint.h"
#include "asterisk/respoke_message.h"
#include "asterisk/respoke_transport.h"
#include "include/respoke_private.h"
#include "include/respoke_app.h"
#include "include/respoke_sdk_header.h"

#define DEFAULT_STATE_BUCKETS 53

static AO2_GLOBAL_OBJ_STATIC(endpoint_states);

/*! \brief hashing function for state objects */
static int endpoint_state_hash(const void *obj, const int flags)
{
	const struct respoke_endpoint_state *object;
	const char *key;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_KEY:
		key = obj;
		break;
	case OBJ_SEARCH_OBJECT:
		object = obj;
		key = object->name;
		break;
	default:
		ast_assert(0);
		return 0;
	}
	return ast_str_hash(key);
}

/*! \brief comparator function for state objects */
static int endpoint_state_cmp(void *obj, void *arg, int flags)
{
	const struct respoke_endpoint_state *object_left = obj;
	const struct respoke_endpoint_state *object_right = arg;
	const char *right_key = arg;
	int cmp;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
		right_key = object_right->name;
		/* Fall through */
	case OBJ_SEARCH_KEY:
		cmp = strcmp(object_left->name, right_key);
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

struct endpoint_identifier_list {
	const struct respoke_endpoint_identifier *identifier;
	AST_RWLIST_ENTRY(endpoint_identifier_list) list;
};

static AST_RWLIST_HEAD_STATIC(endpoint_identifiers, endpoint_identifier_list);

int respoke_register_endpoint_identifier(const struct respoke_endpoint_identifier *identifier)
{
	struct endpoint_identifier_list *endpoint_identifier_list_item;
	SCOPED_LOCK(lock, &endpoint_identifiers, AST_RWLIST_WRLOCK, AST_RWLIST_UNLOCK);

	endpoint_identifier_list_item = ast_calloc(1, sizeof(*endpoint_identifier_list_item));
	if (!endpoint_identifier_list_item) {
		return -1;
	}
	endpoint_identifier_list_item->identifier = identifier;

	AST_RWLIST_INSERT_TAIL(&endpoint_identifiers, endpoint_identifier_list_item, list);
	ast_debug(1, "Registered endpoint identifier '%p'\n", identifier);

	ast_module_ref(respoke_get_module_info()->self);

	return 0;
}

void respoke_unregister_endpoint_identifier(const struct respoke_endpoint_identifier *identifier)
{
	struct endpoint_identifier_list *iter;
	SCOPED_LOCK(lock, &endpoint_identifiers, AST_RWLIST_WRLOCK, AST_RWLIST_UNLOCK);

	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&endpoint_identifiers, iter, list) {
		if (iter->identifier == identifier) {
			AST_RWLIST_REMOVE_CURRENT(list);
			ast_free(iter);
			ast_debug(1, "Unregistered endpoint identifier '%p'\n", identifier);
			ast_module_unref(respoke_get_module_info()->self);
			break;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;
}

struct respoke_endpoint *respoke_endpoint_identify(
	struct respoke_message *message)
{
	struct endpoint_identifier_list *iter;
	struct respoke_endpoint *endpoint = NULL;

	SCOPED_LOCK(lock, &endpoint_identifiers,
		    AST_RWLIST_RDLOCK, AST_RWLIST_UNLOCK);

	AST_RWLIST_TRAVERSE(&endpoint_identifiers, iter, list) {
		ast_assert(iter->identifier->identify != NULL);

		if ((endpoint = iter->identifier->identify(message))) {
			break;
		}
	}
	return endpoint;
}

static void respoke_endpoint_destroy(void *obj)
{
	struct respoke_endpoint *endpoint = obj;

	ao2_cleanup(endpoint->media.codecs);

	ast_string_field_free_memory(&endpoint->media);
	ast_string_field_free_memory(endpoint);
	ast_party_id_free(&endpoint->callerid);
	ast_rtp_dtls_cfg_free(&endpoint->media.dtls_cfg);
}

static void *respoke_endpoint_alloc(const char *name)
{
	struct respoke_endpoint *endpoint = ast_sorcery_generic_alloc(
		sizeof(*endpoint), respoke_endpoint_destroy);

	if (!endpoint) {
		return NULL;
	}

	if (ast_string_field_init(endpoint, 256) ||
	    ast_string_field_init(&endpoint->media, 128)) {
		ao2_ref(endpoint, -1);
		return NULL;
	}

	if (!(endpoint->media.codecs = ast_format_cap_alloc(
		      AST_FORMAT_CAP_FLAG_DEFAULT))) {
		ao2_ref(endpoint, -1);
		return NULL;
	}

	ast_string_field_set(endpoint, from, name);

	endpoint->media.dtls_cfg.enabled = 1;
	endpoint->media.dtls_cfg.suite = AST_AES_CM_128_HMAC_SHA1_80;

	return endpoint;
}

static void respoke_endpoint_state_destroy(void *obj)
{
	struct respoke_endpoint_state *state = obj;

	ao2_cleanup(state->transport);
	ao2_cleanup(state->app);
}

struct respoke_endpoint_state *respoke_endpoint_state_retrieve(const char *name)
{
	RAII_VAR(struct ao2_container *, states, ao2_global_obj_ref(endpoint_states), ao2_cleanup);

	if (!states) {
		return NULL;
	}

	return ao2_find(states, name, OBJ_SEARCH_KEY);
}

static struct respoke_endpoint_state *respoke_endpoint_state_alloc(struct respoke_endpoint *endpoint)
{
	struct respoke_endpoint_state *state;
	RAII_VAR(struct ao2_container *, states, ao2_global_obj_ref(endpoint_states), ao2_cleanup);

	if (!states) {
		return NULL;
	}

	state = ao2_alloc(sizeof(*state) + strlen(ast_sorcery_object_get_id(endpoint)) + 1, respoke_endpoint_state_destroy);
	if (!state) {
		ast_log(LOG_ERROR, "Could not allocate persistent state for endpoint '%s'\n",
			ast_sorcery_object_get_id(endpoint));
		return NULL;
	}
	strcpy(state->name, ast_sorcery_object_get_id(endpoint)); /* safe */
	ao2_link(states, state);

	return state;
}

static int can_reuse_state(struct respoke_endpoint_state *state, struct respoke_app *app,
	struct respoke_transport *transport)
{
	if (strcmp(ast_sorcery_object_get_id(state->app), ast_sorcery_object_get_id(app)) ||
		strcmp(state->app->secret, app->secret) ||
		strcmp(ast_sorcery_object_get_id(state->transport), ast_sorcery_object_get_id(transport)) ||
		strcmp(state->transport->protocol, transport->protocol)) {
		return 0;
	}

	return 1;
}

static void respoke_endpoint_auth_callback(struct respoke_transport *transport, void *data,
	enum respoke_transport_status status)
{
	const char *name = data;
	struct respoke_endpoint *endpoint;
	struct respoke_message *message;
	struct ast_json *json;
	char url[strlen(name) + strlen("/v1/endpoints//connections") + 1];

	if (status == RESPOKE_TRANSPORT_STATUS_DISCONNECTED) {
		ast_verb(2, "Transport for endpoint '%s' has been disconnected\n", name);
		return;
	} else if (status == RESPOKE_TRANSPORT_STATUS_CONNECTED) {
		ast_verb(2, "Transport for endpoint '%s' has connected\n", name);
	}

	endpoint = ast_sorcery_retrieve_by_id(respoke_get_sorcery(), RESPOKE_ENDPOINT, name);
	if (!endpoint) {
		ast_log(LOG_ERROR, "Could not authenticate/register on transport '%s' with endpoint '%s' as it was not found\n",
			ast_sorcery_object_get_id(transport), name);
		return;
	}

	if (!(json = ast_json_pack("{s:s}", "clientType", "asterisk"))) {
		ast_log(LOG_ERROR, "Unable to create message data object on transport '%s' with endpoint '%s'\n",
			ast_sorcery_object_get_id(transport), name);
		return;
	}

	sprintf(url, "/v1/endpoints/%s/connections", name);
	message = respoke_message_alloc(transport, NULL, json, endpoint, url);
	ast_json_unref(json);
	if (!message) {
		ast_log(LOG_ERROR, "Could not create authenticate/register message on transport '%s' for endpoint '%s'\n",
			ast_sorcery_object_get_id(transport), name);
		ao2_ref(endpoint, -1);
		return;
	}

	if (!respoke_message_send_and_release(message, NULL, NULL)) {
		ast_test_suite_event_notify("RESPOKE_ENDPOINT_CONNECT",
					    "Endpoint: %s\r\n", name);
	}
	ao2_ref(endpoint, -1);
}

static int respoke_endpoint_apply(const struct ast_sorcery *sorcery, void *obj)
{
	RAII_VAR(struct ao2_container *, states, ao2_global_obj_ref(endpoint_states), ao2_cleanup);
	struct respoke_endpoint *endpoint = obj;
	RAII_VAR(struct respoke_endpoint_state *, state, NULL, ao2_cleanup);
	struct respoke_app *app;
	struct respoke_transport *transport;
	char *name;
	struct ast_uri *uri;
	char sdk_header[80] = "";
	char encoded_sdk_header[180] = "";

	if (!endpoint->register_with_service) {
		/* This is done in case the configuration for the endpoint goes from register with service
		* to not registering with service.
		*/
		state = respoke_endpoint_state_retrieve(ast_sorcery_object_get_id(endpoint));
		if (state) {
			ao2_unlink(states, state);
		}
		return 0;
	}

	if (ast_strlen_zero(endpoint->app_name)) {
		ast_log(LOG_ERROR, "An application name must be specified on '%s' for registration to occur\n",
			ast_sorcery_object_get_id(endpoint));
		return -1;
	} else if (ast_strlen_zero(endpoint->transport_name)) {
		ast_log(LOG_ERROR, "A transport name must be specified on '%s' for registration to occur\n",
			ast_sorcery_object_get_id(endpoint));
		return -1;
	}

	app = ast_sorcery_retrieve_by_id(respoke_get_sorcery(), RESPOKE_APP,
		endpoint->app_name);
	if (!app) {
		ast_log(LOG_ERROR, "Application '%s' specified on endpoint '%s' was not found\n",
			endpoint->app_name, ast_sorcery_object_get_id(endpoint));
		return -1;
	}

	transport = ast_sorcery_retrieve_by_id(respoke_get_sorcery(), "transport",
		endpoint->transport_name);
	if (!transport) {
		ast_log(LOG_ERROR, "Transport '%s' specified on endpoint '%s' was not found\n",
			endpoint->transport_name, ast_sorcery_object_get_id(endpoint));
		ao2_ref(app, -1);
		return -1;
	}

	/* Determine if we need fresh state and to reconnect */
	state = respoke_endpoint_state_retrieve(ast_sorcery_object_get_id(endpoint));
	if (state) {
		if (can_reuse_state(state, app, transport)) {
			/* Nothing has changed that warrants us reconnecting */
			ao2_ref(app, -1);
			ao2_ref(transport, -1);
			return 0;
		}
		/* Can't reuse it; get rid of the old state */
		ao2_unlink(states, state);
		ao2_ref(state, -1);
		state = NULL;
	}

	state = respoke_endpoint_state_alloc(endpoint);
	if (!state) {
		ast_log(LOG_ERROR, "Could not allocate persistent state for endpoint '%s'\n",
			ast_sorcery_object_get_id(endpoint));
		ao2_ref(app, -1);
		ao2_ref(transport, -1);
		return -1;
	}

	state->app = ast_sorcery_copy(respoke_get_sorcery(), app);
	state->transport = ast_sorcery_copy(respoke_get_sorcery(), transport);
	ao2_ref(app, -1);
	ao2_ref(transport, -1);

	if (!state->transport || !state->app) {
		ast_log(LOG_ERROR, "Could not create necessary objects on endpoint state '%s'\n",
			state->name);
		return -1;
	}

	/* Update the URI to include the provided App-Secret from the application */
	uri = ast_uri_parse_http(state->transport->uri);
	if (!uri) {
		ast_log(LOG_ERROR, "Could not parse provided transport URI '%s' on endpoint '%s'\n",
			state->transport->uri, state->name);
		return -1;
	}

	respoke_get_sdk_header(sdk_header, sizeof(sdk_header));
	ast_uri_encode(sdk_header, encoded_sdk_header, sizeof(encoded_sdk_header), ast_uri_http);
	ast_string_field_build(state->transport, uri, "%s%s%s%s%s/?app-secret=%s&Respoke-SDK=%s",
		S_OR(ast_uri_scheme(uri), ""),
		!ast_strlen_zero(ast_uri_scheme(uri)) ? "://" : "",
		ast_uri_host(uri),
		!ast_strlen_zero(ast_uri_port(uri)) ? ":" : "",
		S_OR(ast_uri_port(uri), ""),
		state->app->secret,
		encoded_sdk_header);

	ao2_ref(uri, -1);
	ast_string_field_set(state->transport, app_secret, state->app->secret);

	state->transport->state = respoke_transport_create_instance(state->transport);
	if (!state->transport->state) {
		ast_log(LOG_ERROR, "Could not create a connection using transport '%s' on endpoint '%s'\n",
			endpoint->transport_name, ast_sorcery_object_get_id(endpoint));
		return -1;
	}

	/* The name is purposely passed in instead of a pointer to the endpoint so we can drop the endpoint on
	 * a reload if need be
	 */
	name = ao2_alloc_options(strlen(ast_sorcery_object_get_id(endpoint)) + 1, NULL, AO2_ALLOC_OPT_LOCK_NOLOCK);
	if (!name) {
		ast_log(LOG_ERROR, "Could not set name for transport callback on endpoint '%s'\n",
			ast_sorcery_object_get_id(endpoint));
		return -1;
	}
	strcpy(name, ast_sorcery_object_get_id(endpoint)); /* Safe */

	respoke_transport_set_callback(state->transport->state, respoke_endpoint_auth_callback, name);

	if (respoke_transport_start(state->transport)) {
		ast_log(LOG_ERROR, "Could not start instance of transport '%s' on endpoint '%s'\n",
			endpoint->transport_name, ast_sorcery_object_get_id(endpoint));
		return -1;
	}

	/* states container holds the only reference, allow the RAII_VAR to drop it */

	return 0;
}

static char *cli_show_endpoints(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
#define FORMAT "%-20.20s %-20.20s %-20.20s\n"
	struct ao2_container *endpoints;
	struct ao2_iterator i;
	struct respoke_endpoint *endpoint;

	switch (cmd) {
	case CLI_INIT:
		e->command = "respoke show endpoints";
		e->usage =
			"Usage: respoke show endpoints\n"
			"       Lists all configured Respoke endpoints.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}

	endpoints = ast_sorcery_retrieve_by_fields(
		respoke_get_sorcery(), RESPOKE_ENDPOINT,
		AST_RETRIEVE_FLAG_MULTIPLE | AST_RETRIEVE_FLAG_ALL, NULL);

	if (!endpoints) {
		ast_cli(a->fd, "Could not retrieve configured Respoke endpoints\n");
		return CLI_SUCCESS;
	}

	ast_cli(a->fd, FORMAT, "Endpoint", "App", "Context");

	i = ao2_iterator_init(endpoints, 0);
	for (; (endpoint = ao2_iterator_next(&i)); ao2_ref(endpoint, -1)) {
		ast_cli(a->fd, FORMAT, ast_sorcery_object_get_id(endpoint),
			endpoint->app_name ,endpoint->context);
	}
	ao2_iterator_destroy(&i);

	ao2_ref(endpoints, -1);

	return CLI_SUCCESS;
#undef FORMAT
}

static char *sorcery_complete_cli(const char *type, const char *word, int state)
{
	struct ao2_container *container;
	char *result = NULL;
	int wordlen = strlen(word);
	int which = 0;
	struct ao2_iterator i;
	void *obj;

	if (!(container = ast_sorcery_retrieve_by_fields(
		      respoke_get_sorcery(), type,
		      AST_RETRIEVE_FLAG_MULTIPLE | AST_RETRIEVE_FLAG_ALL, NULL))) {
		return NULL;
	}

	i = ao2_iterator_init(container, 0);
	for (; (obj = ao2_iterator_next(&i)); ao2_ref(obj, -1)) {
		const char *id = ast_sorcery_object_get_id(obj);
		if (!strncasecmp(word, id, wordlen) && ++which > state &&
		    (result = ast_strdup(id))) {
			ao2_ref(obj, -1);
			break;
		}
	}
	ao2_iterator_destroy(&i);

	ao2_ref(container, -1);
	return result;
}

static int sorcery_object_to_cli(int fd, const void *obj)
{
	struct ast_variable *objset = ast_sorcery_objectset_create2(
			 respoke_get_sorcery(), obj, AST_HANDLER_ONLY_STRING);
	struct ast_variable *i;

	if (!objset) {
		ast_cli(fd, "Unable to retrieve '%s' details\n",
			ast_sorcery_object_get_type(obj));
		return -1;
	}

	ast_cli(fd, "%s: %s\n", ast_sorcery_object_get_type(obj),
		ast_sorcery_object_get_id(obj));

	for (i = objset; i; i = i->next) {
		ast_cli(fd, "%s: %s\n", i->name, i->value);
	}

	ast_variables_destroy(objset);
	return 0;
}

static char *cli_show_endpoint(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct respoke_endpoint *endpoint;

	switch (cmd) {
	case CLI_INIT:
		e->command = "respoke show endpoint";
		e->usage =
			"Usage: respoke show endpoint <endpoint>\n"
			"       List attributes on a given endpoint.\n";
		return NULL;
	case CLI_GENERATE:
		return sorcery_complete_cli(RESPOKE_ENDPOINT, a->word, a->n);
	}

	if (a->argc != 4) {
		return CLI_SHOWUSAGE;
	}

	if (!(endpoint = ast_sorcery_retrieve_by_id(
		      respoke_get_sorcery(), RESPOKE_ENDPOINT, a->argv[3]))) {
		ast_cli(a->fd, "Unable to retrieve endpoint %s\n", a->argv[3]);
		return CLI_FAILURE;
	}

	if (sorcery_object_to_cli(a->fd, endpoint)) {
		ao2_ref(endpoint, -1);
		return CLI_FAILURE;
	}

	ao2_ref(endpoint, -1);
	return CLI_SUCCESS;
}

static struct ast_cli_entry cli_respoke_endpoint[] = {
	AST_CLI_DEFINE(cli_show_endpoints, "List configured Respoke endpoints"),
	AST_CLI_DEFINE(cli_show_endpoint, "List attributes on a Respoke endpoint")
};

static int caller_id_handler(const struct aco_option *opt, struct ast_variable *var, void *obj)
{
	struct respoke_endpoint *endpoint = obj;
	char cid_name[80] = { '\0' };
	char cid_num[80] = { '\0' };

	ast_callerid_split(var->value, cid_name, sizeof(cid_name), cid_num, sizeof(cid_num));
	if (!ast_strlen_zero(cid_name)) {
		endpoint->callerid.name.str = ast_strdup(cid_name);
		if (!endpoint->callerid.name.str) {
			return -1;
		}
		endpoint->callerid.name.valid = 1;
	}
	if (!ast_strlen_zero(cid_num)) {
		endpoint->callerid.number.str = ast_strdup(cid_num);
		if (!endpoint->callerid.number.str) {
			return -1;
		}
		endpoint->callerid.number.valid = 1;
	}
	return 0;
}

static int caller_id_to_str(const void *obj, const intptr_t *args, char **buf)
{
	const struct respoke_endpoint *endpoint = obj;
	const char *name = S_COR(endpoint->callerid.name.valid,
				 endpoint->callerid.name.str, NULL);
	const char *number = S_COR(endpoint->callerid.number.valid,
				   endpoint->callerid.number.str, NULL);

	/* make sure size is at least 10 - that should cover the "<unknown>"
	   case as well as any additional formatting characters added in
	   the name and/or number case. */
	int size = 10;
	size += name ? strlen(name) : 0;
	size += number ? strlen(number) : 0;

	if (!(*buf = ast_calloc(size + 1, sizeof(char)))) {
		return -1;
	}

	ast_callerid_merge(*buf, size + 1, name, number, NULL);
	return 0;
}

static int dtls_handler(const struct aco_option *opt,
			 struct ast_variable *var, void *obj)
{
	struct respoke_endpoint *endpoint = obj;
	char *name = ast_strdupa(var->name);
	char *front, *buf = name;

	/* strip out underscores in the name */
	front = strtok(buf, "_");
	while (front) {
		int size = strlen(front);
		ast_copy_string(buf, front, size + 1);
		buf += size;
		front = strtok(NULL, "_");
	}

	return ast_rtp_dtls_cfg_parse(&endpoint->media.dtls_cfg, name, var->value);
}

static int dtls_verify_to_str(const void *obj, const intptr_t *args, char **buf)
{
	const struct respoke_endpoint *endpoint = obj;
	*buf = ast_strdup(AST_YESNO(endpoint->media.dtls_cfg.verify));
	return 0;
}

static int dtls_rekey_to_str(const void *obj, const intptr_t *args, char **buf)
{
	const struct respoke_endpoint *endpoint = obj;

	return ast_asprintf(
		buf, "%u", endpoint->media.dtls_cfg.rekey) >= 0 ? 0 : -1;
}

static int dtls_cert_file_to_str(const void *obj, const intptr_t *args, char **buf)
{
	const struct respoke_endpoint *endpoint = obj;
	*buf = ast_strdup(endpoint->media.dtls_cfg.certfile);
	return 0;
}

static int dtls_private_key_to_str(const void *obj, const intptr_t *args, char **buf)
{
	const struct respoke_endpoint *endpoint = obj;
	*buf = ast_strdup(endpoint->media.dtls_cfg.pvtfile);
	return 0;
}

static int dtls_cipher_to_str(const void *obj, const intptr_t *args, char **buf)
{
	const struct respoke_endpoint *endpoint = obj;
	*buf = ast_strdup(endpoint->media.dtls_cfg.cipher);
	return 0;
}

static int dtls_cafile_to_str(const void *obj, const intptr_t *args, char **buf)
{
	const struct respoke_endpoint *endpoint = obj;
	*buf = ast_strdup(endpoint->media.dtls_cfg.cafile);
	return 0;
}

static int dtls_capath_to_str(const void *obj, const intptr_t *args, char **buf)
{
	const struct respoke_endpoint *endpoint = obj;
	*buf = ast_strdup(endpoint->media.dtls_cfg.capath);
	return 0;
}

static const char *ast_rtp_dtls_setup_map[] = {
	[AST_RTP_DTLS_SETUP_ACTIVE] = "active",
	[AST_RTP_DTLS_SETUP_PASSIVE] = "passive",
	[AST_RTP_DTLS_SETUP_ACTPASS] = "actpass",
	[AST_RTP_DTLS_SETUP_HOLDCONN] = "holdconn",
};

static int dtls_setup_to_str(const void *obj, const intptr_t *args, char **buf)
{
	const struct respoke_endpoint *endpoint = obj;
	if (ARRAY_IN_BOUNDS(endpoint->media.dtls_cfg.default_setup, ast_rtp_dtls_setup_map)) {
		*buf = ast_strdup(ast_rtp_dtls_setup_map[endpoint->media.dtls_cfg.default_setup]);
	}
	return 0;
}

static int redirect_handler(const struct aco_option *opt, struct ast_variable *var, void *obj)
{
	struct respoke_endpoint *endpoint = obj;

	if (!strcasecmp(var->value, "internal")) {
		endpoint->redirect = RESPOKE_REDIRECT_INTERNAL;
	} else if (!strcasecmp(var->value, "core")) {
		endpoint->redirect = RESPOKE_REDIRECT_CORE;
	} else {
		ast_log(LOG_ERROR, "Unrecognized redirect method %s specified for endpoint %s\n",
			var->value, ast_sorcery_object_get_id(endpoint));
		return -1;
	}

	return 0;
}

static int check_state(void *obj, void *arg, int flags)
{
	struct respoke_endpoint_state *state = obj;
	struct respoke_endpoint *endpoint;

	endpoint = ast_sorcery_retrieve_by_id(respoke_get_sorcery(), RESPOKE_ENDPOINT, state->name);
	if (!endpoint) {
		/* This is a dead endpoint */
		return CMP_MATCH;
	}

	ao2_ref(endpoint, -1);
	return 0;
}

/*!
 * \internal
 * \brief Observer to purge dead endpoint states.
 *
 * \param name Module name owning the sorcery instance.
 * \param sorcery Instance being observed.
 * \param object_type Name of object being observed.
 * \param reloaded Non-zero if the object is being reloaded.
 *
 * \return Nothing
 */
static void endpoint_loaded_observer(const char *name, const struct ast_sorcery *sorcery, const char *object_type, int reloaded)
{
	struct ao2_container *states;

	if (strcmp(object_type, RESPOKE_ENDPOINT)) {
		/* Not interested */
		return;
	}

	states = ao2_global_obj_ref(endpoint_states);
	if (!states) {
		/* Global container has gone.  Likely shutting down. */
		return;
	}

	/*
	 * Refresh the current configured endpoints. We don't need to hold
	 * onto the objects, as the apply handler will cause their states to
	 * be created appropriately.
	 */
	ao2_cleanup(ast_sorcery_retrieve_by_fields(
		respoke_get_sorcery(), RESPOKE_ENDPOINT,
		AST_RETRIEVE_FLAG_MULTIPLE | AST_RETRIEVE_FLAG_ALL, NULL));

	/* Now to purge dead endpoints. */
	ao2_callback(states, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE, check_state, NULL);
	ao2_ref(states, -1);
}

static const struct ast_sorcery_instance_observer observer_callbacks = {
	.object_type_loaded = endpoint_loaded_observer,
};

static void endpoint_deleted_observer(const void *obj)
{
	const struct respoke_endpoint *endpoint = obj;
	struct ao2_container *states;

	states = ao2_global_obj_ref(endpoint_states);
	if (!states) {
		/* Global container has gone.  Likely shutting down. */
		return;
	}
	ao2_find(states, ast_sorcery_object_get_id(endpoint), OBJ_UNLINK | OBJ_NODATA | OBJ_SEARCH_KEY);
	ao2_ref(states, -1);
}

static const struct ast_sorcery_observer endpoint_observer = {
	.deleted = endpoint_deleted_observer,
};

int respoke_endpoint_initialize(void)
{
	struct ast_sorcery *sorcery = respoke_get_sorcery();
	struct ao2_container *new_states;

	/* Create endpoint states container. */
	new_states = ao2_container_alloc(DEFAULT_STATE_BUCKETS,
		endpoint_state_hash, endpoint_state_cmp);
	if (!new_states) {
		ast_log(LOG_ERROR, "Unable to allocate states container\n");
		return -1;
	}
	ao2_global_obj_replace_unref(endpoint_states, new_states);
	ao2_ref(new_states, -1);

	ast_sorcery_apply_default(sorcery, RESPOKE_ENDPOINT, "config",
				  "respoke.conf,criteria=type=endpoint");

	if (ast_sorcery_internal_object_register(
		    sorcery, RESPOKE_ENDPOINT, respoke_endpoint_alloc,
		    NULL, respoke_endpoint_apply)) {
		ao2_global_obj_replace_unref(endpoint_states, NULL);
		return -1;
	}

	/* These are purposely marked as nodoc as documentation will
	   not be included with the running Asterisk */
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_ENDPOINT, "type", "", OPT_NOOP_T, 0, 0);
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_ENDPOINT, "context", "default", OPT_STRINGFIELD_T, 0,
		STRFLDSET(struct respoke_endpoint, context));
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_ENDPOINT, "app", "", OPT_STRINGFIELD_T, 0,
		STRFLDSET(struct respoke_endpoint, app_name));
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_ENDPOINT, "transport", "", OPT_STRINGFIELD_T, 0,
		STRFLDSET(struct respoke_endpoint, transport_name));
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_ENDPOINT, "rtp_engine", "asterisk", OPT_STRINGFIELD_T, 0,
		STRFLDSET(struct respoke_endpoint, media.rtp_engine));
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_ENDPOINT, "from", "", OPT_STRINGFIELD_T, 0,
		STRFLDSET(struct respoke_endpoint, from));
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_ENDPOINT, "from_type", "web", OPT_STRINGFIELD_T, 0,
		STRFLDSET(struct respoke_endpoint, from_type));
	ast_sorcery_object_field_register_alias(
		sorcery, RESPOKE_ENDPOINT, "disallow", "", OPT_CODEC_T, 0,
		FLDSET(struct respoke_endpoint, media.codecs));
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_ENDPOINT, "allow", "", OPT_CODEC_T, 1,
		FLDSET(struct respoke_endpoint, media.codecs));
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_ENDPOINT, "sdp_session", "Asterisk", OPT_STRINGFIELD_T, 0,
		STRFLDSET(struct respoke_endpoint, media.sdp_session));
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_ENDPOINT, "sdp_owner", "-", OPT_STRINGFIELD_T, 0,
		STRFLDSET(struct respoke_endpoint, media.sdp_owner));
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_ENDPOINT, "media_address", "0.0.0.0", OPT_SOCKADDR_T, 0,
		FLDSET(struct respoke_endpoint, media.addr));
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_ENDPOINT, "rtp_ipv6", "no", OPT_BOOL_T, 1,
		FLDSET(struct respoke_endpoint, media.rtp_ipv6));
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_ENDPOINT, "register", "yes", OPT_BOOL_T, 1,
		FLDSET(struct respoke_endpoint, register_with_service));
	ast_sorcery_object_field_register_nodoc(
		sorcery, RESPOKE_ENDPOINT, "turn", "no", OPT_BOOL_T, 1,
		FLDSET(struct respoke_endpoint, media.turn));
	ast_sorcery_object_field_register_custom_nodoc(
		sorcery, RESPOKE_ENDPOINT, "callerid", "", caller_id_handler, caller_id_to_str, NULL, 0, 0);
	ast_sorcery_object_field_register_custom_nodoc(
		sorcery, RESPOKE_ENDPOINT, "dtls_verify", "", dtls_handler, dtls_verify_to_str, NULL, 0, 0);
	ast_sorcery_object_field_register_custom_nodoc(
		sorcery, RESPOKE_ENDPOINT, "dtls_rekey", "", dtls_handler, dtls_rekey_to_str, NULL, 0, 0);
	ast_sorcery_object_field_register_custom_nodoc(
		sorcery, RESPOKE_ENDPOINT, "dtls_cert_file", "", dtls_handler, dtls_cert_file_to_str, NULL, 0, 0);
	ast_sorcery_object_field_register_custom_nodoc(
		sorcery, RESPOKE_ENDPOINT, "dtls_private_key", "", dtls_handler, dtls_private_key_to_str, NULL, 0, 0);
	ast_sorcery_object_field_register_custom_nodoc(
		sorcery, RESPOKE_ENDPOINT, "dtls_cipher", "", dtls_handler, dtls_cipher_to_str, NULL, 0, 0);
	ast_sorcery_object_field_register_custom_nodoc(
		sorcery, RESPOKE_ENDPOINT, "dtls_ca_file", "", dtls_handler, dtls_cafile_to_str, NULL, 0, 0);
	ast_sorcery_object_field_register_custom_nodoc(
		sorcery, RESPOKE_ENDPOINT, "dtls_ca_path", "", dtls_handler, dtls_capath_to_str, NULL, 0, 0);
	ast_sorcery_object_field_register_custom_nodoc(
		sorcery, RESPOKE_ENDPOINT, "dtls_setup", "", dtls_handler, dtls_setup_to_str, NULL, 0, 0);
	ast_sorcery_object_field_register_custom_nodoc(
		sorcery, RESPOKE_ENDPOINT, "redirect_method", "core", redirect_handler, NULL, NULL, 0, 0);

	/*
	 * Register sorcery observers.
	 */
	if (ast_sorcery_instance_observer_add(sorcery, &observer_callbacks)
		|| ast_sorcery_observer_add(sorcery, RESPOKE_ENDPOINT, &endpoint_observer)) {
		ast_log(LOG_ERROR, "Unable to register observers.\n");
		ao2_global_obj_replace_unref(endpoint_states, NULL);
		return -1;
	}

	ast_cli_register_multiple(cli_respoke_endpoint, ARRAY_LEN(cli_respoke_endpoint));

	return 0;
}

void respoke_endpoint_deinitialize(void)
{
	ast_cli_unregister_multiple(cli_respoke_endpoint, ARRAY_LEN(cli_respoke_endpoint));
	ao2_global_obj_replace_unref(endpoint_states, NULL);
}
