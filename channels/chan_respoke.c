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
	<depend>res_respoke_session</depend>
	<support_level>extended</support_level>
 ***/

#include "asterisk.h"

#include "asterisk/app.h"
#include "asterisk/astobj2.h"
#include "asterisk/causes.h"
#include "asterisk/channel.h"
#include "asterisk/indications.h"
#include "asterisk/logger.h"
#include "asterisk/module.h"
#include "asterisk/pbx.h"
#include "asterisk/rtp_engine.h"
#include "asterisk/sorcery.h"
#include "asterisk/strings.h"
#include "asterisk/stasis_channels.h"

#include "asterisk/res_respoke_session.h"

#include "asterisk/respoke.h"
#include "asterisk/respoke_endpoint.h"
#include "asterisk/respoke_message.h"

unsigned int chan_idx;

static struct ast_channel *channel_create(
	struct respoke_session *session, int state, const char *exten,
	const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor);

static int offer_session(struct respoke_session *session)
{
	if (session->channel) {
		return 0;
	}

	if (!(session->channel = channel_create(session, AST_STATE_RING,
		      respoke_session_get_exten(session), NULL, NULL))) {
		return -1;
	}

	switch (ast_pbx_start(session->channel)) {
	case AST_PBX_CALL_LIMIT:
		ast_log(LOG_WARNING, "PBX call limit reached\n");
	case AST_PBX_FAILED:
		ast_log(LOG_WARNING, "Failed to start PBX\n");
		ast_channel_hangupcause_set(session->channel, AST_CAUSE_SWITCH_CONGESTION);
		ast_hangup(session->channel);
		return -1;
	case AST_PBX_SUCCESS:
		break;
	}

	ast_debug(3, "Started PBX on new RESPOKE channel %s\n",
		  ast_channel_name(session->channel));

	return 0;
}

static int hangup_reason_to_cause(enum respoke_status status)
{
	switch (status) {
	case RESPOKE_STATUS_BUSY:
		return AST_CAUSE_BUSY;
	case RESPOKE_STATUS_UNAVAILABLE:
		return AST_CAUSE_CONGESTION;
	case RESPOKE_STATUS_INCOMPLETE:
		return AST_CAUSE_INVALID_NUMBER_FORMAT;
	default:
		return AST_CAUSE_NORMAL;
	}
}

static void set_cause_code(struct respoke_session *session, enum respoke_status status)
{
	struct ast_control_pvt_cause_code *cause_code;
	int size;
	const char *cause = respoke_status_to_str(status);

	/* size of the cause = sizeof + "RESPOKE " + cause */
	size = sizeof(*cause_code) + 9 + strlen(cause);
	cause_code = ast_alloca(size);
	memset(cause_code, 0, size);

	ast_copy_string(cause_code->chan_name,
			ast_channel_name(session->channel), AST_CHANNEL_NAME);
	snprintf(cause_code->code, size - sizeof(*cause_code) + 1, "RESPOKE %s", cause);

	cause_code->ast_cause = hangup_reason_to_cause(status);
	ast_queue_control_data(session->channel, AST_CONTROL_PVT_CAUSE_CODE,
			       cause_code, size);
	ast_channel_hangupcause_hash_set(session->channel, cause_code, size);
}

static int answer_session(struct respoke_session *session, enum respoke_status status)
{
	if (!session->channel) {
		return 0;
	}

	switch (status) {
	case RESPOKE_STATUS_FINAL:
	default:
		ast_queue_control(session->channel, AST_CONTROL_ANSWER);
		break;
	}

	set_cause_code(session, status);
	return 0;
}

static int status_session(struct respoke_session *session, enum respoke_status status)
{
	if (!session->channel) {
		return 0;
	}

	switch (status) {
	case RESPOKE_STATUS_RINGING:
		ast_queue_control(session->channel, AST_CONTROL_RINGING);
		ast_channel_lock(session->channel);
		if (ast_channel_state(session->channel) != AST_STATE_UP) {
			ast_setstate(session->channel, AST_STATE_RINGING);
		}
		ast_channel_unlock(session->channel);
		break;
	case RESPOKE_STATUS_PROGRESS:
		ast_queue_control(session->channel, AST_CONTROL_PROGRESS);
		break;
	default:
		set_cause_code(session, status);
		ast_queue_hangup(session->channel);
		break;
	}

	return 0;
}

static int end_session(struct respoke_session *session, enum respoke_status status, const struct respoke_message *message)
{
	const char *endpoint, *type, *app;

	if (!session->channel) {
		return 0;
	}

	endpoint = respoke_message_redirected_endpoint_get(message);
	type = respoke_message_redirected_type_get(message);
	app = respoke_message_redirected_app_get(message);

	if (!ast_strlen_zero(endpoint) && !ast_strlen_zero(app)) {
		if (session->endpoint->redirect == RESPOKE_REDIRECT_INTERNAL) {
			char id[AST_UUID_STR_LEN];

			/* Since we are changing the session-id and because offer adds this session
			 * to the sessions container we need to unlink it now, which bye does
			 */
			respoke_session_bye(session, RESPOKE_STATUS_REDIRECTING);
			session->terminated = 0;

			ast_string_field_set(session, remote, endpoint);
			ast_string_field_set(session, remote_type, S_OR(type, "web"));
			ast_string_field_set(session, remote_appid, app);
			ast_string_field_set(session, remote_connection, "");
			ast_string_field_set(session, session_id, ast_uuid_generate_str(id, sizeof(id)));

			/* Send a new offer out to the new target, without the caller being any the wiser */
			if (!respoke_session_offer(session)) {
				return 0;
			}

			session->terminated = 1;
		} else if (session->endpoint->redirect == RESPOKE_REDIRECT_CORE) {
			ast_channel_call_forward_build(session->channel, "Respoke/%s/%s@%s", ast_sorcery_object_get_id(session->endpoint),
				endpoint, app);
		}
	}

	ast_set_hangupsource(session->channel, ast_channel_name(session->channel), 0);
	if (!ast_channel_hangupcause(session->channel)) {
		int cause = hangup_reason_to_cause(status);
		ast_queue_hangup_with_cause(session->channel, cause);
	} else {
		ast_queue_hangup(session->channel);
	}
	return 0;
}

struct respoke_session_handler session_handler = {
	.on_offer = offer_session,
	.on_answer = answer_session,
	.on_status = status_session,
	.on_end = end_session
};

struct requester_task_data {
	struct respoke_session *session;
	struct ast_format_cap *caps;
	const char *dest;
	int *cause;
};

static int requester_task(void *obj)
{
	struct respoke_endpoint *endpoint;
	struct requester_task_data *data = obj;
	char *dest = ast_strdupa(data->dest);
	char *from = NULL, *from_type = NULL;
	char *from_connection = NULL;
	char *to_connection = NULL, *to_appid = NULL;

	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(endpoint);
		AST_APP_ARG(target_endpoint);
	);

	if (ast_strlen_zero(dest)) {
		ast_log(LOG_ERROR, "Unable to create channel - no destination\n");
		*data->cause = AST_CAUSE_CHANNEL_UNACCEPTABLE;
		return -1;
	}

	AST_NONSTANDARD_APP_ARGS(args, dest, '/');

	if (ast_strlen_zero(args.endpoint)) {
		ast_log(LOG_ERROR, "Unable to create channel - no endpoint given\n");
		*data->cause = AST_CAUSE_CHANNEL_UNACCEPTABLE;
		return -1;
	} else if (ast_strlen_zero(args.target_endpoint)) {
		ast_log(LOG_ERROR, "Unable to create channel - no target endpoint given\n");
		*data->cause = AST_CAUSE_CHANNEL_UNACCEPTABLE;
		return -1;
	}

	/* Get the optional app identifier */
	to_appid = args.target_endpoint;
	strsep(&to_appid, "@");

	if (!(endpoint = ast_sorcery_retrieve_by_id(
		      respoke_get_sorcery(), RESPOKE_ENDPOINT, args.endpoint))) {
		ast_log(LOG_ERROR, "Unable to create channel - endpoint '%s' not found\n",
			args.endpoint);
		*data->cause = AST_CAUSE_NO_ROUTE_DESTINATION;
		return -1;
	}

	if (!(data->session = respoke_session_create(
		      NULL, endpoint, from, from_type, from_connection,
		      args.target_endpoint, NULL, to_connection, to_appid, NULL, data->caps))) {
		*data->cause = AST_CAUSE_NO_ROUTE_DESTINATION;
		ao2_ref(endpoint, -1);
		return -1;
	}

	return 0;
}

static struct ast_channel *requester_channel(
	const char *type, struct ast_format_cap *cap,
	const struct ast_assigned_ids *assignedids,
	const struct ast_channel *requestor, const char *data, int *cause)
{
	struct requester_task_data task_data = {
		.caps = cap,
		.dest = data,
		.cause = cause
	};

	if (respoke_push_task_synchronous(NULL, requester_task, &task_data)) {
		return NULL;
	}

	if (!(task_data.session->channel = channel_create(
		      task_data.session, AST_STATE_DOWN, NULL,
		      assignedids, requestor))) {
		ao2_ref(task_data.session, -1);
		return NULL;
	}

	/* the channel now maintains a session ref so remove this one */
	ao2_ref(task_data.session, -1);
	return task_data.session->channel;
}

static int call_channel_task(void *data)
{
	struct ast_channel *chan = data;
	int res = respoke_session_offer(ast_channel_tech_pvt(chan));

	if (res) {
		ast_set_hangupsource(chan, ast_channel_name(chan), 0);
		ast_queue_hangup(chan);
	}

	return res;
}

static int call_channel(struct ast_channel *chan, const char *dest, int timeout)
{
	struct respoke_session *session = ast_channel_tech_pvt(chan);

	if (respoke_push_task(session->serializer, call_channel_task, chan)) {
		ast_log(LOG_ERROR, "Unable to push task: call to '%s'\n", dest);
		return -1;
	}

	return 0;
}

static int answer_channel_task(void *data)
{
	return respoke_session_answer(ast_channel_tech_pvt(data));
}

static int answer_channel(struct ast_channel *chan)
{
	struct respoke_session *session = ast_channel_tech_pvt(chan);

	if (ast_channel_state(chan) == AST_STATE_UP) {
		return 0;
	}

	if (respoke_push_task(session->serializer, answer_channel_task, chan)) {
		ast_log(LOG_ERROR, "Unable to push task: answer\n");
		return -1;
	}

	ast_setstate(chan, AST_STATE_UP);
	return 0;
}

static enum respoke_status hangup_cause_to_status(int cause)
{
	switch (cause) {
	default:
		return RESPOKE_STATUS_HANGUP;
	}
}

static void clear_session_channel(struct respoke_session *session)
{
	if (!session->channel) {
		return;
	}

	if (session->audio_rtp) {
		ast_rtp_instance_set_channel_id(session->audio_rtp, "");
	}

	if (session->video_rtp) {
		ast_rtp_instance_set_channel_id(session->video_rtp, "");
	}

	ast_channel_tech_pvt_set(session->channel, NULL);
	session->channel = ast_channel_unref(session->channel);
	ao2_ref(session, -1);
}

static int hangup_channel_task(void *data)
{
	struct respoke_session *session = data;
	enum respoke_status status = hangup_cause_to_status(
		ast_channel_hangupcause(session->channel));
	int res = respoke_session_bye(session, status);

	clear_session_channel(session);
	return res;
}

static int hangup_channel(struct ast_channel *chan)
{
	struct respoke_session *session = ast_channel_tech_pvt(chan);

	ast_channel_ref(session->channel);

	if (respoke_push_task(session->serializer, hangup_channel_task, session)) {
		ast_log(LOG_ERROR, "Unable to push task: hangup\n");
		clear_session_channel(session);
		return -1;
	}

	return 0;
}

static struct ast_frame *read_channel(struct ast_channel *chan)
{
	struct respoke_session *session = ast_channel_tech_pvt(chan);
	struct ast_rtp_instance *instance = NULL;
	struct ast_frame *f;
	int rtcp = 0;

	switch (ast_channel_fdno(chan)) {
	case 1:
		rtcp = 1;
	case 0:
		instance = session->audio_rtp;
		break;
	case 3:
		rtcp = 1;
	case 2:
		instance = session->video_rtp;
		break;
	}

	if (!instance) {
		return &ast_null_frame;
	}

	if (!(f = ast_rtp_instance_read(instance, rtcp))) {
		return f;
	}

	if (f->frametype != AST_FRAME_VOICE) {
		return f;
	}

	if (ast_format_cap_iscompatible_format(
		    ast_channel_nativeformats(chan),
		    f->subclass.format) == AST_FORMAT_CMP_NOT_EQUAL) {
		struct ast_format_cap *caps;

		ast_debug(1, "Oooh, format changed to %s\n",
			  ast_format_get_name(f->subclass.format));

		caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
		if (caps) {
			ast_format_cap_append(caps, f->subclass.format, 0);
			ast_channel_nativeformats_set(chan, caps);
			ao2_ref(caps, -1);
		}

		ast_set_read_format(chan, ast_channel_readformat(chan));
		ast_set_write_format(chan, ast_channel_writeformat(chan));
	}

	return f;
}

static int write_channel(struct ast_channel *chan, struct ast_frame *frame)
{
	struct respoke_session *session = ast_channel_tech_pvt(chan);

	switch (frame->frametype) {
	case AST_FRAME_VOICE:
		if (!session->audio_rtp) {
			return 0;
		}

		if (ast_format_cap_iscompatible_format(
			    ast_channel_nativeformats(chan),
			    frame->subclass.format) == AST_FORMAT_CMP_NOT_EQUAL) {
			struct ast_str *cap_buf = ast_str_alloca(64);
			ast_log(LOG_WARNING,
				"Asked to transmit frame type %s, while native formats "
				"is %s (read/write = %s/%s)\n",
				ast_format_get_name(frame->subclass.format),
				ast_format_cap_get_names(
					ast_channel_nativeformats(chan), &cap_buf),
				ast_format_get_name(ast_channel_readformat(chan)),
				ast_format_get_name(ast_channel_writeformat(chan)));
			return 0;
		}

		return ast_rtp_instance_write(session->audio_rtp, frame);
	case AST_FRAME_VIDEO:
		if (session->video_rtp) {
			return ast_rtp_instance_write(session->video_rtp, frame);
		}
		break;
	default:
		ast_log(LOG_WARNING, "Can't send %u type frames with RESPOKE\n",
			frame->frametype);
		break;
	}

	return 0;
}

static int fixup_channel(struct ast_channel *oldchan, struct ast_channel *newchan)
{
	struct respoke_session *session= ast_channel_tech_pvt(newchan);

	return session->channel == oldchan ? 0 : -1;
}

struct indicate_task_data {
	struct respoke_session *session;
	enum respoke_status status;
};

static int indicate_channel_task(void *data)
{
	struct indicate_task_data *task_data = data;

	int res = respoke_session_status(task_data->session, task_data->status);

	ao2_ref(task_data->session, -1);
	ast_free(task_data);

	return res;
}

static int indicate_channel(struct ast_channel *chan, int condition, const void *data,
			    size_t datalen)
{
	struct respoke_session *session = ast_channel_tech_pvt(chan);
	struct indicate_task_data *task_data;
	int status = -1;

	switch (condition) {
	case AST_CONTROL_RINGING:
		if (ast_channel_state(chan) == AST_STATE_RING) {
			status = RESPOKE_STATUS_RINGING;
		}
		ast_devstate_changed(
			AST_DEVICE_UNKNOWN, AST_DEVSTATE_CACHABLE, "RESPOKE/%s",
			ast_sorcery_object_get_id(session->endpoint));
		break;
	case AST_CONTROL_BUSY:
		if (ast_channel_state(chan) != AST_STATE_UP) {
			status = RESPOKE_STATUS_BUSY;
		}
		break;
	case AST_CONTROL_CONGESTION:
		if (ast_channel_state(chan) != AST_STATE_UP) {
			status = RESPOKE_STATUS_UNAVAILABLE;
		}
		break;
	case AST_CONTROL_INCOMPLETE:
		if (ast_channel_state(chan) != AST_STATE_UP) {
			status = RESPOKE_STATUS_INCOMPLETE;
		}
		break;
	case AST_CONTROL_PROCEEDING:
		if (ast_channel_state(chan) != AST_STATE_UP) {
			status = RESPOKE_STATUS_TRYING;
		}
		break;
	case AST_CONTROL_PROGRESS:
		if (ast_channel_state(chan) != AST_STATE_UP) {
			status = RESPOKE_STATUS_PROGRESS;
		}
		break;
	case AST_CONTROL_REDIRECTING:
		if (ast_channel_state(chan) != AST_STATE_UP) {
			status = RESPOKE_STATUS_REDIRECTING;
		}
		break;
	case AST_CONTROL_UPDATE_RTP_PEER:
	case AST_CONTROL_SRCUPDATE:
	case AST_CONTROL_SRCCHANGE:
	case AST_CONTROL_PVT_CAUSE_CODE:
		return 0;
	case -1:
		return -1;
	default:
		ast_log(LOG_WARNING, "Don't know how to indicate condition %d\n", condition);
		return -1;
	}

	if (status < 0 || !(task_data = ast_malloc(sizeof(*task_data)))) {
		return -1;
	}

	task_data->session = ao2_bump(session);
	task_data->status = status;

	if (respoke_push_task(session->serializer, indicate_channel_task, task_data)) {
		ast_log(LOG_NOTICE, "Cannot send status '%s' to endpoint '%s'. "
			"Could not queue task properly\n", respoke_status_to_str(status),
			ast_sorcery_object_get_id(session->endpoint));
		ao2_ref(session, -1);
		ast_free(task_data);
		return -1;
	}
	return 0;
}

static int digit_begin_channel(struct ast_channel *chan, char digit)
{
	struct respoke_session *session = ast_channel_tech_pvt(chan);

	if (session->audio_rtp) {
		ast_rtp_instance_dtmf_begin(session->audio_rtp, digit);
	}

	return 0;
}

static int digit_end_channel(struct ast_channel *chan, char digit, unsigned int duration)
{
	struct respoke_session *session = ast_channel_tech_pvt(chan);

	if (session->audio_rtp) {
		ast_rtp_instance_dtmf_end_with_duration(
			session->audio_rtp, digit, duration);
	}

	return 0;
}

static int func_read_channel(struct ast_channel *chan, const char *function,
			     char *data, char *buf, size_t len)
{
	struct respoke_session *session;

	if (strcmp(ast_channel_tech(chan)->type, "RESPOKE")) {
		ast_log(LOG_ERROR, "Cannot call %s on a non-RESPOKE channel\n", function);
		return 0;
	}

	session = ast_channel_tech_pvt(chan);

	if (!strcmp(data, "endpoint")) {
		ast_copy_string(buf, ast_sorcery_object_get_id(session->endpoint), len);
	} else if (!strcmp(data, "local")) {
		ast_copy_string(buf, session->local, len);
	} else if (!strcmp(data, "local_type")) {
		ast_copy_string(buf, session->local_type, len);
	} else if (!strcmp(data, "remote")) {
		ast_copy_string(buf, session->remote, len);
	} else if (!strcmp(data, "remote_type")) {
		ast_copy_string(buf, session->remote_type, len);
	} else if (!strcmp(data, "remote_appid")) {
		ast_copy_string(buf, session->remote_appid, len);
	} else {
		return -1;
	}

	return 0;
}

static int func_write_channel(struct ast_channel *chan, const char *function,
			      char *data, const char *value)
{
	struct respoke_session *session = ast_channel_tech_pvt(chan);

	if (strcmp(ast_channel_tech(chan)->type, "RESPOKE")) {
		ast_log(LOG_ERROR, "Cannot call %s on a non-RESPOKE channel\n", function);
		return 0;
	}

	ast_channel_lock(chan);
	if (!strcmp(data, "local")) {
		ast_string_field_set(session, local, value);
	} else if (!strcmp(data, "local_type")) {
		ast_string_field_set(session, local_type, value);
	} else if (!strcmp(data, "remote")) {
		ast_string_field_set(session, remote, value);
	} else if (!strcmp(data, "remote_type")) {
		ast_string_field_set(session, remote_type, value);
	} else if (!strcmp(data, "remote_appid")) {
		ast_string_field_set(session, remote_appid, value);
	} else {
		ast_channel_unlock(chan);
		return -1;
	}

	ast_channel_unlock(chan);
	return 0;
}

struct ast_channel_tech channel_tech = {
	.type = "RESPOKE",
	.description = "Respoke Channel Driver",
	.requester = requester_channel,
	.call = call_channel,
	.answer = answer_channel,
	.hangup = hangup_channel,
	.read = read_channel,
	.write = write_channel,
	.write_video = write_channel,
	.exception = read_channel,
	.fixup = fixup_channel,
	.indicate = indicate_channel,
	.send_digit_begin = digit_begin_channel,
	.send_digit_end = digit_end_channel,
	.func_channel_read = func_read_channel,
	.func_channel_write = func_write_channel,
	.properties = AST_CHAN_TP_WANTSJITTER | AST_CHAN_TP_CREATESJITTER
};

static struct ast_channel *channel_create(
	struct respoke_session *session, int state, const char *exten,
	const struct ast_assigned_ids *assignedids, const struct ast_channel *requestor)
{
	struct ast_format_cap *caps;
	struct ast_format *fmt;
	struct ast_channel *chan;

	if (!(caps = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT))) {
		return NULL;
	}

	chan = ast_channel_alloc(
		1, state, S_OR(session->party_id.number.str, ""),
		S_OR(session->party_id.name.str, ""), "", S_OR(exten, "s"),
		session->endpoint->context, assignedids, requestor, 0,
		"RESPOKE/%s-%08x", ast_sorcery_object_get_id(session->endpoint),
		(unsigned)ast_atomic_fetchadd_int((int *)&chan_idx, +1));

	if (!chan) {
		ao2_ref(caps, -1);
		return NULL;
	}

	ast_channel_stage_snapshot(chan);

	ast_channel_tech_set(chan, &channel_tech);
	ast_channel_tech_pvt_set(chan, ao2_bump(session));


	if (!ast_format_cap_count(session->capabilities) ||
	    !ast_format_cap_iscompatible(session->capabilities,
					 session->endpoint->media.codecs)) {
		ast_format_cap_append_from_cap(
			caps, session->endpoint->media.codecs, AST_MEDIA_TYPE_UNKNOWN);
	} else {
		ast_format_cap_append_from_cap(
			caps, session->capabilities, AST_MEDIA_TYPE_UNKNOWN);
	}

	ast_channel_nativeformats_set(chan, caps);
	fmt = ast_format_cap_get_format(caps, 0);
	ast_channel_set_writeformat(chan, fmt);
	ast_channel_set_rawwriteformat(chan, fmt);
	ast_channel_set_readformat(chan, fmt);
	ast_channel_set_rawreadformat(chan, fmt);
	ao2_ref(fmt, -1);
	ao2_ref(caps, -1);

	if (state == AST_STATE_RING) {
		ast_channel_rings_set(chan, 1);
	}

	ast_channel_adsicpe_set(chan, AST_ADSI_UNAVAILABLE);
	ast_channel_priority_set(chan, 1);

	if (session->audio_rtp) {
		ast_rtp_instance_set_channel_id(
			session->audio_rtp, ast_channel_uniqueid(chan));
		ast_channel_set_fd(chan, 0, ast_rtp_instance_fd(session->audio_rtp, 0));
		ast_channel_set_fd(chan, 1, ast_rtp_instance_fd(session->audio_rtp, 1));
	}

	if (session->video_rtp) {
		ast_rtp_instance_set_channel_id(
			session->video_rtp, ast_channel_uniqueid(chan));
		ast_channel_set_fd(chan, 2, ast_rtp_instance_fd(session->video_rtp, 0));
		ast_channel_set_fd(chan, 3, ast_rtp_instance_fd(session->video_rtp, 1));
	}

	ast_channel_stage_snapshot_done(chan);
	ast_channel_unlock(chan);

	return chan;
}

static int unload_module(void)
{
	respoke_session_unregister_handler(&session_handler);
	ast_channel_unregister(&channel_tech);
	return 0;
}

static int load_module(void)
{
	if (!(channel_tech.capabilities = ast_format_cap_alloc(0))) {
		return AST_MODULE_LOAD_DECLINE;
	}

	ast_format_cap_append_by_type(channel_tech.capabilities, AST_MEDIA_TYPE_AUDIO);

	if (ast_channel_register(&channel_tech)) {
		ast_log(LOG_ERROR, "Unable to register channel type %s\n",
			channel_tech.type);
		unload_module();
		return AST_MODULE_LOAD_FAILURE;
	}

	if (respoke_session_register_handler(&session_handler)) {
		ast_log(LOG_ERROR, "Unable to register session handler\n");
		unload_module();
		return AST_MODULE_LOAD_FAILURE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS |
		AST_MODFLAG_LOAD_ORDER, "Respoke Channel Driver",
		.support_level = AST_MODULE_SUPPORT_EXTENDED,
		.load = load_module,
		.unload = unload_module,
		.load_pri = AST_MODPRI_CHANNEL_DRIVER,
	       );
