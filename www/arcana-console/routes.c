/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The routes of the console: an exact path, or a POSIX extended
 * expression when it starts with ^; the first whose path and method
 * match is taken, before the files of the web root.
 */

#include <sys/param.h>

#include "console.h"

const struct route routes[] = {
	{ "/api/health", api_health, NULL,
	    HTTP_METHOD_GET },
	{ "/.well-known/assetlinks.json", api_assetlinks, NULL,
	    HTTP_METHOD_GET },
	{ "/.well-known/host-meta", api_host_meta, NULL,
	    HTTP_METHOD_GET },
	{ "/restconf", api_restconf, NULL,
	    HTTP_METHOD_GET },
	{ "/restconf/yang-library-version", api_restconf_ylv, NULL,
	    HTTP_METHOD_GET },
	/* A module described for forms (ymodule.c). */
	{ "^/yang/[a-z][a-z0-9_.-]{0,63}@[0-9]{4}-[0-9]{2}-[0-9]{2}[.]json$",
	    api_yang_module, NULL, HTTP_METHOD_GET },
	{ "^/restconf/data/ietf-network:networks(/.*)?$", api_sapnet,
	    api_sapnet_free, HTTP_METHOD_GET | HTTP_METHOD_OPTIONS },
	/* arcana-console's actions that wait on a task. */
	{ CYANG_DATA "settings/mail-test", api_mail_test, NULL,
	    HTTP_METHOD_POST },
	{ CYANG_DATA "settings/telegram-test", api_telegram_test,
	    api_telegram_test_free, HTTP_METHOD_POST },
	{ CYANG_DATA "push/send", api_push_send, api_push_free,
	    HTTP_METHOD_POST },
	/* What the console answers of a host (cyang.c's bridges). */
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/drift$", api_drift, api_call_free,
	    HTTP_METHOD_GET },
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/watch$", api_watch, NULL,
	    HTTP_METHOD_GET },
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/notifications$", api_notifications,
	    NULL, HTTP_METHOD_GET },
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/subscription$", api_subscription,
	    NULL, HTTP_METHOD_GET },
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/subscription-token$",
	    api_subscription_token, NULL, HTTP_METHOD_POST },
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/(tls|renew-tls)$", api_tls,
	    api_call_free, HTTP_METHOD_GET | HTTP_METHOD_POST },
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/(transport|listen)$", api_transport,
	    api_call_free, HTTP_METHOD_GET | HTTP_METHOD_POST },
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/switch-transport$",
	    api_transport_switch, api_call_free, HTTP_METHOD_POST },
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/(configuration|export-configuration)$",
	    api_config_export, api_call_free, HTTP_METHOD_GET |
	    HTTP_METHOD_POST },
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/apply-configuration$",
	    api_config_apply, api_call_free, HTTP_METHOD_POST },
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/move$", api_server_move,
	    api_server_move_free, HTTP_METHOD_POST },
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/nacm-sync$", api_nacm_sync,
	    api_call_free, HTTP_METHOD_POST },
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/(agent-build|console-update)$",
	    api_agent_build, api_call_free, HTTP_METHOD_POST },
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/agent-update$", api_agent_update,
	    api_call_free, HTTP_METHOD_POST },
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/capture$", api_capture,
	    api_call_free, HTTP_METHOD_POST },
	{ "^" CYANG_HOST "[0-9a-f]{1,16}/dataset-key$", api_zfs_key,
	    api_call_free, HTTP_METHOD_POST },
	/* The SD-WAN's verbs (cyang.c's bridges). */
	{ CYANG_DATA "sdwan/document", api_sdwan, NULL,
	    HTTP_METHOD_GET | HTTP_METHOD_PUT },
	{ CYANG_DATA "sdwan/check", api_sdwan, NULL, HTTP_METHOD_POST },
	{ "^" CYANG_DATA "sdwan/(plan|ledger|apply-state|steering)$",
	    api_sdwan_edges, NULL, HTTP_METHOD_GET },
	{ "^" CYANG_DATA "sdwan/(apply|pin)$", api_sdwan_edges, NULL,
	    HTTP_METHOD_POST },
	{ CYANG_DATA "sdwan/rekeys", api_sdwan_rekey, NULL, HTTP_METHOD_GET },
	{ CYANG_DATA "sdwan/rekey", api_sdwan_rekey, NULL, HTTP_METHOD_POST },
	{ CYANG_DATA "sdwan/lists", api_sdwan_lists, NULL,
	    HTTP_METHOD_GET | HTTP_METHOD_PUT },
	{ CYANG_DATA "sdwan/fetch-lists", api_sdwan_lists, NULL,
	    HTTP_METHOD_POST },
	{ CYANG_DATA "sdwan/identities", api_sdwan_identities, NULL,
	    HTTP_METHOD_GET },
	{ "^" CYANG_DATA "sdwan/(issue|revoke)-identity$",
	    api_sdwan_identities, NULL, HTTP_METHOD_POST },
	{ CYANG_DATA "sdwan/audit", api_sdwan_audit, NULL, HTTP_METHOD_GET },
	{ CYANG_DATA "sdwan/sen", api_sdwan_sen, NULL, HTTP_METHOD_GET },
	{ CYANG_DATA "sdwan/san", api_sdwan_san, NULL, HTTP_METHOD_GET },
	{ CYANG_DATA "sdwan/record", api_sdwan_record, NULL,
	    HTTP_METHOD_GET },
	{ CYANG_DATA "sdwan/attach", api_sapnet_attach, api_sapnet_free,
	    HTTP_METHOD_POST },
	/* The console's own (cyang.c's bridges). */
	{ CYANG_DATA "update", api_update, NULL, HTTP_METHOD_GET },
	{ CYANG_DATA "update-notes", api_update_notes, NULL,
	    HTTP_METHOD_GET },
	{ CYANG_DATA "cluster", api_cluster, NULL, HTTP_METHOD_GET },
	{ "^" CYANG_DATA "ca(/state)?$", api_ca, NULL, HTTP_METHOD_GET },
	{ "^" CYANG_DATA "ca/(make|request|import|discard|rollout|finish)$",
	    api_ca, NULL, HTTP_METHOD_POST },
	{ "^" CYANG_DATA "plugins/plugin=[a-z0-9-]{1,40}/(shared-)?store$",
	    api_cplug_store, NULL, HTTP_METHOD_GET | HTTP_METHOD_PUT },
	{ "/restconf/operations/arcana-console:trace-path",
	    api_troubleshoot_path, api_troubleshoot_free, HTTP_METHOD_POST },
	{ "/restconf/operations/arcana-console:wireguard-keypair",
	    api_wg_keypair, NULL, HTTP_METHOD_POST },
	{ "^/restconf/data(/.*)?$", api_restconf_data, api_call_free,
	    HTTP_METHOD_GET | HTTP_METHOD_POST | HTTP_METHOD_PUT |
	    HTTP_METHOD_PATCH | HTTP_METHOD_DELETE | HTTP_METHOD_OPTIONS },
	{ "^/restconf/operations(/.*)?$", api_restconf_operations, NULL,
	    HTTP_METHOD_GET | HTTP_METHOD_POST },
	{ "^/restconf/ds/.*$", api_restconf_ds, api_call_free,
	    HTTP_METHOD_GET | HTTP_METHOD_POST | HTTP_METHOD_PUT |
	    HTTP_METHOD_PATCH | HTTP_METHOD_DELETE | HTTP_METHOD_OPTIONS },
	{ "^/restconf/subscriptions/([0-9]+)$", api_restconf_subscription,
	    api_restconf_stream_free, HTTP_METHOD_GET },
	{ "^/restconf/streams/([0-9a-f]+)/json$", api_restconf_stream,
	    api_restconf_stream_free, HTTP_METHOD_GET },
	{ "^/restconf/streams/fleet/json$", api_restconf_fleet_stream,
	    api_restconf_stream_free, HTTP_METHOD_GET },
	/*
	 * The console's plain-HTTP resources, /api beside /restconf
	 * (PLAN-SDN-YANG D-10): no YANG data, so not modelled.  The
	 * WebAuthn and password ceremonies, enrolment by token, the
	 * receiver of the hosts' configured subscriptions, an IDS's pcap
	 * files, the socket of the page's streamed reads; the plugins'
	 * files.
	 */
	{ "/api/auth/status", api_auth_status, NULL,
	    HTTP_METHOD_GET },
	{ "/api/auth/register/begin", api_register_begin, NULL,
	    HTTP_METHOD_POST },
	{ "/api/auth/register/finish", api_register_finish, NULL,
	    HTTP_METHOD_POST },
	{ "/api/auth/login/begin", api_login_begin, NULL,
	    HTTP_METHOD_POST },
	{ "/api/auth/login/finish", api_login_finish, NULL,
	    HTTP_METHOD_POST },
	{ "/api/auth/login/password", api_login_password,
	    api_login_password_free,
	    HTTP_METHOD_POST },
	{ "/api/auth/login/token", api_login_token, NULL,
	    HTTP_METHOD_POST },
	{ "/api/auth/setup/password", api_setup_password, NULL,
	    HTTP_METHOD_POST },
	{ "/api/auth/password", api_auth_password, NULL,
	    HTTP_METHOD_POST },
	{ "/api/auth/logout", api_logout, NULL,
	    HTTP_METHOD_POST },
	{ "/api/enrol", api_enrol, NULL,
	    HTTP_METHOD_POST },
	{ "^/api/notif/[0-9a-f]{1,16}/capabilities$", api_notif_capabilities,
	    NULL, HTTP_METHOD_GET },
	{ "^/api/notif/[0-9a-f]{1,16}/relay-notification$", api_notif_relay,
	    NULL, HTTP_METHOD_POST },
	{ "^/api/servers/[0-9a-f]{1,16}/ids/pcap$", api_ids_pcap,
	    api_ids_pcap_free, HTTP_METHOD_POST },
	{ "^/api/servers/[0-9a-f]{1,16}/ids/pcap-log$", api_ids_pcap_log,
	    api_ids_pcap_log_free, HTTP_METHOD_GET },
	{ "/api/stream", api_stream, NULL,
	    HTTP_METHOD_GET },
	{ "^/plugins/[a-z0-9-]{1,40}/.+$", api_cplug_file, NULL,
	    HTTP_METHOD_GET },
};
const size_t nroutes = nitems(routes);
