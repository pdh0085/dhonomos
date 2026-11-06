/*
 * A small XMPP client on libstrophe, the library the devices' xmppc is built on, for trying the
 * built-in XMPP server (scripts/xmpp-interop.sh). It does what xmppc does: connects with
 * mandatory TLS (STARTTLS), logs in with SASL, binds, sends an empty presence and a XEP-0199
 * ping to the domain, and answers a TR-069 Annex K Connection Request with an empty result.
 *
 * Usage: client <host> <port> <jid> <password>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strophe.h>

static int ok = 0;

static int on_ping_result(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    const char *type = xmpp_stanza_get_type(stanza);
    printf("ping answered: type=%s from=%s to=%s\n", type ? type : "?",
           xmpp_stanza_get_from(stanza) ? xmpp_stanza_get_from(stanza) : "-",
           xmpp_stanza_get_to(stanza) ? xmpp_stanza_get_to(stanza) : "-");
    ok |= 1;
    return 0;
}

static int on_get(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    xmpp_ctx_t *ctx = userdata;
    xmpp_stanza_t *cr = xmpp_stanza_get_child_by_name(stanza, "connectionRequest");
    xmpp_stanza_t *user, *pass, *reply;
    const char *text;

    if (!cr)
        return 1;
    printf("connection request: id=%s from=%s to=%s type=%s\n", xmpp_stanza_get_id(stanza),
           xmpp_stanza_get_from(stanza), xmpp_stanza_get_to(stanza), xmpp_stanza_get_type(stanza));
    user = xmpp_stanza_get_child_by_name(cr, "username");
    pass = xmpp_stanza_get_child_by_name(cr, "password");
    text = user ? xmpp_stanza_get_text(user) : NULL;
    printf("  username=%s\n", text ? text : "(none)");
    text = pass ? xmpp_stanza_get_text(pass) : NULL;
    printf("  password=%s\n", text ? text : "(none)");
    reply = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(reply, "iq");
    xmpp_stanza_set_type(reply, "result");
    xmpp_stanza_set_id(reply, xmpp_stanza_get_id(stanza));
    xmpp_stanza_set_to(reply, xmpp_stanza_get_from(stanza));
    xmpp_send(conn, reply);
    xmpp_stanza_release(reply);
    ok |= 2;
    return 1;
}

static int quit(xmpp_conn_t *conn, void *userdata)
{
    xmpp_disconnect(conn);
    return 0;
}

static void on_conn(xmpp_conn_t *conn, xmpp_conn_event_t status, int error,
                    xmpp_stream_error_t *stream_error, void *userdata)
{
    xmpp_ctx_t *ctx = userdata;

    if (status == XMPP_CONN_CONNECT) {
        xmpp_stanza_t *presence = xmpp_presence_new(ctx);
        printf("connected, bound as %s\n", xmpp_conn_get_bound_jid(conn));
        xmpp_send(conn, presence);
        xmpp_stanza_release(presence);
        xmpp_handler_add(conn, on_ping_result, NULL, "iq", "result", NULL);
        xmpp_id_handler_add(conn, on_ping_result, "s2c1", ctx);
        xmpp_send_raw_string(conn, "<iq type='get' id='s2c1' to='%s' from='%s/'>"
                             "<ping xmlns='urn:xmpp:ping'/></iq>",
                             "xmpp.test", xmpp_conn_get_jid(conn));
        xmpp_handler_add(conn, on_get, NULL, "iq", "get", ctx);
        xmpp_timed_handler_add(conn, quit, 8000, ctx);
    } else {
        printf("disconnected (error %d%s)\n", error, stream_error ? ", stream error" : "");
        xmpp_stop(ctx);
    }
}

int main(int argc, char **argv)
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;

    if (argc != 5) {
        fprintf(stderr, "usage: %s host port jid password\n", argv[0]);
        return 2;
    }
    xmpp_initialize();
    ctx = xmpp_ctx_new(NULL, xmpp_get_default_logger(XMPP_LEVEL_WARN));
    conn = xmpp_conn_new(ctx);
    xmpp_conn_set_jid(conn, argv[3]);
    xmpp_conn_set_pass(conn, argv[4]);
    xmpp_conn_set_flags(conn, XMPP_CONN_FLAG_MANDATORY_TLS);
    if (xmpp_connect_client(conn, argv[1], (unsigned short)atoi(argv[2]), on_conn, ctx) != 0) {
        fprintf(stderr, "connect failed\n");
        return 1;
    }
    xmpp_run(ctx);
    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);
    xmpp_shutdown();
    printf("result: ping=%s connection-request=%s\n", (ok & 1) ? "ok" : "MISSING",
           (ok & 2) ? "ok" : "MISSING");
    return ok == 3 ? 0 : 1;
}
