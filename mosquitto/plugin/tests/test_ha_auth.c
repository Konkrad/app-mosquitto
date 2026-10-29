/*
 * Tests for the plugin internals. ha_auth.c is included directly so that the
 * static functions can be called, and the broker functions it uses are
 * stubbed out. Supervisor requests go to a small HTTP server in a child
 * process.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../ha_auth.c"
#include "test.h"

/* ------------------------------------------------------------------------
 * Broker stubs
 * ------------------------------------------------------------------------ */

static int callbacks_registered;

void mosquitto_log_printf(int level, const char *fmt, ...)
{
	UNUSED(level);
	UNUSED(fmt);
}

int mosquitto_callback_register(mosquitto_plugin_id_t *identifier, int event,
		MOSQ_FUNC_generic_callback cb_func, const void *event_data, void *userdata)
{
	UNUSED(identifier);
	UNUSED(event);
	UNUSED(cb_func);
	UNUSED(event_data);
	UNUSED(userdata);
	callbacks_registered++;
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_callback_unregister(mosquitto_plugin_id_t *identifier, int event,
		MOSQ_FUNC_generic_callback cb_func, const void *event_data)
{
	UNUSED(identifier);
	UNUSED(event);
	UNUSED(cb_func);
	UNUSED(event_data);
	callbacks_registered--;
	return MOSQ_ERR_SUCCESS;
}

/* ------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------ */

static char tmpdir[] = "/tmp/ha-auth-test-XXXXXX";

static char *tmp_path(const char *name)
{
	static char paths[8][256];
	static int next;
	char *p = paths[next++ % 8];

	snprintf(p, 256, "%s/%s", tmpdir, name);
	return p;
}

static void write_file(const char *path, const char *content)
{
	FILE *fp = fopen(path, "w");

	if(!fp){
		perror(path);
		exit(2);
	}
	fputs(content, fp);
	fclose(fp);
}

static char *read_file(const char *path)
{
	static char buf[16384];
	FILE *fp = fopen(path, "r");
	size_t n;

	buf[0] = '\0';
	if(!fp){
		return buf;
	}
	n = fread(buf, 1, sizeof(buf) - 1, fp);
	buf[n] = '\0';
	fclose(fp);
	return buf;
}

static char *make_hash(const char *password)
{
	static char hashes[8][256];
	static int next;
	char *h = hashes[next++ % 8];

	if(pbkdf2_create(password, 1000, h, 256)){
		fprintf(stderr, "pbkdf2_create failed\n");
		exit(2);
	}
	return h;
}

static void reset_plugin(void)
{
	free_users(plugin.users);
	free(plugin.users_file);
	free(plugin.supervisor_url);
	if(plugin.curl){
		curl_easy_cleanup(plugin.curl);
		curl_global_cleanup();
	}
	curl_slist_free_all(plugin.headers);
	memset(&plugin, 0, sizeof(plugin));
	plugin.cache_seconds = DEFAULT_CACHE_SECONDS;
}

static int auth_rc(const char *username, const char *password)
{
	struct mosquitto_evt_basic_auth ed = {
		.username = (char *)username,
		.password = (char *)password,
	};

	return basic_auth_callback(MOSQ_EVT_BASIC_AUTH, &ed, &plugin);
}

/* ------------------------------------------------------------------------
 * Fake Supervisor
 *
 * Answers every request with a status chosen by the username in the body:
 * "ok" gets 200, "denied" 401, "badreq" 400 and anything else 500. Each
 * request is appended to <tmpdir>/requests.
 * ------------------------------------------------------------------------ */

static pid_t server_pid;
static char server_url[64];

static void serve_connection(int fd, const char *log_path)
{
	char buf[8192];
	size_t len = 0;
	const char *status = "500 Internal Server Error";
	char *body;
	FILE *log;

	for(;;){
		ssize_t n = read(fd, buf + len, sizeof(buf) - 1 - len);

		if(n <= 0){
			break;
		}
		len += (size_t)n;
		buf[len] = '\0';

		body = strstr(buf, "\r\n\r\n");
		if(body){
			const char *cl = strcasestr(buf, "content-length:");
			size_t want = cl ? (size_t)atoi(cl + strlen("content-length:")) : 0;

			if(len >= (size_t)(body + 4 - buf) + want){
				break;
			}
		}
	}

	log = fopen(log_path, "a");
	if(log){
		fprintf(log, "%s\n----\n", buf);
		fclose(log);
	}

	body = strstr(buf, "\r\n\r\n");
	body = body ? body + 4 : buf;
	if(!strncmp(body, "username=ok&", 12)){
		status = "200 OK";
	}else if(!strncmp(body, "username=denied&", 16)){
		status = "401 Unauthorized";
	}else if(!strncmp(body, "username=badreq&", 16)){
		status = "400 Bad Request";
	}

	snprintf(buf, sizeof(buf),
			"HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status);
	if(write(fd, buf, strlen(buf)) < 0){
		/* the client went away */
	}
}

static void start_server(void)
{
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t alen = sizeof(addr);
	int one = 1;
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	char *log_path = tmp_path("requests");

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) || listen(fd, 8)
			|| getsockname(fd, (struct sockaddr *)&addr, &alen)){
		perror("fake supervisor");
		exit(2);
	}
	snprintf(server_url, sizeof(server_url), "http://127.0.0.1:%d/auth", ntohs(addr.sin_port));

	server_pid = fork();
	if(server_pid == 0){
		for(;;){
			int c = accept(fd, NULL, NULL);

			if(c < 0){
				continue;
			}
			serve_connection(c, log_path);
			close(c);
		}
	}
	close(fd);
}

static void stop_server(void)
{
	if(server_pid > 0){
		kill(server_pid, SIGTERM);
		waitpid(server_pid, NULL, 0);
		server_pid = 0;
	}
}

static int count_requests(void)
{
	const char *p = read_file(tmp_path("requests"));
	int n = 0;

	while((p = strstr(p, "POST ")) != NULL){
		n++;
		p += 5;
	}
	return n;
}

/* ------------------------------------------------------------------------
 * Tests
 * ------------------------------------------------------------------------ */

static void test_load_users(void)
{
	char content[2048];
	char *path = tmp_path("users");

	snprintf(content, sizeof(content),
			"# comment\n"
			"\n"
			"alice:%s\n"
			"AA:BB:CC:DD:EE:FF:%s\r\n"
			"nocolon\n"
			":%s\n"
			"badhash:plaintext\n"
			"alice:%s\n"
			"bob:%s",
			make_hash("alicepw"), make_hash("macpw"), make_hash("x"),
			make_hash("other"), make_hash("bobpw"));
	write_file(path, content);

	reset_plugin();
	plugin.users_file = strdup(path);
	CHECK(load_users(&plugin) == MOSQ_ERR_SUCCESS);

	CHECK(find_user(plugin.users, "alice") != NULL);
	CHECK(find_user(plugin.users, "bob") != NULL);
	CHECK(find_user(plugin.users, "AA:BB:CC:DD:EE:FF") != NULL);
	CHECK(find_user(plugin.users, "AA:BB:CC:DD:EE") == NULL);
	CHECK(find_user(plugin.users, "nocolon") == NULL);
	CHECK(find_user(plugin.users, "badhash") == NULL);
	CHECK(find_user(plugin.users, "") == NULL);

	CHECK(check_local(&plugin, "alice", "alicepw") == AUTH_GRANTED);
	/* The duplicate entry doesn't replace the first */
	CHECK(check_local(&plugin, "alice", "other") == AUTH_DENIED);
	CHECK(check_local(&plugin, "alice", "wrong") == AUTH_DENIED);
	CHECK(check_local(&plugin, "AA:BB:CC:DD:EE:FF", "macpw") == AUTH_GRANTED);
	CHECK(check_local(&plugin, "bob", "bobpw") == AUTH_GRANTED);
	CHECK(check_local(&plugin, "carol", "alicepw") == AUTH_DENIED);
	/* Passwords aren't checked against other users */
	CHECK(check_local(&plugin, "bob", "alicepw") == AUTH_DENIED);
}

static void test_load_users_errors(void)
{
	reset_plugin();
	plugin.users_file = strdup(tmp_path("missing"));
	CHECK(load_users(&plugin) == MOSQ_ERR_INVAL);

	write_file(tmp_path("empty"), "");
	reset_plugin();
	plugin.users_file = strdup(tmp_path("empty"));
	CHECK(load_users(&plugin) == MOSQ_ERR_SUCCESS);
	CHECK(plugin.users == NULL);
	CHECK(check_local(&plugin, "alice", "x") == AUTH_DENIED);
}

static void test_parse_options(void)
{
	struct mosquitto_opt opts[] = {
		{ .key = "users_file", .value = "/some/file" },
		{ .key = "supervisor_url", .value = "http://example.invalid/x" },
		{ .key = "cache_seconds", .value = "42" },
		{ .key = "http_timeout_ms", .value = "1234" },
		{ .key = "something_else", .value = "ignored" },
	};

	reset_plugin();
	CHECK(parse_options(&plugin, NULL, 0) == MOSQ_ERR_SUCCESS);
	CHECK(!strcmp(plugin.supervisor_url, DEFAULT_SUPERVISOR_URL));
	CHECK(plugin.http_timeout_ms == DEFAULT_HTTP_TIMEOUT_MS);
	CHECK(plugin.cache_seconds == DEFAULT_CACHE_SECONDS);
	CHECK(plugin.users_file == NULL);

	reset_plugin();
	CHECK(parse_options(&plugin, opts, 5) == MOSQ_ERR_SUCCESS);
	CHECK(!strcmp(plugin.users_file, "/some/file"));
	CHECK(!strcmp(plugin.supervisor_url, "http://example.invalid/x"));
	CHECK(plugin.cache_seconds == 42);
	CHECK(plugin.http_timeout_ms == 1234);

	/* An invalid timeout falls back to the default */
	opts[3].value = "-1";
	reset_plugin();
	CHECK(parse_options(&plugin, opts, 5) == MOSQ_ERR_SUCCESS);
	CHECK(plugin.http_timeout_ms == DEFAULT_HTTP_TIMEOUT_MS);
}

static void test_cache_key(void)
{
	unsigned char a[CACHE_KEY_LEN], b[CACHE_KEY_LEN], c[CACHE_KEY_LEN], d[CACHE_KEY_LEN];

	CHECK(cache_key("user", "pass", a));
	CHECK(cache_key("user", "pass", b));
	CHECK(!memcmp(a, b, CACHE_KEY_LEN));

	/* Moving the boundary between username and password changes the key */
	CHECK(cache_key("use", "rpass", c));
	CHECK(memcmp(a, c, CACHE_KEY_LEN) != 0);
	CHECK(cache_key("user", "Pass", d));
	CHECK(memcmp(a, d, CACHE_KEY_LEN) != 0);
}

static void test_cache(void)
{
	unsigned char k1[CACHE_KEY_LEN], k2[CACHE_KEY_LEN];
	bool granted = false;

	cache_key("u1", "p", k1);
	cache_key("u2", "p", k2);

	reset_plugin();
	CHECK(!cache_lookup(&plugin, k1, 1000, &granted));

	cache_store(&plugin, k1, true, 1000);
	cache_store(&plugin, k2, false, 1000);
	CHECK(cache_lookup(&plugin, k1, 1000, &granted) && granted);
	CHECK(cache_lookup(&plugin, k2, 1000, &granted) && !granted);

	/* Entries expire exactly cache_seconds later */
	CHECK(cache_lookup(&plugin, k1, 1000 + DEFAULT_CACHE_SECONDS - 1, &granted));
	CHECK(!cache_lookup(&plugin, k1, 1000 + DEFAULT_CACHE_SECONDS, &granted));

	/* Storing again replaces the entry instead of adding a second one */
	cache_store(&plugin, k1, false, 2000);
	CHECK(cache_lookup(&plugin, k1, 2000, &granted) && !granted);
	{
		int used = 0;

		for(int i = 0; i < CACHE_SIZE; i++){
			used += plugin.cache[i].used;
		}
		CHECK(used == 2);
	}

	/* cache_seconds = 0 disables the cache */
	reset_plugin();
	plugin.cache_seconds = 0;
	cache_store(&plugin, k1, true, 1000);
	CHECK(!cache_lookup(&plugin, k1, 1000, &granted));
}

static void test_cache_eviction(void)
{
	unsigned char key[CACHE_KEY_LEN];
	bool granted;
	char user[32];

	reset_plugin();

	/* Fill the cache; entry i expires at 1000 + 300 + i */
	for(int i = 0; i < CACHE_SIZE; i++){
		snprintf(user, sizeof(user), "user%d", i);
		cache_key(user, "pw", key);
		cache_store(&plugin, key, true, 1000 + i);
	}
	for(int i = 0; i < CACHE_SIZE; i++){
		snprintf(user, sizeof(user), "user%d", i);
		cache_key(user, "pw", key);
		CHECK(cache_lookup(&plugin, key, 1000, &granted));
	}

	/* One more evicts the entry closest to expiring and nothing else */
	cache_key("newuser", "pw", key);
	cache_store(&plugin, key, true, 1000 + CACHE_SIZE);
	CHECK(cache_lookup(&plugin, key, 1000, &granted));

	cache_key("user0", "pw", key);
	CHECK(!cache_lookup(&plugin, key, 1000, &granted));
	for(int i = 1; i < CACHE_SIZE; i++){
		snprintf(user, sizeof(user), "user%d", i);
		cache_key(user, "pw", key);
		CHECK(cache_lookup(&plugin, key, 1000, &granted));
	}

	/* An expired entry is reused before a live one is evicted */
	cache_key("later", "pw", key);
	cache_store(&plugin, key, true, 1000 + DEFAULT_CACHE_SECONDS + 5);
	CHECK(cache_lookup(&plugin, key, 1000 + DEFAULT_CACHE_SECONDS + 5, &granted));
	{
		unsigned char survivor[CACHE_KEY_LEN];

		cache_key("user200", "pw", survivor);
		CHECK(cache_lookup(&plugin, survivor, 1000 + DEFAULT_CACHE_SECONDS + 5, &granted));
	}
}

static void test_callback_local(void)
{
	char content[1024];
	char *path = tmp_path("cb_users");

	snprintf(content, sizeof(content), "alice:%s\n", make_hash("alicepw"));
	write_file(path, content);

	reset_plugin();
	plugin.users_file = strdup(path);
	parse_options(&plugin, NULL, 0);
	CHECK(load_users(&plugin) == MOSQ_ERR_SUCCESS);

	CHECK(auth_rc("alice", "alicepw") == MOSQ_ERR_SUCCESS);
	CHECK(auth_rc("alice", "wrong") == MOSQ_ERR_PLUGIN_DEFER);
	CHECK(auth_rc("nobody", "alicepw") == MOSQ_ERR_PLUGIN_DEFER);

	/* Anonymous clients are left to other plugins and the broker config */
	CHECK(auth_rc(NULL, NULL) == MOSQ_ERR_PLUGIN_DEFER);
	CHECK(auth_rc("alice", NULL) == MOSQ_ERR_PLUGIN_DEFER);
	CHECK(auth_rc(NULL, "alicepw") == MOSQ_ERR_PLUGIN_DEFER);

	/* Results are served from the cache, grants and denials alike */
	free_users(plugin.users);
	plugin.users = NULL;
	CHECK(auth_rc("alice", "alicepw") == MOSQ_ERR_SUCCESS);
	CHECK(auth_rc("alice", "wrong") == MOSQ_ERR_PLUGIN_DEFER);

	/* With the cache disabled the users are consulted every time */
	plugin.cache_seconds = 0;
	memset(plugin.cache, 0, sizeof(plugin.cache));
	CHECK(auth_rc("alice", "alicepw") == MOSQ_ERR_PLUGIN_DEFER);
}

static void test_no_supervisor_token(void)
{
	unsetenv("SUPERVISOR_TOKEN");
	reset_plugin();
	parse_options(&plugin, NULL, 0);
	CHECK(setup_supervisor(&plugin) == MOSQ_ERR_SUCCESS);
	CHECK(plugin.curl == NULL);
	CHECK(check_supervisor(&plugin, "ok", "pw") == AUTH_DENIED);
	CHECK(auth_rc("ok", "pw") == MOSQ_ERR_PLUGIN_DEFER);

	setenv("SUPERVISOR_TOKEN", "", 1);
	CHECK(setup_supervisor(&plugin) == MOSQ_ERR_SUCCESS);
	CHECK(plugin.curl == NULL);
}

static void test_supervisor(void)
{
	char *reqs;

	start_server();
	setenv("SUPERVISOR_TOKEN", "tok-123", 1);
	reset_plugin();
	plugin.supervisor_url = strdup(server_url);
	parse_options(&plugin, NULL, 0);
	CHECK(setup_supervisor(&plugin) == MOSQ_ERR_SUCCESS);
	CHECK(plugin.curl != NULL);

	CHECK(check_supervisor(&plugin, "ok", "pw") == AUTH_GRANTED);
	CHECK(check_supervisor(&plugin, "denied", "pw") == AUTH_DENIED);
	CHECK(check_supervisor(&plugin, "badreq", "pw") == AUTH_DENIED);
	/* Any other status is an error, not a denial */
	CHECK(check_supervisor(&plugin, "boom", "pw") == AUTH_ERROR);

	reqs = read_file(tmp_path("requests"));
	CHECK(strstr(reqs, "POST /auth ") != NULL);
	CHECK(strcasestr(reqs, "X-Supervisor-Token: tok-123\r\n") != NULL);
	CHECK(strstr(reqs, "username=ok&password=pw") != NULL);

	/* Special characters are percent-encoded */
	CHECK(check_supervisor(&plugin, "ok", "p&ss=w d%\xc3\xa4") == AUTH_GRANTED);
	reqs = read_file(tmp_path("requests"));
	CHECK(strstr(reqs, "username=ok&password=p%26ss%3Dw%20d%25%C3%A4") != NULL);

	/* An empty password is sent as such, not as the previous one */
	CHECK(check_supervisor(&plugin, "denied", "") == AUTH_DENIED);
	reqs = read_file(tmp_path("requests"));
	CHECK(strstr(reqs, "username=denied&password=\n----") != NULL);
}

static void test_callback_supervisor(void)
{
	int before;

	/* The server from test_supervisor is still running */
	setenv("SUPERVISOR_TOKEN", "tok-123", 1);
	reset_plugin();
	plugin.supervisor_url = strdup(server_url);
	parse_options(&plugin, NULL, 0);
	setup_supervisor(&plugin);

	before = count_requests();
	CHECK(auth_rc("ok", "pw") == MOSQ_ERR_SUCCESS);
	CHECK(count_requests() == before + 1);
	CHECK(auth_rc("ok", "pw") == MOSQ_ERR_SUCCESS);
	CHECK(count_requests() == before + 1);

	CHECK(auth_rc("denied", "pw") == MOSQ_ERR_PLUGIN_DEFER);
	CHECK(count_requests() == before + 2);
	CHECK(auth_rc("denied", "pw") == MOSQ_ERR_PLUGIN_DEFER);
	CHECK(count_requests() == before + 2);

	/* Errors are deferred and not cached */
	CHECK(auth_rc("boom", "pw") == MOSQ_ERR_PLUGIN_DEFER);
	CHECK(count_requests() == before + 3);
	CHECK(auth_rc("boom", "pw") == MOSQ_ERR_PLUGIN_DEFER);
	CHECK(count_requests() == before + 4);

	/* Local users win without asking the Supervisor */
	{
		char content[1024];

		snprintf(content, sizeof(content), "ok:%s\nlocal:%s\n", make_hash("localpw"), make_hash("localpw"));
		write_file(tmp_path("sv_users"), content);
		plugin.users_file = strdup(tmp_path("sv_users"));
		CHECK(load_users(&plugin) == MOSQ_ERR_SUCCESS);
		before = count_requests();
		CHECK(auth_rc("local", "localpw") == MOSQ_ERR_SUCCESS);
		CHECK(count_requests() == before);
		/* A local user with the wrong password falls through to the Supervisor */
		CHECK(auth_rc("local", "wrong") == MOSQ_ERR_PLUGIN_DEFER);
		CHECK(count_requests() == before + 1);
	}

	stop_server();
}

static void test_supervisor_unreachable(void)
{
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t alen = sizeof(addr);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	char url[64];

	/* Find a port nobody listens on */
	bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	getsockname(fd, (struct sockaddr *)&addr, &alen);
	close(fd);
	snprintf(url, sizeof(url), "http://127.0.0.1:%d/auth", ntohs(addr.sin_port));

	setenv("SUPERVISOR_TOKEN", "tok-123", 1);
	reset_plugin();
	plugin.supervisor_url = strdup(url);
	plugin.http_timeout_ms = 500;
	parse_options(&plugin, NULL, 0);
	setup_supervisor(&plugin);

	CHECK(check_supervisor(&plugin, "ok", "pw") == AUTH_ERROR);
	CHECK(auth_rc("ok", "pw") == MOSQ_ERR_PLUGIN_DEFER);
	{
		unsigned char key[CACHE_KEY_LEN];
		bool granted;

		cache_key("ok", "pw", key);
		CHECK(!cache_lookup(&plugin, key, now_seconds(), &granted));
	}
}

static void test_plugin_lifecycle(void)
{
	char content[1024];
	void *user_data = NULL;
	struct mosquitto_opt opts[] = {
		{ .key = "users_file", .value = tmp_path("lifecycle_users") },
		{ .key = "cache_seconds", .value = "10" },
	};

	snprintf(content, sizeof(content), "alice:%s\n", make_hash("alicepw"));
	write_file(tmp_path("lifecycle_users"), content);
	unsetenv("SUPERVISOR_TOKEN");

	callbacks_registered = 0;
	CHECK(mosquitto_plugin_init(NULL, &user_data, opts, 2) == MOSQ_ERR_SUCCESS);
	CHECK(user_data == &plugin);
	CHECK(callbacks_registered == 1);
	CHECK(plugin.cache_seconds == 10);
	CHECK(auth_rc("alice", "alicepw") == MOSQ_ERR_SUCCESS);

	CHECK(mosquitto_plugin_cleanup(user_data, opts, 2) == MOSQ_ERR_SUCCESS);
	CHECK(callbacks_registered == 0);
	CHECK(plugin.users == NULL);

	/* A missing users file stops the plugin from loading */
	opts[0].value = tmp_path("does_not_exist");
	CHECK(mosquitto_plugin_init(NULL, &user_data, opts, 2) != MOSQ_ERR_SUCCESS);
	CHECK(callbacks_registered == 0);
	reset_plugin();
}

int main(void)
{
	if(!mkdtemp(tmpdir)){
		perror("mkdtemp");
		return 2;
	}
	signal(SIGPIPE, SIG_IGN);

	test_load_users();
	test_load_users_errors();
	test_parse_options();
	test_cache_key();
	test_cache();
	test_cache_eviction();
	test_callback_local();
	test_no_supervisor_token();
	test_supervisor();
	test_callback_supervisor();
	test_supervisor_unreachable();
	test_plugin_lifecycle();

	stop_server();
	reset_plugin();
	{
		char cmd[64];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
		if(system(cmd)){
			/* leftover temp files are harmless */
		}
	}
	TEST_DONE();
}
