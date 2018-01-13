/*
 *  gnome-keyring-cli.c
 *
 *  Command line interface to Gnome Keyring Daemon
 *
 *  Brandon Casey <drafnel@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <glib.h>
#include <gnome-keyring.h>

#ifdef GNOME_KEYRING_DEFAULT

   /* Modern gnome-keyring */

#include <gnome-keyring-memory.h>

#else

   /*
    * Support ancient gnome-keyring, circ. RHEL 5.X.
    * GNOME_KEYRING_DEFAULT seems to have been introduced with Gnome 2.22,
    * and the other features roughly around Gnome 2.20, 6 months before.
    */

#define ANCIENT_GNOME_KEYRING
#define GNOME_KEYRING_DEFAULT NULL
#define gnome_keyring_memory_free gnome_keyring_free_password
#define gnome_keyring_string_list_free g_list_free

#include <sys/mman.h>

static gpointer gnome_keyring_memory_alloc(gulong size)
{
	gpointer ptr;

	ptr = g_malloc(size);

	if (mlock(ptr, size))
		perror("failed to lock memory pages");

	return ptr;
}

static const char* gnome_keyring_result_to_message(GnomeKeyringResult result)
{
	switch (result) {
	case GNOME_KEYRING_RESULT_OK:
		return "OK";
	case GNOME_KEYRING_RESULT_DENIED:
		return "Denied";
	case GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON:
		return "No Keyring Daemon";
	case GNOME_KEYRING_RESULT_ALREADY_UNLOCKED:
		return "Already UnLocked";
	case GNOME_KEYRING_RESULT_NO_SUCH_KEYRING:
		return "No Such Keyring";
	case GNOME_KEYRING_RESULT_BAD_ARGUMENTS:
		return "Bad Arguments";
	case GNOME_KEYRING_RESULT_IO_ERROR:
		return "IO Error";
	case GNOME_KEYRING_RESULT_CANCELLED:
		return "Cancelled";
	case GNOME_KEYRING_RESULT_ALREADY_EXISTS:
		return "Already Exists";
	default:
		return "Unknown Error";
	}
}

/*
 * Just a guess to support RHEL 4.X.
 * Glib 2.8 was roughly Gnome 2.12 ?
 * Which was released with gnome-keyring 0.4.3 ??
 */
#if GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION < 8

static void gnome_keyring_done_cb(GnomeKeyringResult result, gpointer user_data)
{
	gpointer *data = (gpointer*) user_data;
	int *done = (int*) data[0];
	GnomeKeyringResult *r = (GnomeKeyringResult*) data[1];

	*r = result;
	*done = 1;
}

static void prepend_string_list_item(gpointer data, gpointer user_data)
{
	GList **l = (GList**) user_data;
	*l = g_list_prepend(*l, g_strdup((const char*) data));
}

static GList* dup_string_list(GList* src)
{
	GList *l = NULL;
	g_list_foreach(src, prepend_string_list_item, &l);
	return g_list_reverse(l);
}

static void gnome_keyring_get_string_list_cb(GnomeKeyringResult result, GList *list, gpointer user_data)
{
	gpointer *data = (gpointer*) user_data;
	int *done = (int*) data[0];
	GnomeKeyringResult *r = (GnomeKeyringResult*) data[1];
	GList **l = (GList **) data[2];

	*r = result;
	if (result == GNOME_KEYRING_RESULT_OK)
		*l = dup_string_list(list);
	*done = 1;
}

static void gnome_keyring_get_int_list_cb(GnomeKeyringResult result, GList *list, gpointer user_data)
{
	gpointer *data = (gpointer*) user_data;
	int *done = (int*) data[0];
	GnomeKeyringResult *r = (GnomeKeyringResult*) data[1];
	GList **l = (GList **) data[2];

	*r = result;
	if (result == GNOME_KEYRING_RESULT_OK)
		*l = g_list_copy(list);
	*done = 1;
}

static void gnome_keyring_get_string_cb(GnomeKeyringResult result, const char *string, gpointer user_data)
{
	gpointer *data = (gpointer*) user_data;
	int *done = (int*) data[0];
	GnomeKeyringResult *r = (GnomeKeyringResult*) data[1];
	char **s = (char**) data[2];

	*r = result;
	if (result == GNOME_KEYRING_RESULT_OK)
		*s = g_strdup(string);
	*done = 1;
}

static void gnome_keyring_get_info_cb(GnomeKeyringResult result, GnomeKeyringInfo *info, gpointer user_data)
{
	gpointer *data = (gpointer*) user_data;
	int *done = (int*) data[0];
	GnomeKeyringResult *r = (GnomeKeyringResult*) data[1];
	GnomeKeyringInfo **i = (GnomeKeyringInfo**) data[2];

	*r = result;
	if (result == GNOME_KEYRING_RESULT_OK)
		*i = gnome_keyring_info_copy(info);
	*done = 1;
}

static void gnome_keyring_get_item_info_cb(GnomeKeyringResult result, GnomeKeyringItemInfo *info, gpointer user_data)
{
	gpointer *data = (gpointer*) user_data;
	int *done = (int*) data[0];
	GnomeKeyringResult *r = (GnomeKeyringResult*) data[1];
	GnomeKeyringItemInfo **i = (GnomeKeyringItemInfo**) data[2];

	*r = result;
	if (result == GNOME_KEYRING_RESULT_OK)
		*i = gnome_keyring_item_info_copy(info);
	*done = 1;
}

static void wait_for_request_completion(int *done)
{
	GMainContext *mc = g_main_context_default();
	while (!*done)
		g_main_context_iteration(mc, TRUE);
}

static GnomeKeyringResult gnome_keyring_unlock_sync(const char *keyring, const char *password)
{
	int done = 0;
	GnomeKeyringResult result;
	gpointer data[] = { &done, &result };

	gnome_keyring_unlock(keyring, password, gnome_keyring_done_cb, data,
		NULL);

	wait_for_request_completion(&done);

	return result;
}

static GnomeKeyringResult gnome_keyring_lock_sync(const char *keyring)
{
	int done = 0;
	GnomeKeyringResult result;
	gpointer data[] = { &done, &result };

	gnome_keyring_lock(keyring, gnome_keyring_done_cb, data, NULL);

	wait_for_request_completion(&done);

	return result;
}

static GnomeKeyringResult gnome_keyring_list_keyring_names_sync(GList **keyrings)
{
	int done = 0;
	GnomeKeyringResult result;
	gpointer data[] = { &done, &result, keyrings };

	*keyrings = NULL;

	gnome_keyring_list_keyring_names(gnome_keyring_get_string_list_cb,
		data, NULL);

	wait_for_request_completion(&done);

	return result;
}

static GnomeKeyringResult gnome_keyring_item_get_info_sync(const char *keyring, guint32 id, GnomeKeyringItemInfo **info)
{
	int done = 0;
	GnomeKeyringResult result;
	gpointer data[] = { &done, &result, info };

	gnome_keyring_item_get_info(keyring, id,
		gnome_keyring_get_item_info_cb, data, NULL);

	wait_for_request_completion(&done);

	return result;
}

static GnomeKeyringResult gnome_keyring_list_item_ids_sync(const char *keyring, GList **ids)
{
	int done = 0;
	GnomeKeyringResult result;
	gpointer data[] = { &done, &result, ids };

	gnome_keyring_list_item_ids(keyring, gnome_keyring_get_int_list_cb,
		data, NULL);

	wait_for_request_completion(&done);

	return result;
}

static GnomeKeyringResult gnome_keyring_get_default_keyring_sync(char **keyring)
{
	int done = 0;
	GnomeKeyringResult result;
	gpointer data[] = { &done, &result, keyring };

	gnome_keyring_get_default_keyring(gnome_keyring_get_string_cb, data,
		NULL);

	wait_for_request_completion(&done);

	return result;
}

static GnomeKeyringResult gnome_keyring_get_info_sync(const char *keyring, GnomeKeyringInfo **info)
{
	int done = 0;
	GnomeKeyringResult result;
	gpointer data[] = { &done, &result, info };

	gnome_keyring_get_info(keyring, gnome_keyring_get_info_cb, data, NULL);

	wait_for_request_completion(&done);

	return result;
}

static GnomeKeyringResult gnome_keyring_create_sync(const char *keyring, const char *password)
{
	int done = 0;
	GnomeKeyringResult result;
	gpointer data[] = { &done, &result };

	gnome_keyring_create(keyring, password, gnome_keyring_done_cb, data,
		NULL);

	wait_for_request_completion(&done);

	return result;
}

static GnomeKeyringResult gnome_keyring_delete_sync(const char *keyring)
{
	int done = 0;
	GnomeKeyringResult result;
	gpointer data[] = { &done, &result };

	gnome_keyring_delete(keyring, gnome_keyring_done_cb, data, NULL);

	wait_for_request_completion(&done);

	return result;
}

static GnomeKeyringResult gnome_keyring_item_delete_sync(const char *keyring, guint32 id)
{
	int done = 0;
	GnomeKeyringResult result;
	gpointer data[] = { &done, &result };

	gnome_keyring_item_delete(keyring, id, gnome_keyring_done_cb, data,
		NULL);

	wait_for_request_completion(&done);

	return result;
}

#endif
#endif

static int term_fd = -1;
static struct termios old_term;

/* lifted from compat/terminal.c in the git sources */
static int restore_term(void)
{
	int status = 0;

	if (term_fd < 0)
		return 0;

	if (tcsetattr(term_fd, TCSAFLUSH, &old_term)) {
		perror("failed to restore terminal settings");
		status = 1;
	}

	close(term_fd);
	term_fd = -1;

	return status;
}

static int disable_echo(void)
{
	struct termios t;

	term_fd = open("/dev/tty", O_RDWR);
	if (term_fd == -1) {
		perror("failed to open /dev/tty for writing");
		return -1;
	}

	if (tcgetattr(term_fd, &t) < 0) {
		perror("failed getting terminal attributes");
		goto error;
	}

	old_term = t;

	/* install sighandler to restore terminal */

	t.c_lflag &= ~ECHO;
	if (!tcsetattr(term_fd, TCSAFLUSH, &t))
		return 0;

	perror("failed to set terminal attributes");

error:
	close(term_fd);
	term_fd = -1;
	return -1;
}

static const char* gnome_keyring_itemtype_to_string(GnomeKeyringItemType t)
{
	static char type_string[32];

	switch (t) {
	case GNOME_KEYRING_ITEM_GENERIC_SECRET:
		return "GENERIC_SECRET";
	case GNOME_KEYRING_ITEM_NETWORK_PASSWORD:
		return "NETWORK_PASSWORD";
	case GNOME_KEYRING_ITEM_NOTE:
		return "NOTE";
#ifndef ANCIENT_GNOME_KEYRING
	case GNOME_KEYRING_ITEM_CHAINED_KEYRING_PASSWORD:
		return "CHAINED_KEYRING_PASSWORD";
	case GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD:
		return "ENCRYPTION_KEY_PASSWORD";
	case GNOME_KEYRING_ITEM_PK_STORAGE:
		return "PK_STORAGE";
#else
	case GNOME_KEYRING_ITEM_NO_TYPE:
		return "NO_TYPE";
#endif
	default:
		snprintf(type_string, sizeof(type_string),
			"Unrecognized Type (%u)", t);
		return type_string;
	}
}

#define PROMPT_BUF_SIZE 1024
#define PROMPT_NO_ECHO 0x1

static char* prompt_user(const char *prompt, int flags)
{
	char *value;
	size_t len;

	int noecho = (flags & PROMPT_NO_ECHO);

	if (noecho && disable_echo())
		g_warning("failed to disable terminal echo");

	fputs(prompt, stdout);
	fflush(stdout);

	value = noecho ? gnome_keyring_memory_alloc(PROMPT_BUF_SIZE) :
	    g_malloc(PROMPT_BUF_SIZE);

	if (!fgets(value, PROMPT_BUF_SIZE, stdin))
		value[0] = '\0';

	if (noecho) {
		putchar('\n');
		fflush(stdout);
		restore_term();
	}

	len = strlen(value);

	if (len && value[len-1] == '\n')
		value[--len] = '\0';

	if (!len) {
		if (noecho)
			gnome_keyring_memory_free(value);
		else
			g_free(value);
		return NULL;
	}

	return value;
}

static int unlock_keyring(int argc, char *argv[])
{
	const char *keyring = GNOME_KEYRING_DEFAULT;
	char *pass;
	GnomeKeyringResult result;

	if (argc > 2) {
		fprintf(stderr, "Usage: %s [keyring]\n", argv[0]);
		return 1;
	}

	if (argc == 2)
		keyring = argv[1];

	pass = prompt_user("Keyring password: ", PROMPT_NO_ECHO);

	result = gnome_keyring_unlock_sync(keyring, pass);

	gnome_keyring_memory_free(pass);

	if (result != GNOME_KEYRING_RESULT_OK) {
		g_critical("failed unlocking keyring: %s",
			gnome_keyring_result_to_message(result));
		return 1;
	}

	return 0;
}

static int lock_keyring(int argc, char *argv[])
{
	const char *keyring = GNOME_KEYRING_DEFAULT;
	GnomeKeyringResult result;

	if (argc > 2) {
		fprintf(stderr, "Usage: %s [keyring]\n", argv[0]);
		return 1;
	}

	if (argc == 2)
		keyring = argv[1];

	result = gnome_keyring_lock_sync(keyring);

	if (result != GNOME_KEYRING_RESULT_OK) {
		g_critical("failed locking keyring: %s",
			gnome_keyring_result_to_message(result));
		return 1;
	}

	return 0;
}

static void print_string_list_entry(gpointer data, gpointer unused_user_data)
{
	puts((const char*) data);
}

static int list_keyrings(int argc, char *argv[])
{
	GList *keyrings;
	GnomeKeyringResult result;

	if (argc > 1) {
		fprintf(stderr, "Usage: %s\n", argv[0]);
		return 1;
	}

	result = gnome_keyring_list_keyring_names_sync(&keyrings);

	if (result != GNOME_KEYRING_RESULT_OK) {
		g_critical("failed getting list of keyrings: %s",
			gnome_keyring_result_to_message(result));
		return 1;
	}

	g_list_foreach(keyrings, print_string_list_entry, NULL);

	gnome_keyring_string_list_free(keyrings);

	return 0;
}

static void print_keyring_item(gpointer data, gpointer user_data)
{
	guint32 id = GPOINTER_TO_UINT(data);
	gpointer *vals = (gpointer*) user_data;
	int *status = (int*) vals[0];
	const char* keyring = (const char*) vals[1];
	GnomeKeyringItemInfo *info;
	GnomeKeyringResult result;
	GnomeKeyringItemType type;
	time_t t;
	char *s;

	result = gnome_keyring_item_get_info_sync(keyring, id, &info);

	if (result != GNOME_KEYRING_RESULT_OK) {
		g_critical("failed getting item info: %s",
			gnome_keyring_result_to_message(result));
		*status = 1;
		return;
	}

	printf("---\n");

	type = gnome_keyring_item_info_get_type(info);

	printf("Type: %s\n", gnome_keyring_itemtype_to_string(type));

	s = gnome_keyring_item_info_get_display_name(info);

	printf("Name: %s\n", s);

	g_free(s);

	s = gnome_keyring_item_info_get_secret(info);

	printf("Secret: %s\n", s);

	gnome_keyring_memory_free(s);

	t = gnome_keyring_item_info_get_mtime(info);
	printf("mtime: %s", ctime(&t));

	t = gnome_keyring_item_info_get_ctime(info);
	printf("ctime: %s", ctime(&t));

	gnome_keyring_item_info_free(info);
}

static int list_items(int argc, char *argv[])
{
	GList *items;
	char *keyring = NULL;
	GnomeKeyringResult result;
	int status = 0;
	gpointer data[2] = { &status, NULL };

	if (argc > 2) {
		fprintf(stderr, "Usage: %s [keyring]\n", argv[0]);
		return 1;
	}

	if (argc == 2)
		keyring = g_strdup(argv[1]);

	if (!keyring) {
		result = gnome_keyring_get_default_keyring_sync(&keyring);

		if (result != GNOME_KEYRING_RESULT_OK) {
			g_critical("failed getting default keyring name: %s",
				gnome_keyring_result_to_message(result));
			return 1;
		}

		printf("Default keyring: %s\n", keyring);
	}

	result = gnome_keyring_list_item_ids_sync(keyring, &items);

	if (result != GNOME_KEYRING_RESULT_OK) {
		g_critical("failed getting list of items: %s",
			gnome_keyring_result_to_message(result));
		g_free(keyring);
		return 1;
	}

	data[1] = keyring;

	g_list_foreach(items, print_keyring_item, data);

	g_free(keyring);

	g_list_free(items);

	return status;
}

static int get_keyring_info(int argc, char *argv[])
{
	GnomeKeyringInfo *kinfo;
	char *keyring = NULL;
	time_t t;
	GnomeKeyringResult result;

	if (argc > 2) {
		fprintf(stderr, "Usage: %s [keyring]\n", argv[0]);
		return 1;
	}

	if (argc == 2)
		keyring = g_strdup(argv[1]);

	if (!keyring) {
		result = gnome_keyring_get_default_keyring_sync(&keyring);

		if (result != GNOME_KEYRING_RESULT_OK) {
			g_critical("failed getting default keyring name: %s",
				gnome_keyring_result_to_message(result));
			return 1;
		}

		printf("Default keyring name: %s\n", keyring);
	}

	result = gnome_keyring_get_info_sync(keyring, &kinfo);

	if (result != GNOME_KEYRING_RESULT_OK) {
		g_critical("failed getting keyring info: %s",
			gnome_keyring_result_to_message(result));
		return 1;
	}

	g_free(keyring);

	fputs("Locked: ", stdout);
	if (gnome_keyring_info_get_is_locked(kinfo))
		puts("yes");
	else
		puts("no");

	fputs("Lock-on-idle: ", stdout);
	if (gnome_keyring_info_get_lock_on_idle(kinfo))
		printf("%u\n", gnome_keyring_info_get_lock_timeout(kinfo));
	else
		puts("no");

	t = gnome_keyring_info_get_mtime(kinfo);
	printf("mtime: %s", ctime(&t));

	t = gnome_keyring_info_get_ctime(kinfo);
	printf("ctime: %s", ctime(&t));

	gnome_keyring_info_free(kinfo);

	return 0;
}

static int create_keyring(int argc, char *argv[])
{
	char *keyring;
	char *pass;
	GnomeKeyringResult result;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s keyring\n", argv[0]);
		return 1;
	}

	keyring = argv[1];

	pass = prompt_user("Keyring password: ", PROMPT_NO_ECHO);

	result = gnome_keyring_create_sync(keyring, pass);

	gnome_keyring_memory_free(pass);

	if (result != GNOME_KEYRING_RESULT_OK) {
		g_critical("failed creating keyring: %s",
			gnome_keyring_result_to_message(result));
		return 1;
	}

	return 0;
}

static int delete_keyring(int argc, char *argv[])
{
	char *keyring;
	GnomeKeyringResult result;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s keyring\n", argv[0]);
		return 1;
	}

	keyring = argv[1];

	result = gnome_keyring_delete_sync(keyring);

	if (result != GNOME_KEYRING_RESULT_OK) {
		g_critical("failed deleting keyring: %s",
			gnome_keyring_result_to_message(result));
		return 1;
	}

	return 0;
}

static void print_network_passwords(gpointer data, gpointer unused_user_data)
{
	GnomeKeyringNetworkPasswordData *pw =
	    (GnomeKeyringNetworkPasswordData*) data;

	printf("---\n"
	       "Keyring: %s\n"
	       "id: %u\n"
	       "protocol: %s\n"
	       "server: %s\n"
	       "object: %s\n"
	       "authtype: %s\n"
	       "port: %u\n"
	       "user: %s\n"
	       "domain: %s\n"
	       "password: %s\n",
	       pw->keyring,
	       pw->item_id,
	       pw->protocol,
	       pw->server,
	       pw->object,
	       pw->authtype,
	       pw->port,
	       pw->user,
	       pw->domain,
	       pw->password);
}

static int lookup_item(int argc, char *argv[])
{
	GnomeKeyringResult result;
	GList *entries;
	char *user;
	char *domain;
	char *server;
	char *object;
	char *protocol;
	char *authtype;
	char *s_port;
	guint32 port = 0;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s\n", argv[0]);
		return 1;
	}

	user = prompt_user("User: ", 0);
	domain = prompt_user("Domain: ", 0);
	server = prompt_user("Server: ", 0);
	protocol = prompt_user("Protocol: ", 0);
	object = prompt_user("Object: ", 0);
	authtype = prompt_user("AuthType: ", 0);
	s_port = prompt_user("Port: ", 0);

	if (s_port)
		sscanf(s_port, "%u", &port);

	g_free(s_port);

	result = gnome_keyring_find_network_password_sync(user, domain,
                server, object, protocol, authtype, port, &entries);

	g_free(user);
	g_free(domain);
	g_free(server);
	g_free(protocol);
	g_free(object);
	g_free(authtype);

	if (result != GNOME_KEYRING_RESULT_OK) {
		g_critical("failed searching for entries: %s",
			gnome_keyring_result_to_message(result));
		return 1;
	}

	g_list_foreach(entries, print_network_passwords, NULL);

	gnome_keyring_network_password_list_free(entries);

	return 0;
}

static int store_item(int argc, char *argv[])
{
	char *keyring = NULL;
	GnomeKeyringResult result;
	char *user;
	char *pass;
	char *domain;
	char *server;
	char *object;
	char *protocol;
	char *authtype;
	char *s_port;
	guint32 port = 0;
	guint32 item_id;

	if (argc > 2) {
		fprintf(stderr, "Usage: %s [keyring]\n", argv[0]);
		return 1;
	}

	if (argc == 2)
		keyring = argv[1];

	user = prompt_user("User: ", 0);
	domain = prompt_user("Domain: ", 0);
	server = prompt_user("Server: ", 0);
	protocol = prompt_user("Protocol: ", 0);
	object = prompt_user("Object: ", 0);
	authtype = prompt_user("AuthType: ", 0);
	s_port = prompt_user("Port: ", 0);

	if (s_port)
		sscanf(s_port, "%u", &port);

	g_free(s_port);

	pass = prompt_user("Password: ", PROMPT_NO_ECHO);

	result = gnome_keyring_set_network_password_sync(keyring, user, domain,
                server, object, protocol, authtype, port, pass, &item_id);

	gnome_keyring_memory_free(pass);
	g_free(user);
	g_free(domain);
	g_free(server);
	g_free(protocol);
	g_free(object);
	g_free(authtype);

	if (result != GNOME_KEYRING_RESULT_OK) {
		g_critical("failed storing to keyring: %s",
			gnome_keyring_result_to_message(result));
		return 1;
	}

	return 0;
}

static int erase_item(int argc, char *argv[])
{
	GnomeKeyringResult result;
	GList *entries;
	char *user;
	char *domain;
	char *server;
	char *object;
	char *protocol;
	char *authtype;
	char *s_port;
	guint32 port = 0;
	GnomeKeyringNetworkPasswordData *pw;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s\n", argv[0]);
		return 1;
	}

	user = prompt_user("User: ", 0);
	domain = prompt_user("Domain: ", 0);
	server = prompt_user("Server: ", 0);
	protocol = prompt_user("Protocol: ", 0);
	object = prompt_user("Object: ", 0);
	authtype = prompt_user("AuthType: ", 0);
	s_port = prompt_user("Port: ", 0);

	if (s_port)
		sscanf(s_port, "%u", &port);

	g_free(s_port);

	result = gnome_keyring_find_network_password_sync(user, domain,
                server, object, protocol, authtype, port, &entries);

	g_free(user);
	g_free(domain);
	g_free(server);
	g_free(protocol);
	g_free(object);
	g_free(authtype);

	if (result != GNOME_KEYRING_RESULT_OK) {
		g_critical("failed searching for entry: %s",
			gnome_keyring_result_to_message(result));
		return 1;
	}

	pw = (GnomeKeyringNetworkPasswordData*) entries->data;

	result = gnome_keyring_item_delete_sync(pw->keyring, pw->item_id);

	if (result != GNOME_KEYRING_RESULT_OK) {
		g_critical("failed deleting item: %s",
			gnome_keyring_result_to_message(result));
		gnome_keyring_network_password_list_free(entries);
		return 1;
	}

	gnome_keyring_network_password_list_free(entries);

	return 0;
}

#define ARRAY_LEN(_x) (sizeof(_x) / sizeof(*(_x)))

int main (int argc, char *argv[])
{
	const char *subcmd;
	size_t i;
	struct { const char* name; int (*func)(int, char **); } subcmds[] = {
		{ "lock", lock_keyring },
		{ "unlock", unlock_keyring },
		{ "list", list_keyrings },
		{ "info", get_keyring_info },
		{ "items", list_items },
		{ "create", create_keyring },
		{ "delete", delete_keyring },
		{ "lookup", lookup_item },
		{ "store", store_item },
		{ "erase", erase_item },
	};

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <%s", argv[0], subcmds[0].name);
		for (i = 1; i < ARRAY_LEN(subcmds); i++)
			fprintf(stderr, "|%s", subcmds[i].name);
		fputs("> [args]\n", stderr);
		return 1;
	}

	g_set_application_name("Gnome Keyring CLI");

	subcmd = argv[1];
	for (i = 0; i < ARRAY_LEN(subcmds); i++)
		if (!strcmp(subcmds[i].name, subcmd))
			return subcmds[i].func(argc-1, argv+1);

	g_critical("invalid sub-command \"%s\"\n", subcmd);

	return 1;
}
