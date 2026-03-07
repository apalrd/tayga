#include "cmdline.h"
#include "tayga.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>

static const char *progname;

char *arg_conffile = TAYGA_CONF_PATH;
char *arg_user = NULL;
char *arg_group = NULL;
char *arg_pidfile = NULL;
int arg_do_mktun = 0;
int arg_do_rmtun = 0;
int arg_do_chroot = 0;
int arg_detach = 1;

static void usage(int code) {
	int pad = strlen(progname);
	fprintf(stderr,
			"TAYGA version %s\n"
			"Usage:\n"
			"%s [-c|--config CONFIGFILE] [-d|--debug] [-n|--nodetach]\n"
			"%*c [-u|--user USERID] [-g|--group GROUPID] [-r|--chroot] [-p|--pidfile PIDFILE]\n"
			"%*c [--syslog|--stdout|--journal]\n"
			"%s --mktun [-c|--config CONFIGFILE]\n"
			"%s --rmtun [-c|--config CONFIGFILE]\n"
			"%*c [-u|--user USERID] [-g|--group GROUPID] [-r|--chroot] [-p|--pidfile PIDFILE]\n\n"
			"--config FILE      : Read configuration options from FILE\n"
			"--debug, -d        : Enable debug messages (implies --nodetach and --stdout)\n"
			"--nodetach         : Do not fork the process\n"
			"--syslog           : Log messages to syslog (default)\n"
			"--stdout           : Log messages to stdout\n"
			"--journal          : Log messages to the systemd journal\n"
			"--user USERID      : Set uid to USERID after initialization\n"
			"--group GROUPID    : Set gid to GROUPID after initialization\n"
			"--chroot           : chroot() to data-dir (specified in config file)\n"
			"--pidfile FILE     : Write process ID of daemon to FILE\n"
			"--mktun            : Create the persistent TUN interface\n"
			"--rmtun            : Remove the persistent TUN interface\n"
			"--help, -h         : Show this help message\n",
		TAYGA_VERSION,
		progname,
		pad, ' ',
		pad, ' ',
		progname,
		progname,
		pad, ' '
	);
	exit(code);
}

/* Used during argument parsing, before logging is setup */
static void die(const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	putc('\n', stderr);
	exit(1);
}

void cmdline_parse(int argc, char **argv) {
	progname = argv[0];

	int arg_log_out = -1;
	struct option long_opts[] = {
		{ "mktun", no_argument, &arg_do_mktun, 1 },
		{ "rmtun", no_argument, &arg_do_rmtun, 1 },
		{ "syslog", no_argument, &arg_log_out, LOG_TO_SYSLOG },
		{ "stdout", no_argument, &arg_log_out, LOG_TO_STDOUT },
		{ "journal", no_argument, &arg_log_out, LOG_TO_JOURNAL },
		{ "help", no_argument, NULL, 'h' },
		{ "config", required_argument, NULL, 'c' },
		{ "nodetach", no_argument, NULL, 'n' },
		{ "user", required_argument, NULL, 'u' },
		{ "group", required_argument, NULL, 'g' },
		{ "chroot", no_argument, NULL, 'r' },
		{ "pidfile", required_argument, NULL, 'p' },
		{ "debug", no_argument, NULL, 'd' },
		{ NULL, 0, NULL, 0 }
	};

	/* Arg parsing loop */
	for (int c; c = getopt_long(argc, argv, "-c:dhnu:g:rp:", long_opts, NULL), c != -1;) {
		switch (c) {
		case 0:
			break;
		case 1:
			fprintf(stderr, "Warning: skipping positional argument `%s`\n", optarg);
			break;
		case 'c':
			arg_conffile = optarg;
			break;
		case 'd':
			arg_log_out = LOG_TO_STDOUT;
			arg_detach = 0;
			break;
		case 'n':
			arg_detach = 0;
			break;
		case 'u':
			arg_user = optarg;
			break;
		case 'g':
			arg_group = optarg;
			break;
		case 'r':
			arg_do_chroot = 1;
			break;
		case 'p':
			arg_pidfile = optarg;
			break;
		case 'h':
			usage(0);
			break;
		default:
			die("Try `%s --help' for more information", progname);
		}
	}

	// Make sure --mktun/--rmtun is not combined with unsupported options.
	if (arg_do_mktun || arg_do_rmtun) {
		if (arg_do_mktun && arg_do_rmtun)
			die("Error: both --mktun and --rmtun specified");
		if (arg_user)
			die("Error: cannot specify -u or --user with mktun/rmtun operation");
		if (arg_group)
			die("Error: cannot specify -g or --group with mktun/rmtun operation");
		if (arg_do_chroot)
			die("Error: cannot specify -r or --chroot with mktun/rmtun operation");

		// Cannot error here as it would be a nasty breaking change.
		if (arg_log_out != -1)
			fprintf(stderr, "Warning: cannot set logging on mktun/rmtun operation, forcing stdout\n");
		arg_log_out = LOG_TO_STDOUT;
	}

	if (arg_log_out != -1)
		gcfg->log_out = arg_log_out;
}
