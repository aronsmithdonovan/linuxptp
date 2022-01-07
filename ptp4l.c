/**
 * @file ptp4l.c
 * @brief PTP Boundary Clock or Transparent Clock main program
 * @note Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* 
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 *  INCLUDE STATEMENTS
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*/
	#include <limits.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <unistd.h>

	#include "clock.h"
		// clock_create
		// clock_poll
	#include "config.h"
		// config_create
		// config_long_options
		// config_parse_option
		// config_set_int
		// config_read
		// config_destroy
	#include "ntpshm.h"
	#include "pi.h"
	#include "print.h"
		// print_set_progname
		// print_set_tag
		// print_set_verbose
		// print_set_syslog
		// print_set_level
	#include "raw.h"
	#include "sk.h"
	#include "transport.h"
	#include "udp6.h"
	#include "uds.h"
	#include "util.h"
		// handle_term_signals
	#include "version.h"


/* 
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 *  usage
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*/
static void usage(char *progname)
{
	fprintf(stderr,
		"\nusage: %s [options]\n\n"
		" Delay Mechanism\n\n"
		" -A        Auto, starting with E2E\n"
		" -E        E2E, delay request-response (default)\n"
		" -P        P2P, peer delay mechanism\n\n"
		" Network Transport\n\n"
		" -2        IEEE 802.3\n"
		" -4        UDP IPV4 (default)\n"
		" -6        UDP IPV6\n\n"
		" Time Stamping\n\n"
		" -H        HARDWARE (default)\n"
		" -S        SOFTWARE\n"
		" -L        LEGACY HW\n\n"
		" Other Options\n\n"
		" -f [file] read configuration from 'file'\n"
		" -i [dev]  interface device to use, for example 'eth0'\n"
		"           (may be specified multiple times)\n"
		" -p [dev]  Clock device to use, default auto\n"
		"           (ignored for SOFTWARE/LEGACY HW time stamping)\n"
		" -s        slave only mode (overrides configuration file)\n"
		" -l [num]  set the logging level to 'num'\n"
		" -m        print messages to stdout\n"
		" -q        do not print messages to the syslog\n"
		" -v        prints the software version and exits\n"
		" -h        prints this message and exits\n"
		"\n",
		progname);
}

/* 
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 *  main
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*/
int main(int argc, char *argv[])
{
	// DEBUG
	pr_info("DEBUG: ptp4l.main\n");

	// initializations
	char *config = NULL, *req_phc = NULL, *progname;
	enum clock_type type = CLOCK_TYPE_ORDINARY;
	int c, err = -1, index, print_level;
	struct clock *clock = NULL;
	struct option *opts;
	struct config *cfg;

	// sets up a handler for terminating signals
	// TODO: what does this mean?
	if (handle_term_signals())
		return -1;

	// initialize a config struct
	cfg = config_create();
	if (!cfg) {
		return -1;
	}

	// get opts from cfg
	opts = config_long_options(cfg);

	// processing command line arguments
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt_long(argc, argv, "AEP246HSLf:i:p:sl:mqvh",
				       opts, &index))) {
		switch (c) {

		// 0 - ???
		// TODO: what does this mean?
		case 0:
			if (config_parse_option(cfg, opts[index].name, optarg))
				goto out;
			break;
		
		// A - automatically select delay measurement mechanism
		case 'A':
			if (config_set_int(cfg, "delay_mechanism", DM_AUTO))
				goto out;
			break;

		// E - select the end-to-end delay measurement mechanism
		case 'E':
			if (config_set_int(cfg, "delay_mechanism", DM_E2E))
				goto out;
			break;

		// P - select the peer-to-peer delay measurement mechanism
		case 'P':
			if (config_set_int(cfg, "delay_mechanism", DM_P2P))
				goto out;
			break;
		
		// 2 - select transport over Ethernet (standard IEEE 802.3)
		case '2':
			if (config_set_int(cfg, "network_transport",
					    TRANS_IEEE_802_3))
				goto out;
			break;
		
		// 4 - select transport over IPv4-based UDP
		case '4':
			if (config_set_int(cfg, "network_transport",
					    TRANS_UDP_IPV4))
				goto out;
			break;

		// 6 - select transport over IPv6-based UDP
		case '6':
			if (config_set_int(cfg, "network_transport",
					    TRANS_UDP_IPV6))
				goto out;
			break;
		
		// H - select hardware timestamping
		case 'H':
			if (config_set_int(cfg, "time_stamping", TS_HARDWARE))
				goto out;
			break;

		// S - select software timestamping
		case 'S':
			if (config_set_int(cfg, "time_stamping", TS_SOFTWARE))
				goto out;
			break;

		// L - select legacy hardware timestamping
		case 'L':
			if (config_set_int(cfg, "time_stamping", TS_LEGACY_HW))
				goto out;
			break;
		
		// f - specify a configuration file
		case 'f':
			config = optarg;
			break;

		// i - specify a PTP port [REQUIRED]
		case 'i':
			if (!config_create_interface(optarg, cfg))
				goto out;
			break;

		// p - specify which PHC device should be used (with hardware timestamping only)
		case 'p':
			req_phc = optarg;
			break;

		// s - enable slaveOnly mode
		// TODO: what does this mean?
		case 's':
			if (config_set_int(cfg, "slaveOnly", 1)) {
				goto out;
			}
			break;

		// l - specify the maximum syslog level of messages that should be printed or sent to the system logger (default 6)
		case 'l':
			if (get_arg_val_i(c, optarg, &print_level,
					  PRINT_LEVEL_MIN, PRINT_LEVEL_MAX))
				goto out;
			config_set_int(cfg, "logging_level", print_level);
			break;

		// m - enable verbose messages
		case 'm':
			config_set_int(cfg, "verbose", 1);
			break;

		// q - disable messages to the system logger
		case 'q':
			config_set_int(cfg, "use_syslog", 0);
			break;

		// v - print messages to the standard output
		// TODO: what does this mean?
		case 'v':
			version_show(stdout);
			return 0;

		// h - display usage message 
		case 'h':
			usage(progname);
			return 0;

		// ? - display usage message and go to out statement (same as default)
		// TODO: what does this mean?
		case '?':
			usage(progname);
			goto out;

		// default - display usage message and go to out statement
		default:
			usage(progname);
			goto out;
		}
	}

	// ???
	// TODO: what does this mean?
	if (config && (c = config_read(config, cfg))) {
		return c;
	}

	// ???
	// TODO: what does this mean?
	print_set_progname(progname);
	print_set_tag(config_get_string(cfg, NULL, "message_tag"));
	print_set_verbose(config_get_int(cfg, NULL, "verbose"));
	print_set_syslog(config_get_int(cfg, NULL, "use_syslog"));
	print_set_level(config_get_int(cfg, NULL, "logging_level"));

	// ???
	// TODO: what does this mean?
	assume_two_step = config_get_int(cfg, NULL, "assume_two_step");
	sk_check_fupsync = config_get_int(cfg, NULL, "check_fup_sync");
	sk_tx_timeout = config_get_int(cfg, NULL, "tx_timestamp_timeout");
	sk_hwts_filter_mode = config_get_int(cfg, NULL, "hwts_filter");

	// if clock_servo == CLOCK_SERVO_NTPSHM, set kernel_leap and sanity_freq_limit to 0
	if (config_get_int(cfg, NULL, "clock_servo") == CLOCK_SERVO_NTPSHM) {
		config_set_int(cfg, "kernel_leap", 0);
		config_set_int(cfg, "sanity_freq_limit", 0);
	}

	// check if an interface is specified; if not, display usage message and go to out statement
	if (STAILQ_EMPTY(&cfg->interfaces)) {
		fprintf(stderr, "no interface specified\n");
		usage(progname);
		goto out;
	}

	// get clock_type
	type = config_get_int(cfg, NULL, "clock_type");
	// check that minimum requirements for clock type are fulfilled
	switch (type) {
	case CLOCK_TYPE_ORDINARY:
		if (cfg->n_interfaces > 1) {
			type = CLOCK_TYPE_BOUNDARY;
		}
		break;
	case CLOCK_TYPE_BOUNDARY:
		if (cfg->n_interfaces < 2) {
			fprintf(stderr, "BC needs at least two interfaces\n");
			goto out;
		}
		break;
	case CLOCK_TYPE_P2P:
		if (cfg->n_interfaces < 2) {
			fprintf(stderr, "TC needs at least two interfaces\n");
			goto out;
		}
		if (DM_P2P != config_get_int(cfg, NULL, "delay_mechanism")) {
			fprintf(stderr, "P2P_TC needs P2P delay mechanism\n");
			goto out;
		}
		break;
	case CLOCK_TYPE_E2E:
		if (cfg->n_interfaces < 2) {
			fprintf(stderr, "TC needs at least two interfaces\n");
			goto out;
		}
		if (DM_E2E != config_get_int(cfg, NULL, "delay_mechanism")) {
			fprintf(stderr, "E2E_TC needs E2E delay mechanism\n");
			goto out;
		}
		break;
	case CLOCK_TYPE_MANAGEMENT:
		goto out;
	}

	// create a clock instance
	// note: there can only be one clock in any system, so subsequent calls will destroy the previous instance
	clock = clock_create(type, cfg, req_phc);
	// if fail to create a clock, go to out statement
	if (!clock) {
		fprintf(stderr, "failed to create a clock\n");
		goto out;
	}

	err = 0;

	while (is_running()) {
		// poll for events and dispatch them (zero on success, non-zero otherwise)
		if (clock_poll(clock))
			break;
	}

// out statement
out:
	// if clock, destroy it
	if (clock)
		clock_destroy(clock);

	// destroy config object
	config_destroy(cfg);
	
	// return error
	return err;
}
