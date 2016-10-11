/*
 * Copyright (C) 2016  Michael R. Altizer <xiche@verizon.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <daq.h>
#include <daq_api.h>
#include <daq_capture.h>

static const DAQ_Module_t *dm = NULL;
static void *handle = NULL;
static DAQ_Mode mode = DAQ_MODE_PASSIVE;
static DAQ_Capture_t *capture = NULL;

static volatile sig_atomic_t notdone = 1;

static void handler(int sig)
{
    void *newconfig, *oldconfig;
    switch(sig)
    {
        case SIGTERM:
        case SIGINT:
            daq_breakloop(dm, handle);
            notdone = 0;
            break;
        case SIGHUP:
            daq_hup_prep(dm, handle, &newconfig);
            daq_hup_apply(dm, handle, newconfig, &oldconfig);
            daq_hup_post(dm, handle, oldconfig);
            break;
    }
}

static void usage()
{
    printf("Usage: daqcap -d <daq_module> -i <input> [options...]\n");
    printf("  -c <num>   Acquire <num> packets (default = 0, <= 0 is unlimited)\n");
    printf("  -C <key[=value]>  Set a DAQ configuration key/value pair\n");
    printf("  -f <bpf>   Set the BPF based on <bpf>\n");
    printf("  -h         Display this usage text and exit\n");
    printf("  -m <path>  Specify the path to the directory to search for modules\n");
    printf("  -M <mode>  Specify the mode (passive (default), inline, read-file)\n");
    printf("  -s <len>   Specify the capture length in bytes (default = 1518)\n");
    printf("  -t <num>   Specify the read timeout in milliseconds (default = 0)\n");
    printf("  -v <level> Set the verbosity level of the DAQ library (default = 1)\n");
}

static DAQ_Verdict got_packet(void *user, const DAQ_PktHdr_t *hdr, const uint8_t *data)
{
    daq_capture_write(capture, hdr, data);
    return DAQ_VERDICT_PASS;
}

int main(int argc, char *argv[])
{
    struct sigaction action;
    DAQ_Config_t config;
	DAQ_Stats_t stats;
    const char **module_path = NULL;
    const char *options = "a:A:c:C:d:D:f:hi:lm:M:OpP:s:t:v:V:x";
    char errbuf[DAQ_ERRBUF_SIZE];
    char *input = NULL;
    char *daq = NULL;
    char *filter = NULL;
    char *cp;
    unsigned int num_module_paths = 0;
    unsigned int timeout = 0;
    int verbosity = 1;
    int snaplen = 1518;
    int flags = DAQ_CFG_PROMISC;
    int cnt = 0;
    int dlt;
    int ch;
    int rval;

    memset(&config, 0, sizeof(config));

    opterr = 0;
    while ((ch = getopt(argc, argv, options)) != -1)
    {
        switch (ch)
        {
            case 'c':
                cnt = strtol(optarg, NULL, 10);
                break;

            case 'C':
                cp = strchr(optarg, '=');
                if (cp)
                {
                    *cp = '\0';
                    cp++;
                    if (*cp == '\0')
                        cp = NULL;
                }
                printf("Key: %s, Value: %s\n", optarg, cp);
                daq_config_set_value(&config, optarg, cp);
                break;

            case 'd':
                daq = strdup(optarg);
                break;

            case 'f':
                filter = strdup(optarg);
                break;

            case 'h':
                usage();
                return 0;

            case 'i':
                input = strdup(optarg);
                break;

            case 'm':
                num_module_paths++;
                module_path = realloc(module_path, (num_module_paths + 1) * sizeof(char *));
                module_path[num_module_paths - 1] = strdup(optarg);
                module_path[num_module_paths] = NULL;
                break;

            case 'M':
                for (mode = DAQ_MODE_PASSIVE; mode < MAX_DAQ_MODE; mode++)
                {
                    if (!strcmp(optarg, daq_mode_string(mode)))
                        break;
                }
                if (mode == MAX_DAQ_MODE)
                {
                    fprintf(stderr, "Invalid mode: %s!\n", optarg);
                    return -1;
                }
                break;

            case 's':
                snaplen = strtoul(optarg, NULL, 10);
                break;

            case 't':
                timeout = strtoul(optarg, NULL, 10);
                break;

            case 'v':
                verbosity = strtol(optarg, NULL, 10);
                break;

            default:
                fprintf(stderr, "Invalid argument specified (%c)!\n", ch);
                return -1;
        }
    }

    if (!input || !daq)
    {
        usage();
        return -1;
    }

    daq_set_verbosity(verbosity);
    daq_load_modules(module_path);
    if (module_path)
    {
        while (num_module_paths > 0)
        {
            num_module_paths--;
            free((char *) module_path[num_module_paths]);
        }
        free(module_path);
    }

    dm = daq_find_module(daq);
    if (!dm)
    {
        fprintf(stderr, "Could not find requested module: %s!\n", daq);
        return -1;
    }

    config.name = input;
    config.snaplen = snaplen;
    config.timeout = timeout;
    config.mode = mode;
    config.flags = flags;

    if ((rval = daq_initialize(dm, &config, &handle, errbuf, sizeof(errbuf))) != 0)
    {
        fprintf(stderr, "Could not initialize DAQ module: (%d: %s)\n", rval, errbuf);
        return -1;
    }

    free(input);
    free(daq);

    /* Free the memory in the config's values dictionary. */
    daq_config_clear_values(&config);

    if (filter && (rval = daq_set_filter(dm, handle, filter)) != 0)
    {
        fprintf(stderr, "Could not set BPF filter for DAQ module! (%d: %s)\n", rval, filter);
        return -1;
    }

    if ((rval = daq_start(dm, handle)) != 0)
    {
        fprintf(stderr, "Could not start DAQ module: (%d: %s)\n", rval, daq_get_error(dm, handle));
        return -1;
    }

    dlt = daq_get_datalink_type(dm, handle);
    capture = daq_capture_open_writer("capture.dcap", dlt, snaplen);

    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGHUP, &action, NULL);

    while (notdone)
    {
        rval = daq_acquire_with_meta(dm, handle, cnt, got_packet, NULL, NULL);
        if (rval < 0)
        {
            if (rval != DAQ_READFILE_EOF || mode != DAQ_MODE_READ_FILE)
                fprintf(stderr, "Error acquiring packets! (%d)\n", rval);
            break;
        }
    }

    if ((rval = daq_get_stats(dm, handle, &stats)) != 0)
        fprintf(stderr, "Could not get DAQ module stats: (%d: %s)\n", rval, daq_get_error(dm, handle));
    daq_print_stats(&stats, NULL);

    daq_stop(dm, handle);

    daq_shutdown(dm, handle);

    daq_capture_close(capture);

    return 0;
}
