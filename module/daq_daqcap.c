/*
** Copyright (C) 2016 Michael R. Altizer <xiche@verizon.net>
** All rights reserved.
**
** This software may be modified and distributed under the terms
** of the BSD license.  See the LICENSE file for details.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <daq_api.h>
#include <sfbpf.h>

#include "daq_capture.h"

#define DAQ_DAQCAP_VERSION 1

typedef struct _daqcap_context
{
    char *filename;
    char *filter;
    int snaplen;
    int timeout;
    bool debug;
    DAQ_Capture_t *capture;
    struct sfbpf_program fcode;
    volatile bool break_loop;
    DAQ_Stats_t stats;
    DAQ_State state;
    char errbuf[256];
} DAQCap_Context_t;

static void destroy_daqcap_daq_context(DAQCap_Context_t *dcc)
{
    if (dcc)
    {
        if (dcc->capture)
            daq_capture_close(dcc->capture);
        free(dcc->filename);
        free(dcc->filter);
        free(dcc);
    }
}

static int daqcap_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t errlen)
{
    DAQCap_Context_t *dcc;
    DAQ_Dict *entry;
    int rval;

    dcc = calloc(1, sizeof(DAQCap_Context_t));
    if (!dcc)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the new daqcap context!", __func__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    dcc->filename = strdup(config->name);
    if (!dcc->filename)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the filename string!", __func__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    dcc->snaplen = config->snaplen;
    dcc->timeout = config->timeout;

    for (entry = config->values; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, "debug"))
            dcc->debug = true;
    }

    dcc->capture = daq_capture_open_reader(dcc->filename);
    if (!dcc->capture)
    {
        snprintf(errbuf, errlen, "%s: Unable to open DAQ capture for reading!", __func__);
        rval = DAQ_ERROR;
        goto err;
    }

    dcc->state = DAQ_STATE_INITIALIZED;

    *ctxt_ptr = dcc;
    return DAQ_SUCCESS;

err:
    destroy_daqcap_daq_context(dcc);

    return rval;
}

static int daqcap_daq_set_filter(void *handle, const char *filter)
{
    DAQCap_Context_t *dcc = (DAQCap_Context_t *) handle;
    struct sfbpf_program fcode;

    if (dcc->filter)
        free(dcc->filter);

    dcc->filter = strdup(filter);
    if (!dcc->filter)
    {
        DPE(dcc->errbuf, "%s: Couldn't allocate memory for the filter string!", __func__);
        return DAQ_ERROR;
    }

    if (sfbpf_compile(dcc->snaplen, DLT_EN10MB, &fcode, dcc->filter, 1, 0) < 0)
    {
        DPE(dcc->errbuf, "%s: BPF state machine compilation failed!", __func__);
        return DAQ_ERROR;
    }

    sfbpf_freecode(&dcc->fcode);
    dcc->fcode.bf_len = fcode.bf_len;
    dcc->fcode.bf_insns = fcode.bf_insns;

    return DAQ_SUCCESS;
}

static int daqcap_daq_start(void *handle)
{
    DAQCap_Context_t *dcc = (DAQCap_Context_t *) handle;

    dcc->state = DAQ_STATE_STARTED;

    return DAQ_SUCCESS;
}

static int daqcap_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user)
{
    DAQCap_Context_t *dcc = (DAQCap_Context_t *) handle;
    DAQ_PktHdr_t daqhdr;
    DAQ_Verdict verdict;
    uint8_t *data;
    int rval, c = 0;

    while (c < cnt || cnt >= 0)
    {
        if (dcc->break_loop)
        {
            dcc->break_loop = 0;
            return DAQ_SUCCESS;
        }

        rval = daq_capture_read(dcc->capture, &daqhdr, &data);
        if (rval < 0)
            return DAQ_ERROR;
        if (rval == 1)
            return DAQ_READFILE_EOF;

        if (dcc->fcode.bf_insns && sfbpf_filter(dcc->fcode.bf_insns, data, daqhdr.pktlen, daqhdr.caplen) == 0)
        {
            dcc->stats.packets_filtered++;
            continue;
        }

        if (callback)
        {
            verdict = callback(user, &daqhdr, data);
            if (verdict >= MAX_DAQ_VERDICT)
                verdict = DAQ_VERDICT_PASS;
            dcc->stats.verdicts[verdict]++;
        }
        dcc->stats.packets_received++;
        c++;
    }

    return DAQ_SUCCESS;
}

static int daqcap_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
    DAQCap_Context_t *dcc = (DAQCap_Context_t *) handle;

    dcc->stats.packets_injected++;

    return DAQ_SUCCESS;
}

static int daqcap_daq_breakloop(void *handle)
{
    DAQCap_Context_t *dcc = (DAQCap_Context_t *) handle;

    dcc->break_loop = true;

    return DAQ_SUCCESS;
}

static int daqcap_daq_stop(void *handle)
{
    DAQCap_Context_t *dcc = (DAQCap_Context_t *) handle;

    if (dcc->capture)
    {
        daq_capture_close(dcc->capture);
        dcc->capture = NULL;
    }

    dcc->state = DAQ_STATE_STOPPED;

    return DAQ_SUCCESS;
}

static void daqcap_daq_shutdown(void *handle)
{
    DAQCap_Context_t *dcc = (DAQCap_Context_t *) handle;

    destroy_daqcap_daq_context(dcc);
}

static DAQ_State daqcap_daq_check_status(void *handle)
{
    DAQCap_Context_t *dcc = (DAQCap_Context_t *) handle;

    return dcc->state;
}

static int daqcap_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    DAQCap_Context_t *dcc = (DAQCap_Context_t *) handle;

    memcpy(stats, &dcc->stats, sizeof(DAQ_Stats_t));
    return DAQ_SUCCESS;
}

static void daqcap_daq_reset_stats(void *handle)
{
    DAQCap_Context_t *dcc = (DAQCap_Context_t *) handle;

    memset(&dcc->stats, 0, sizeof(DAQ_Stats_t));
}

static int daqcap_daq_get_snaplen(void *handle)
{
    DAQCap_Context_t *dcc = (DAQCap_Context_t *) handle;

    return dcc->snaplen;
}

static uint32_t daqcap_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_INJECT | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_BPF;
}

static int daqcap_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

static const char *daqcap_daq_get_errbuf(void *handle)
{
    DAQCap_Context_t *dcc = (DAQCap_Context_t *) handle;

    return dcc->errbuf;
}

static void daqcap_daq_set_errbuf(void *handle, const char *string)
{
    DAQCap_Context_t *dcc = (DAQCap_Context_t *) handle;

    if (!string)
        return;

    DPE(dcc->errbuf, "%s", string);
    return;
}

static int daqcap_daq_get_device_index(void *handle, const char *device)
{
    return DAQ_ERROR_NODEV;
}

DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
{
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_DAQCAP_VERSION,
    .name = "daqcap",
    .type = DAQ_TYPE_FILE_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    .initialize = daqcap_daq_initialize,
    .set_filter = daqcap_daq_set_filter,
    .start = daqcap_daq_start,
    .acquire = daqcap_daq_acquire,
    .inject = daqcap_daq_inject,
    .breakloop = daqcap_daq_breakloop,
    .stop = daqcap_daq_stop,
    .shutdown = daqcap_daq_shutdown,
    .check_status = daqcap_daq_check_status,
    .get_stats = daqcap_daq_get_stats,
    .reset_stats = daqcap_daq_reset_stats,
    .get_snaplen = daqcap_daq_get_snaplen,
    .get_capabilities = daqcap_daq_get_capabilities,
    .get_datalink_type = daqcap_daq_get_datalink_type,
    .get_errbuf = daqcap_daq_get_errbuf,
    .set_errbuf = daqcap_daq_set_errbuf,
    .get_device_index = daqcap_daq_get_device_index,
    .modify_flow = NULL,
    .hup_prep = NULL,
    .hup_apply = NULL,
    .hup_post = NULL,
};
