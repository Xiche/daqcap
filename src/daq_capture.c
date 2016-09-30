
#include "daq_capture.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define DAQCAP_MAGIC            0xda71ca70  // "daqcap"
#define DAQCAP_VERSION_MAJOR    1
#define DAQCAP_VERSION_MINOR    0


struct daqcap_file_header
{
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t snaplen;
    uint32_t linktype;
};

typedef enum
{
    DAQCAP_MODE_READ,
    DAQCAP_MODE_WRITE
} DAQ_Capture_Mode_t;

typedef struct _daq_capture
{
    FILE *fp;
    DAQ_Capture_Mode_t mode;
    uint32_t snaplen;
    uint32_t linktype;
    uint8_t *buffer;
} DAQ_Capture_t;


/*
 * Shared
 */

uint32_t daq_capture_snaplen(DAQ_Capture_t *capture)
{
    if (!capture)
        return 0;
    return capture->snaplen;
}

uint32_t daq_capture_linktype(DAQ_Capture_t *capture)
{
    if (!capture)
        return 0;
    return capture->linktype;
}

void daq_capture_close(DAQ_Capture_t *capture)
{
    if (capture)
    {
        if (capture->fp)
            fclose(capture->fp);
        free(capture->buffer);
        free(capture);
    }
}


/*
 * Reading
 */

DAQ_Capture_t *daq_capture_open_reader(const char *filename)
{
    struct daqcap_file_header hdr;
    DAQ_Capture_t *capture;
    size_t bytes_read;

    capture = calloc(1, sizeof(*capture));
    if (!capture)
        return NULL;

    capture->mode = DAQCAP_MODE_READ;

    capture->fp = fopen(filename, "rb");
    if (!capture->fp)
    {
        free(capture);
        return NULL;
    }

    bytes_read = fread((uint8_t *) &hdr.magic, 1, sizeof(hdr.magic), capture->fp);
    if (bytes_read != sizeof(hdr.magic))
    {
        if (ferror(capture->fp))
        {
            fprintf(stderr, "error reading capture file: %s", strerror(errno));
        }
        else
        {
            fprintf(stderr, "truncated capture file; tried to read %zu file header bytes, only got %zd",
                    sizeof(hdr.magic), bytes_read);
        }
        daq_capture_close(capture);
        return NULL;
    }

    if (hdr.magic != DAQCAP_MAGIC)
    {
        daq_capture_close(capture);
        return NULL;
    }

    bytes_read = fread(((uint8_t *) &hdr) + sizeof(hdr.magic), 1, sizeof(hdr) - sizeof(hdr.magic), capture->fp);
    if (bytes_read != sizeof(hdr) - sizeof(hdr.magic))
    {
        if (ferror(capture->fp))
            fprintf(stderr, "error reading capture file: %s", strerror(errno));
        else
            fprintf(stderr, "truncated capture file; tried to read %zu file header bytes, only got %zd",
                    sizeof(hdr), bytes_read + sizeof(hdr.magic));
        daq_capture_close(capture);
        return NULL;
    }

    if (hdr.version_major != DAQCAP_VERSION_MAJOR || hdr.version_minor != DAQCAP_VERSION_MINOR)
    {
        fprintf(stderr, "unsupported capture file version: %hu.%hu", hdr.version_major, hdr.version_minor);
        daq_capture_close(capture);
        return NULL;
    }

    capture->snaplen = hdr.snaplen;
    capture->linktype = hdr.linktype;

    capture->buffer = malloc(capture->snaplen);
    if (!capture->buffer)
    {
        fprintf(stderr, "couldn't allocate a %u-byte read buffer", capture->snaplen);
        daq_capture_close(capture);
        return NULL;
    }

    return capture;
}

int daq_capture_read(DAQ_Capture_t *capture, DAQ_PktHdr_t *hdr, uint8_t **data)
{
    size_t bytes_read;

    if (!capture || !capture->fp || capture->mode != DAQCAP_MODE_READ)
        return -1;

    bytes_read = fread(hdr, 1, sizeof(*hdr), capture->fp);
    if (bytes_read != sizeof(*hdr))
    {
        if (ferror(capture->fp))
        {
            fprintf(stderr, "error reading capture file: %s", strerror(errno));
            return -1;
        }
        else
        {
            if (bytes_read != 0)
            {
                fprintf(stderr, "truncated capture file; tried to read %zu file header bytes, only got %zd",
                        sizeof(*hdr), bytes_read);
                return -1;
            }
            /* EOF */
            return 1;
        }
    }

    if (hdr->caplen > capture->snaplen)
    {
        fprintf(stderr, "captured length exceeds capture snaplen (%u > %u)", hdr->caplen, capture->snaplen);
        return -1;
    }

    bytes_read = fread(capture->buffer, 1, hdr->caplen, capture->fp);
    if (bytes_read != hdr->caplen)
    {
        if (ferror(capture->fp))
            fprintf(stderr, "error reading capture file: %s", strerror(errno));
        else
            fprintf(stderr, "truncated capture file; tried to read %u captured bytes, only got %zd",
                    hdr->caplen, bytes_read);
    }
    *data = capture->buffer;

    return 0;
}


/*
 * Writing
 */

DAQ_Capture_t *daq_capture_open_writer(const char *filename, int linktype, int snaplen)
{
    struct daqcap_file_header dcf_hdr;
    DAQ_Capture_t *capture;

    capture = calloc(1, sizeof(*capture));
    if (!capture)
        return NULL;

    capture->mode = DAQCAP_MODE_WRITE;
    capture->snaplen = snaplen;

    capture->fp = fopen(filename, "wb");
    if (!capture->fp)
    {
        fprintf(stderr, "could not open capture output file %s: %s", filename, strerror(errno));
        free(capture);
        return NULL;
    }

    dcf_hdr.magic = DAQCAP_MAGIC;
    dcf_hdr.version_major = DAQCAP_VERSION_MAJOR;
    dcf_hdr.version_minor = DAQCAP_VERSION_MINOR;
    dcf_hdr.snaplen = snaplen;
    dcf_hdr.linktype = linktype;

    if (fwrite((const void *) &dcf_hdr, sizeof(dcf_hdr), 1, capture->fp) != 1)
    {
        fprintf(stderr, "could not write header to capture output file");
        fclose(capture->fp);
        free(capture);
        return NULL;
    }

    return capture;
}

void daq_capture_write(DAQ_Capture_t *capture, const DAQ_PktHdr_t *h, const uint8_t *data)
{
    DAQ_PktHdr_t hdr;

    if (!capture || !capture->fp || capture->mode != DAQCAP_MODE_WRITE || !h || !data)
        return;

    hdr = *h;
    // Remove flags that would prompt query_flow calls for now.
    hdr.flags &= ~(DAQ_PKT_FLAG_SCRUBBED_TCP_OPTS | DAQ_PKT_FLAG_HA_STATE_AVAIL);
    // Clear private pointer that will no longer be valid.
    hdr.priv_ptr = NULL;

    fwrite(&hdr, sizeof(hdr), 1, capture->fp);
    fwrite(data, hdr.caplen, 1, capture->fp);
}
