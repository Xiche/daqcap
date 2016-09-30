#ifndef _DAQ_CAPTURE_H
#define _DAQ_CAPTURE_H

#include <daq_common.h>

typedef struct _daq_capture DAQ_Capture_t;

DAQ_Capture_t *daq_capture_open_reader(const char *filename);
DAQ_Capture_t *daq_capture_open_writer(const char *filename, int linktype, int snaplen);
uint32_t daq_capture_snaplen(DAQ_Capture_t *capture);
uint32_t daq_capture_linktype(DAQ_Capture_t *capture);
int daq_capture_read(DAQ_Capture_t *capture, DAQ_PktHdr_t *hdr, uint8_t **data);
void daq_capture_write(DAQ_Capture_t *capture, const DAQ_PktHdr_t *h, const uint8_t *data);
void daq_capture_close(DAQ_Capture_t *capture);

const char *daq_capture_geterr(DAQ_Capture_t *capture);

#endif /* _DAQ_CAPTURE_H */
