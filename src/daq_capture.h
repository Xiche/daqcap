/*
 * Copyright (C) 2016  Michael Altizer <xiche@verizon.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

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
