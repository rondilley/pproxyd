/****
 *
 * Passive Proxy Logging Daemon - Headers
 * 
 * Copyright (c) 2011-2015, Ron Dilley
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 ****/

#ifndef PPROXYD_DOT_H
#define PPROXYD_DOT_H

/****
 *
 * defines
 *
 ****/

#define LINEBUF_SIZE 4096
#define PORT_LIST "80,81,8080"

/****
 *
 * ripped from httpd.h which apr-1 does not include
 *
 ****/

#define M_GET                   0       /** RFC 2616: HTTP */
#define M_PUT                   1       /* : */
#define M_POST                  2
#define M_DELETE                3
#define M_CONNECT               4
#define M_OPTIONS               5
#define M_TRACE                 6       /** RFC 2616: HTTP */
#define M_PATCH                 7       /** no rfc(!)  ### remove this one? */
#define M_PROPFIND              8       /** RFC 2518: WebDAV */
#define M_PROPPATCH             9       /* : */
#define M_MKCOL                 10
#define M_COPY                  11
#define M_MOVE                  12
#define M_LOCK                  13
#define M_UNLOCK                14      /** RFC 2518: WebDAV */
#define M_VERSION_CONTROL       15      /** RFC 3253: WebDAV Versioning */
#define M_CHECKOUT              16      /* : */
#define M_UNCHECKOUT            17
#define M_CHECKIN               18
#define M_UPDATE                19
#define M_LABEL                 20
#define M_REPORT                21
#define M_MKWORKSPACE           22
#define M_MKACTIVITY            23
#define M_BASELINE_CONTROL      24
#define M_MERGE                 25
#define M_INVALID               26      /** RFC 3253: WebDAV Versioning */
#define UNKNOWN_METHOD (-1)

/****
 *
 * includes
 *
 ****/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sysdep.h>

#ifndef __SYSDEP_H__
# error something is messed up
#endif

#include <common.h>
#include <nids.h>
#include <pcap.h>
#include "util.h"
#include "mem.h"
#include "parser.h"
#include "hash.h"
#include "bintree.h"

/****
 *
 * consts & enums
 *
 ****/

/****
 *
 * typedefs & structs
 *
 ****/

struct proxyData {
  char *reqStr;
  char *respStr;
  int respCode;
  char *userAgentStr;
  char *hostStr;
  char *cTypeStr;
  unsigned long clientBytes;
  long startTime;
  long startUTime;
  long endTime;
  long endUTime;
};

/****
 *
 * function prototypes
 *
 ****/

void null_syslog(int type, int errnum, struct ip *iph, void *data);
void hexDump( size_t bPos, uint8_t buf[], size_t len );
char *strnstr(const char *s, const char *find, size_t slen);
int lookupHTTPMethod( const char *method, size_t len );
int dissectHTTP( char *data, size_t count, char *fwLog, struct proxyData *pData );
void tcp_sniff_callback(struct tcp_stream *stream, void **not_needed);

#endif /* PPROXYD_DOT_H */

