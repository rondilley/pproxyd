/****
 *
 * Passive Proxy Logging Daemon
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

/****
 *
 * includes
 *
 ****/

#include "pproxyd.h"

/****
 *
 * local variables
 *
 ****/

PRIVATE char *cvsid = "$Id: pproxyd.c,v 1.4 2012/02/04 22:17:34 rdilley Exp $";

/****
 *
 * global variables
 *
 ****/

/* hashes */
struct hash_s *templateHash = NULL;

/****
 *
 * external variables
 *
 ****/

extern int errno;
extern char **environ;
extern Config_t *config;
extern int quit;
extern int reload;

/* libnids externs */
extern struct nids_prm nids_params;
extern struct pcap_pkthdr *nids_last_pcap_header;

/****
 *
 * functions
 *
 ****/

/****
 *
 * hexdump
 *
 ****/

void hexDump( size_t bPos, uint8_t buf[], size_t len ) {
  size_t y, i = 0;

#ifdef DEBUG
  if ( config->debug >= 7 )
    display( LOG_DEBUG, "%d %d", bPos, len );
#endif

  while ( i < len ) {
    printf( "%08x ", (uint32_t)(bPos + i) );
    for ( y = 0; y < 16 & i + y < len; y++ ) {

      printf( "%02x", (uint8_t)buf[i+y] );
      printf( " " );
    }
    while( y < 16 ) {
      printf( "   " );
      y++;
    }
    printf( " " );
    for ( y = 0; y < 16 & i + y < len; y++ ) {
      if ( ( buf[i+y] < 32 ) | ( buf[i+y] > 127 ) )
        printf( "." );
      else
        printf( "%c", buf[i+y] );
    }
    i += y;

    printf( "\n" );
  }
}

/****
 *
 * safe strstr
 *
 ****/

char *strnstr(const char *s, const char *find, size_t slen) {
  char c, sc;
  size_t len;

  if ((c = *find++) != '\0') {
    len = strlen(find);
    do {
      do {
	if (slen < 1 || (sc = *s) == '\0')
	  return (NULL);
	--slen;
	++s;
      } while (sc != c);
      if (len > slen)
	return (NULL);
    } while (strncmp(s, find, len) != 0);
    s--;
  }
  return (char *) s;
}

/****
 *
 * dummy syslog destination for events
 *
 ****/

void null_syslog(int type, int errnum, struct ip *iph, void *data) {
  /* do nothing */
}

/****
 *
 * extract HTTP method
 *
 * ripped from modules/http/http_protocol.c
 *
 ****/

int lookupHTTPMethod( const char *method, size_t len ) {
  int i;

  for( i = 0; i < len && method[i] != ' '; i++ );

  switch (i) {
  case 3:
    switch (method[0]) {
    case 'P':
      return (method[1] == 'U' && method[2] == 'T' ? M_PUT : UNKNOWN_METHOD);
    case 'G':
      return (method[1] == 'E' && method[2] == 'T' ? M_GET : UNKNOWN_METHOD);
    default:
      return UNKNOWN_METHOD;
    }
    
  case 4:
    switch (method[0]) {
    case 'H':
      return (method[1] == 'E' && method[2] == 'A' && method[3] == 'D' ? M_GET : UNKNOWN_METHOD);
    case 'P':
      return (method[1] == 'O' && method[2] == 'S' && method[3] == 'T' ? M_POST : UNKNOWN_METHOD);
    case 'M':
      return (method[1] == 'O' && method[2] == 'V' && method[3] == 'E' ? M_MOVE : UNKNOWN_METHOD);
    case 'L':
      return (method[1] == 'O' && method[2] == 'C' && method[3] == 'K' ? M_LOCK : UNKNOWN_METHOD);
    case 'C':
      return (method[1] == 'O' && method[2] == 'P' && method[3] == 'Y' ? M_COPY : UNKNOWN_METHOD);
    default:
      return UNKNOWN_METHOD;
    }
    
  case 5:
    switch (method[2]) {
    case 'T':
      return (memcmp(method, "PATCH", 5) == 0 ? M_PATCH : UNKNOWN_METHOD);
    case 'R':
      return (memcmp(method, "MERGE", 5) == 0 ? M_MERGE : UNKNOWN_METHOD);
    case 'C':
      return (memcmp(method, "MKCOL", 5) == 0 ? M_MKCOL : UNKNOWN_METHOD);
    case 'B':
      return (memcmp(method, "LABEL", 5) == 0 ? M_LABEL : UNKNOWN_METHOD);
    case 'A':
      return (memcmp(method, "TRACE", 5) == 0 ? M_TRACE : UNKNOWN_METHOD);
    default:
      return UNKNOWN_METHOD;
    }
    
  case 6:
    switch (method[0]) {
    case 'U':
      switch (method[5]) {
      case 'K':
	return (memcmp(method, "UNLOCK", 6) == 0 ? M_UNLOCK : UNKNOWN_METHOD);
      case 'E':
	return (memcmp(method, "UPDATE", 6) == 0 ? M_UPDATE : UNKNOWN_METHOD);
      default:
	return UNKNOWN_METHOD;
      }
    case 'R':
      return (memcmp(method, "REPORT", 6) == 0 ? M_REPORT : UNKNOWN_METHOD);
    case 'D':
      return (memcmp(method, "DELETE", 6) == 0 ? M_DELETE : UNKNOWN_METHOD);
    default:
      return UNKNOWN_METHOD;
    }
    
  case 7:
    switch (method[1]) {
    case 'P':
      return (memcmp(method, "OPTIONS", 7) == 0 ? M_OPTIONS : UNKNOWN_METHOD);
    case 'O':
      return (memcmp(method, "CONNECT", 7) == 0 ? M_CONNECT : UNKNOWN_METHOD);
    case 'H':
      return (memcmp(method, "CHECKIN", 7) == 0 ? M_CHECKIN : UNKNOWN_METHOD);
    default:
      return UNKNOWN_METHOD;
    }
    
  case 8:
    switch (method[0]) {
    case 'P':
      return (memcmp(method, "PROPFIND", 8) == 0 ? M_PROPFIND : UNKNOWN_METHOD);
    case 'C':
      return (memcmp(method, "CHECKOUT", 8) == 0 ? M_CHECKOUT : UNKNOWN_METHOD);
    default:
      return UNKNOWN_METHOD;
    }
    
  case 9:
    return (memcmp(method, "PROPPATCH", 9) == 0 ? M_PROPPATCH : UNKNOWN_METHOD);
    
  case 10:
    switch (method[0]) {
    case 'U':
      return (memcmp(method, "UNCHECKOUT", 10) == 0 ? M_UNCHECKOUT : UNKNOWN_METHOD);
    case 'M':
      return (memcmp(method, "MKACTIVITY", 10) == 0 ? M_MKACTIVITY : UNKNOWN_METHOD);
    default:
      return UNKNOWN_METHOD;
    }
    
  case 11:
    return (memcmp(method, "MKWORKSPACE", 11) == 0 ? M_MKWORKSPACE : UNKNOWN_METHOD);
    
  case 15:
    return (memcmp(method, "VERSION-CONTROL", 15) == 0 ? M_VERSION_CONTROL : UNKNOWN_METHOD);
    
  case 16:
    return (memcmp(method, "BASELINE-CONTROL", 16) == 0 ? M_BASELINE_CONTROL : UNKNOWN_METHOD);
  }

  return UNKNOWN_METHOD;
}

/****
 *
 * disect http requests
 *
 ****/

int dissectHTTP( char *data, size_t count, char *fwLog, struct proxyData *pData ) {
  int i, s, tmpCode, msgCount = 0, m, done = 0;
  uint32_t curPos, hdrOff;
  char *curPtr, *tmpPtr, *tmpCharPtr, *sPtr, *cPtr;
  uint8_t tmpBuf[4096];

  if ( data == NULL ) {
    fprintf( stderr, "NULL data\n" );
    return( -1 );
  }

  curPtr = data;

  while( ( curPtr - data ) < count ) {
    hdrOff = curPtr - data;   
    if ( ( m = lookupHTTPMethod( curPtr, count ) ) == UNKNOWN_METHOD ) {
#ifdef DEBUG
      if ( config->debug >= 3 )
	printf( "%s\n", fwLog );
#endif
      if ( curPtr[0] == 'H' && curPtr[1] == 'T' && curPtr[2] == 'T' && curPtr[3] == 'P' ) {

	/* grab the response string */
	for( i = 0; curPtr[i] != '\r' & i < count; i++ );
	pData->respStr = (char *)XMALLOC( i+1 );
	XMEMSET( pData->respStr, 0, i+1 );
	for( i = 0; curPtr[i] != '\r' & i < count; i++ )
	  pData->respStr[i] = curPtr[i];
	if ( sscanf( pData->respStr, "%s %d ", (char *)&tmpBuf, &i ) EQ 2 )
	  pData->respCode = i;

	/* grab the content type string, if it exists */
	if ( ( tmpPtr = strnstr( curPtr, "Content-Type: ", count ) ) != NULL ) {
	  for( i = 14; tmpPtr[i] != '\r' & tmpPtr[i] != ' ' & tmpPtr[i] != ';' & (tmpPtr-curPtr)+i < count; i++ );
	  pData->cTypeStr = (char *)XMALLOC( i+1 );
	  XMEMSET( pData->cTypeStr, 0, i+1 );
	  i--;
	  while( i >= 14 ) { pData->cTypeStr[i-14] = tmpPtr[i]; i--; }
	}

#ifdef DEBUG
	if ( config->debug >= 3 )
	  printf( "=====\n" );
#endif

	for( i = 0; i < count & ! done; i++ ) {
	  if ( curPtr[i] == '\r' && curPtr[i+1] == '\n' && curPtr[i+2] == '\r' && curPtr[i+3] == '\n' ) {
	    done = 1;
	  } else if ( curPtr[i] == '\r' && curPtr[i+1] == '\n' ) {
	    if ( config->debug >= 4 )
	      printf( "\n" );
	    i++;
	  } else if ( isprint( curPtr[i] ) )
	    if ( config->debug >= 4 )
	      printf( "%c", curPtr[i] );
	    else
	      if ( config->debug >= 4 )
		printf( "\n" );
	}
	if ( config->debug >= 4 )
	  printf( "\n\n" );
      } else {
	//hexDump( hdrOff, data + hdrOff, count );
      }
      curPtr += count;
    } else if ( m == M_POST || m == M_PUT ) {

      /* grab the request string */
      for( i = 0; curPtr[i] != '\r' & i < count; i++ );
      pData->reqStr = (char *)XMALLOC( i+1 );
      XMEMSET( pData->reqStr, 0, i+1 );
      for( i = 0; curPtr[i] != '\r' & i < count; i++ )
	pData->reqStr[i] = curPtr[i];

      /* grab the host string, if it exists */
      if ( ( tmpPtr = strnstr( curPtr, "Host: ", count ) ) != NULL ) {
	for( i = 6; tmpPtr[i] != '\r' & (tmpPtr-curPtr)+i < count; i++ );
	pData->hostStr = (char *)XMALLOC( i+1 );
	XMEMSET( pData->hostStr, 0, i+1 );
	i--;
	while( i >= 6 ) { pData->hostStr[i-6] = tmpPtr[i]; i--; }
      }

      /* grab the user-agent string, if it exists */
      if ( ( tmpPtr = strnstr( curPtr, "User-Agent: ", count ) ) != NULL ) {
	for( i = 12; tmpPtr[i] != '\r' & (tmpPtr-curPtr)+i < count; i++ );
	pData->userAgentStr = (char *)XMALLOC( i+1 );
	XMEMSET( pData->userAgentStr, 0, i+1 );
	i--;
	while( i >= 12 ) { pData->userAgentStr[i-12] = tmpPtr[i]; i--; }
      }

#ifdef DEBUG
      if ( config->debug >= 3 ) {
	printf( "%s\n", fwLog );
	printf( "=====\n" );
      }
#endif

      for( i = 0; i < count & ! done; i++ ) {
	if ( curPtr[i] == '\r' && curPtr[i+1] == '\n' && curPtr[i+2] == '\r' && curPtr[i+3] == '\n' ) {
	  done = 1;
	  } else if ( curPtr[i] == '\r' && curPtr[i+1] == '\n' ) {
	  if ( config->debug >= 4 )
	    printf( "\n" );
	  i++;
	} else if ( isprint( curPtr[i] ) )
	  if ( config->debug >= 4 )
	    printf( "%c", curPtr[i] );
	else
	  if ( config->debug >= 4 )
	    printf( "\n" );
      }
      if ( config->debug >= 4 )
	printf( "\n\n" );
      //hexDump( hdrOff, data + hdrOff, count );
      curPtr += i;

    } else if ( m == M_GET ) {

      /* grab the request string */
      for( i = 0; curPtr[i] != '\r' & i < count; i++ );
      pData->reqStr = (char *)XMALLOC( i+1 );
      XMEMSET( pData->reqStr, 0, i+1 );
      i-=10;
      while( i >= 0 ) { pData->reqStr[i] = curPtr[i]; i--; }

      /* grab the host string, if it exists */
      if ( ( tmpPtr = strnstr( curPtr, "Host: ", count ) ) != NULL ) {
	for( i = 6; tmpPtr[i] != '\r' & (tmpPtr-curPtr)+i < count; i++ );
	pData->hostStr = (char *)XMALLOC( i+1 );
	XMEMSET( pData->hostStr, 0, i+1 );
	i--;
	while( i >= 6 ) { pData->hostStr[i-6] = tmpPtr[i]; i--; }
      }

      /* grab the user-agent string, if it exists */
      if ( ( tmpPtr = strnstr( curPtr, "User-Agent: ", count ) ) != NULL ) {
	for( i = 12; tmpPtr[i] != '\r' & (tmpPtr-curPtr)+i < count; i++ );
	pData->userAgentStr = (char *)XMALLOC( i+1 );
	XMEMSET( pData->userAgentStr, 0, i+1 );
	i--;
	while( i >= 12 ) { pData->userAgentStr[i-12] = tmpPtr[i]; i--; }
      }

#ifdef DEBUG
      if ( config->debug >= 3 ) {
	/* XXX special user agent 'TESTING_YYYYMMDD_HHMM_PID_SEQ' */
	printf( "%s\n", fwLog );
	printf( "=====\n" );
      }
#endif
      
      for( i = 0; i < count; i++ ) {
	if ( curPtr[i] == '\r' && curPtr[i+1] == '\n' ) {
	  if ( config->debug >= 4 )
	    printf( "\n" );
	  i++;
	} else if ( isprint( curPtr[i] ) )
	  if ( config->debug >= 4 )
	    printf( "%c", curPtr[i] );
	  else
	    if ( config->debug >= 4 )
	      printf( "\n" );
      }
      if ( config->debug >= 4 )
	printf( "\n" );
      //hexDump( hdrOff, data + hdrOff, count );
      curPtr += i;
    } else
      curPtr++;
  }
  return( msgCount );
}

/****
 *
 * tcp libnids callback
 *
 ****/

void tcp_sniff_callback(struct tcp_stream *stream, void **not_needed) {
  struct half_stream *half;
  struct tm pkt_time;
  char tmpBuf[8192];
  char tmpSrcAddr[32];
  char tmpDstAddr[32];
  struct proxyData *tmpProxyData;

  /* bail if someone asked us to term */
  if ( quit ) {
    if ( config->mode = MODE_INTERACTIVE )
      fprintf( stderr, "Shutting down\n" );
    else
      syslog(nids_params.syslog_level, "Sutting down" );
    exit( EXIT_FAILURE );
  }

  switch ( stream->nids_state ) {
  case NIDS_JUST_EST:

    /* SYN */

    /* make sure this is a tcp session we care about */
    stream->client.collect++;
    stream->server.collect++;
    stream->user = (struct proxyData *)XMALLOC(sizeof(struct proxyData) );
    tmpProxyData = (struct proxyData *)stream->user;
    tmpProxyData->startTime = nids_last_pcap_header->ts.tv_sec;
    tmpProxyData->startUTime = nids_last_pcap_header->ts.tv_usec;

    break;

  case NIDS_TIMED_OUT:
  case NIDS_CLOSE:
  case NIDS_EXITING:
  case NIDS_RESET:

    /* RST, FIN, etc */

    if ( stream->user ) {
      /* save user defined data */
      tmpProxyData = (struct proxyData *)stream->user;
      tmpProxyData->endTime = nids_last_pcap_header->ts.tv_sec;
      tmpProxyData->endUTime = nids_last_pcap_header->ts.tv_usec;
      strcpy( tmpSrcAddr, inet_ntoa(*((struct in_addr *)&stream->addr.saddr)) );
      strcpy( tmpDstAddr, inet_ntoa(*((struct in_addr *)&stream->addr.daddr)) );

      snprintf( tmpBuf, sizeof( tmpBuf ), "%9ld.%03ld %6ld %s:%d TCP_%s/%03d %ld %s - DIRECT/%s:%d %s [%s]",
		tmpProxyData->startTime,
		tmpProxyData->startUTime/1000,
		((tmpProxyData->endTime - tmpProxyData->startTime)*1000)+((tmpProxyData->endUTime - tmpProxyData->startUTime)/1000),
		tmpSrcAddr,
		stream->addr.source,
		tmpProxyData->respStr != NULL ? "MISS" : "FAIL",
		tmpProxyData->respCode,
		tmpProxyData->clientBytes,
		tmpProxyData->reqStr != NULL ? tmpProxyData->reqStr : "FAIL No_request_found",
		tmpProxyData->hostStr != NULL ? tmpProxyData->hostStr : tmpDstAddr,
		stream->addr.dest,
		tmpProxyData->cTypeStr != NULL ? tmpProxyData->cTypeStr : "-",
		tmpProxyData->userAgentStr != NULL ? tmpProxyData->userAgentStr : "-"
		);
      if ( config->mode EQ MODE_INTERACTIVE )
	printf( "%s\n", tmpBuf );
      else
	syslog(nids_params.syslog_level, "%s", tmpBuf );

      /* cleanup the user stream buffer */
      if ( tmpProxyData->reqStr != NULL )
	XFREE( tmpProxyData->reqStr );
      if ( tmpProxyData->respStr != NULL )
	XFREE( tmpProxyData->respStr );
      if ( tmpProxyData->userAgentStr != NULL )
	XFREE( tmpProxyData->userAgentStr );
      if ( tmpProxyData->hostStr != NULL )
	XFREE( tmpProxyData->hostStr );
      if ( tmpProxyData->cTypeStr != NULL )
	XFREE( tmpProxyData->cTypeStr );
      XFREE( stream->user );
      stream->user = NULL;
    }

    break;

  case NIDS_DATA:

    if ( stream->user == NULL ) {
      /* no user defined data yet */
    } else {
      /* get user defined data */
    }

    /* convert packet time into something usable */
    localtime_r((const time_t*)&nids_last_pcap_header->ts.tv_sec, &pkt_time);
    tmpProxyData = (struct proxyData *)stream->user;

    if ( stream->client.count_new ) {
      /* data from client */
      half = &stream->client;
      tmpProxyData->clientBytes += half->count_new;
      strcpy( tmpSrcAddr, inet_ntoa(*((struct in_addr *)&stream->addr.daddr)) );
      strcpy( tmpDstAddr, inet_ntoa(*((struct in_addr *)&stream->addr.saddr)) );
      sprintf( tmpBuf, "%04d/%02d/%02d %02d:%02d:%02d.%06d %s:%d -> %s:%d", 
	       pkt_time.tm_year+1900,
	       pkt_time.tm_mon+1,
	       pkt_time.tm_mday,
	       pkt_time.tm_hour,
	       pkt_time.tm_min,
	       pkt_time.tm_sec,
	       (int)nids_last_pcap_header->ts.tv_usec,
	       tmpSrcAddr,
	       stream->addr.dest,
	       tmpDstAddr,
	       stream->addr.source
	       );
    } else {
      /* data from server */
      half = &stream->server;
      //tmpProxyData->clientBytes += half->count_new;
      strcpy( tmpSrcAddr, inet_ntoa(*((struct in_addr *)&stream->addr.saddr)) );
      strcpy( tmpDstAddr, inet_ntoa(*((struct in_addr *)&stream->addr.daddr)) );
      sprintf( tmpBuf, "%04d/%02d/%02d %02d:%02d:%02d.%06d %s:%d -> %s:%d", 
	       pkt_time.tm_year+1900,
	       pkt_time.tm_mon+1,
	       pkt_time.tm_mday,
	       pkt_time.tm_hour,
	       pkt_time.tm_min,
	       pkt_time.tm_sec,
	       (int)nids_last_pcap_header->ts.tv_usec,
	       tmpSrcAddr,
	       stream->addr.source,
	       tmpDstAddr,
	       stream->addr.dest
	       );
    }

    /* payload */

    /* tcp session that we are interested in */
    dissectHTTP( half->data, half->count_new, tmpBuf, tmpProxyData );

    nids_discard( stream, half->count_new );

    break;
  }
}
