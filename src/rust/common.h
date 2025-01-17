/****************************************************************************
 *
 * common.h - NRPE Common header file
 *
 * License: GPLv2
 * Copyright (c) 2006-2017 Nagios Enterprises
 *               1999-2006 Ethan Galstad (nagios@nagios.org)
 *
 * License Notice:
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 ****************************************************************************/

#include "config.h"

#define SSL_TYPE_openssl

#ifdef HAVE_SSL
#ifdef OPENSSL_V3
# define OPENSSL_API_COMPAT 10002
# define OPENSSL_NO_DEPRECATED
#endif
#include <openssl/ssl.h>
# ifdef SSL_TYPE_openssl
#  include <openssl/err.h>
#  include <openssl/rand.h>
#  include <openssl/engine.h>
# endif
#endif

#define PROGRAM_VERSION "4.1.0"
#define MODIFICATION_DATE "2022-07-18"

#define OK							0
#define ERROR						-1

#define TRUE						1
#define FALSE						0

#define STATE_UNKNOWN				3		/* service state return codes */
#define	STATE_CRITICAL				2
#define STATE_WARNING				1
#define STATE_OK					0


#define DEFAULT_SOCKET_TIMEOUT		10		/* timeout after 10 seconds */
#define DEFAULT_CONNECTION_TIMEOUT	300		/* timeout if daemon is waiting for connection more than this time */

#define MAX_INPUT_BUFFER			2048	/* max size of most buffers we use */
#define MAX_FILENAME_LENGTH			256
#define MAX_HOST_ADDRESS_LENGTH		256		/* max size of a host address */
#define MAX_COMMAND_ARGUMENTS		16

#define NRPE_HELLO_COMMAND			"_NRPE_CHECK"

/**************** PACKET STRUCTURE DEFINITION **********/

#define QUERY_PACKET				1		/* id code for a packet containing a query */
#define	RESPONSE_PACKET				2		/* id code for a packet containing a response */

/* v4 takes struct padding into account, so the buffer "takes" 4 bytes
 * v3 removes the 1 byte that "should" be allocated to buffer.
 */
#define NRPE_V4_PACKET_SIZE_OFFSET  4
#define NRPE_V3_PACKET_SIZE_OFFSET  1

/* packet version identifiers */
#define NRPE_PACKET_VERSION_4		4       /* Same as version 3, but accounts for struct padding in network code */
#define NRPE_PACKET_VERSION_3		3		/* Allows for variable-length buffer */
#define NRPE_PACKET_VERSION_2		2
#define NRPE_PACKET_VERSION_1		1		/* older packet version identifiers (no longer supported) */

#define MAX_PACKETBUFFER_LENGTH		1024	/* amount of data to send in one query/response vor version 2 */

#define NRPE_DEFAULT_PACKET_VERSION NRPE_PACKET_VERSION_4

typedef struct _v2_packet {
	int16_t		packet_version;
	int16_t		packet_type;
	u_int32_t	crc32_value;
	int16_t		result_code;
	char		buffer[MAX_PACKETBUFFER_LENGTH];
} v2_packet;
typedef struct _v3_packet {
	int16_t		packet_version;
	int16_t		packet_type;
	u_int32_t	crc32_value;
	int16_t		result_code;
	int16_t		alignment;
	int32_t		buffer_length;
	char		buffer[1];
} v3_packet;

typedef v3_packet v4_packet;

/**************** OPERATING SYSTEM SPECIFIC DEFINITIONS **********/
#if defined(__sun) || defined(__hpux)

# ifndef LOG_AUTHPRIV
#  define LOG_AUTHPRIV LOG_AUTH
# endif
# ifndef LOG_FTP
#  define LOG_FTP LOG_DAEMON
# endif
#elif defined(_AIX)
# include <sys/select.h>
# ifndef LOG_FTP
#  define LOG_FTP LOG_DAEMON
# endif
#endif
