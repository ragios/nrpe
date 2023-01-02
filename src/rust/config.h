/* include/config.h.  Generated from config.h.in by configure.  */
/****************************************************************************
 *
 * config.h - NRPE Configuration header file
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

#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdio.h>
#include <stdlib.h>


/* Default port for NRPE daemon */
#define DEFAULT_SERVER_PORT 5666

#define NRPE_LOG_FACILITY "daemon"
/* NRPE syslog facility */
#define NRPE_LOG_FACILITY "daemon"

/* Enable command-line arguments */
/* #undef ENABLE_COMMAND_ARGUMENTS */

/* Enable bash command substitution */
/* #undef ENABLE_BASH_COMMAND_SUBSTITUTION */

/* type to use in place of socklen_t if not defined */
/* #undef socklen_t */

/* Define to 1 if you have the `getopt_long' function. */
#define HAVE_GETOPT_LONG 1

/* Have the TCP wrappers library */
/* #undef HAVE_LIBWRAP */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the `strstr' function. */
#define HAVE_STRSTR 1

/* Define to 1 if you have the `strtoul' function. */
#define HAVE_STRTOUL 1

/* Define to 1 if you have the `strtok_r' function. */
#define HAVE_STRTOK_R 1

/* Define to 1 if you have the `initgroups' function. */
#define HAVE_INITGROUPS 1

/* Define to 1 if you have the `closesocket' function. */
/* #undef HAVE_CLOSESOCKET */

/* Define to 1 if you have the `sigaction' function. */
#define HAVE_SIGACTION 1

/* Define to 1 if you have the `scandir' function. */
#define HAVE_SCANDIR 1

/* Set to 1 if you have rfc931_timeout */
/* #undef HAVE_RFC931_TIMEOUT */

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `short', as computed by sizeof. */
#define SIZEOF_SHORT 2

/* The size of `long', as computed by sizeof. */
#define SIZEOF_LONG 8

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Set to 1 to use SSL DH */
#define USE_SSL_DH 1

/* stupid stuff for u_int32_t */
/* #undef U_INT32_T_IS_USHORT */
/* #undef U_INT32_T_IS_UINT */
/* #undef U_INT32_T_IS_ULONG */
/* #undef U_INT32_T_IS_UINT32_T */

#ifdef U_INT32_T_IS_USHORT
typedef unsigned short u_int32_t;
#endif
#ifdef U_INT32_T_IS_ULONG
typedef unsigned long u_int32_t;
#endif
#ifdef U_INT32_T_IS_UINT
typedef unsigned int u_int32_t;
#endif
#ifdef U_INT32_T_IS_UINT32_t
typedef uint32_t u_int32_t;
#endif

/* stupid stuff for int32_t */
/* #undef INT32_T_IS_SHORT */
/* #undef INT32_T_IS_INT */
/* #undef INT32_T_IS_LONG */

#ifdef INT32_T_IS_USHORT
typedef short int32_t;
#endif
#ifdef INT32_T_IS_ULONG
typedef long int32_t;
#endif
#ifdef INT32_T_IS_UINT
typedef int int32_t;
#endif


/***** ASPRINTF() AND FRIENDS *****/

/* Whether vsnprintf() is available */
/* #undef HAVE_VSNPRINTF */
/* Whether snprintf() is available */
/* #undef HAVE_SNPRINTF */
/* Whether aprintf() is available */
/* #undef HAVE_ASPRINTF */
/* Whether vaprintf() is available */
/* #undef HAVE_VASPRINTF */
/* Define if system has C99 compatible vsnprintf */
#define HAVE_C99_VSNPRINTF 1

/* Whether va_copy() is available */
#define HAVE_VA_COPY 1

/* Whether __va_copy() is available */
/* #undef HAVE___VA_COPY */


/* Socket Size Type */
#define SOCKET_SIZE_TYPE size_t

/* Define to the type of elements in the array set by `getgroups'. Usually
   this is either `int' or `gid_t'. */
#define GETGROUPS_T gid_t

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Define to 1 if the system has the type `struct sockaddr_storage'. */
#define HAVE_STRUCT_SOCKADDR_STORAGE 1

/* Use seteuid() or setresuid() depending on the platform */
#define SETEUID(id) seteuid(id)

/* Set to 1 if we are on Solaris 10 */
/* #undef SOLARIS_10 */

/* Define to 1 if you have the <getopt.h> header file. */
#define HAVE_GETOPT_H 1
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1
#ifdef HAVE_STRING_H
#include <string.h>
#endif

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

/* Define to 1 if you have the <sys/wait.h> header file. */
#define HAVE_SYS_WAIT_H 1
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif


/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

/* Define to 1 if you have the <socket.h> header file. */
/* #undef HAVE_SOCKET_H */
#ifdef HAVE_SOCKET_H
#include <socket.h>
#endif

/* Define to 1 if you have the <tcpd.h> header file. */
/* #undef HAVE_TCPD_H */
#ifdef HAVE_TCPD_H
#include <tcpd.h>
#endif

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

/* Define to 1 if you have the <ctype.h> header file. */
#define HAVE_CTYPE_H 1
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1
#ifdef HAVE_GRP_H
#include <grp.h>
#endif

/* Define to 1 if you have the <dirent.h> header file. */
#define HAVE_DIRENT_H 1
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

/* Have SSL support */
#define HAVE_SSL 1
/* #undef OPENSSL_V3 */

/* Have the krb5.h header file */
#define HAVE_KRB5_H 1
#ifdef HAVE_KRB5_H
#include <krb5.h>
#endif

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#endif

/* Define to 1 if you have the <paths.h> header file. */
#define HAVE_PATHS_H 1

/* Define to 1 if you have the <sys/resource.h> header file. */
#define HAVE_SYS_RESOURCE_H 1

#endif
