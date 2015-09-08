/****
 *
 * Passive Proxy Logging Daemon - Main
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
 *.
 ****/

#include "main.h"

/****
 *
 * local variables
 *
 ****/

/****
 *
 * global variables
 *
 ****/

PUBLIC int quit = FALSE;
PUBLIC int reload = FALSE;
PUBLIC Config_t *config = NULL;

/****
 *
 * external variables
 *
 ****/

extern int errno;
extern char **environ;

/* libnids externs */
extern struct nids_prm nids_params;
extern struct pcap_pkthdr *nids_last_pcap_header;

/****
 *
 * main function
 *
 ****/

int main(int argc, char *argv[]) {
  PRIVATE int pid = 0, fds = 0;
  FILE *inFile = NULL, *outFile = NULL;
  char inBuf[8192];
  char tmpNumber[32];
  char tmpBpf[8192];
  PRIVATE int c = 0, i, ret;
  PRIVATE struct passwd *pwd_ent;
  PRIVATE struct group *grp_ent;
  char *tmp_ptr = NULL;
  char *pid_file = NULL;
  char *home_dir = NULL;
  char *chroot_dir = NULL;
  char *port_list = NULL;
  char *user = NULL;
  char *group = NULL;
  int curPos, nOff, done;
  char *curBpfPtr;

#ifndef DEBUG
  struct rlimit rlim;

  rlim.rlim_cur = rlim.rlim_max = 0;
  setrlimit( RLIMIT_CORE, &rlim );
#endif

  /* setup config */
  config = ( Config_t * )XMALLOC( sizeof( Config_t ) );
  XMEMSET( config, 0, sizeof( Config_t ) );

  /* force mode to forground */
  config->mode = MODE_INTERACTIVE;

  /* store current pid */
  config->cur_pid = getpid();

  /* store current user record */
  config->starting_uid = getuid();
  pwd_ent = getpwuid( config->starting_uid );
  if ( pwd_ent EQ NULL ) {
    fprintf( stderr, "Unable to get user's record\n" );
    endpwent();
    exit( EXIT_FAILURE );
  }
  if ( ( tmp_ptr = strdup( pwd_ent->pw_dir ) ) EQ NULL ) {
    fprintf( stderr, "Unable to dup home dir\n" );
    endpwent();
    exit( EXIT_FAILURE );
  }
  /* set home dir */
  home_dir = ( char * )XMALLOC( MAXPATHLEN + 1 );
  strncpy( home_dir, pwd_ent->pw_dir, MAXPATHLEN );
  endpwent();

  /* get real uid and gid in prep for priv drop */
  config->gid = getgid();
  config->uid = getuid();

  while (1) {
    int this_option_optind = optind ? optind : 1;
#ifdef HAVE_GETOPT_LONG
    int option_index = 0;
    static struct option long_options[] = {
      {"version", no_argument, 0, 'v' },
      {"debug", required_argument, 0, 'd' },
      {"help", no_argument, 0, 'h' },
      {"int", required_argument, 0, 'i' },
      {"read", required_argument, 0, 'r' },
      {0, no_argument, 0, 0}
    };
    c = getopt_long(argc, argv, "c:Dd:g:hi:P:p:r:u:v", long_options, &option_index);
#else
    c = getopt( argc, argv, "c:Dd:g:hi:P:p:r:u:v" );
#endif

    if (c EQ -1)
      break;

    switch (c) {

    case 'c':
      /* chroot the process into the specific dir */
      chroot_dir = ( char * )XMALLOC( MAXPATHLEN + 1 );
      XMEMSET( chroot_dir, 0, MAXPATHLEN + 1 );
      XSTRNCPY( chroot_dir, optarg, MAXPATHLEN );

      break;

    case 'D':
      /* run in the background */
      if ( config->infile EQ NULL )
	config->mode = MODE_DAEMON;
      break;

    case 'd':
      /* show debig info */
      config->debug = atoi( optarg );
      break;

    case 'g':

      /* set gid to run as */
      group = ( char * )XMALLOC( (sizeof(char)*MAX_GROUP_LEN)+1 );
      XMEMSET( group, 0, (sizeof(char)*MAX_GROUP_LEN)+1 );
      XSTRNCPY( group, optarg, MAX_GROUP_LEN );
      if ( ( grp_ent = getgrnam( group ) ) EQ NULL ) {
	fprintf( stderr, "ERR - Unknown group [%s]\n", group );
	endgrent();
	XFREE( group );
	cleanup();
	exit( EXIT_FAILURE );
      }
      config->gid = grp_ent->gr_gid;
      endgrent();
      XFREE( group );
    
      break;

    case 'h':
      /* show help info */
      print_help();
      return( EXIT_SUCCESS );

    case 'i':
      /* set interface to monitor */
      config->iface = ( char * )XMALLOC( ( sizeof( char ) * MAXPATHLEN ) + 1 );
      XMEMSET( config->iface, 0, ( sizeof( char ) * MAXPATHLEN ) + 1 );
      XSTRNCPY( config->iface, optarg, MAXPATHLEN );
      break;

    case 'P':
      /* define the location of the pid file used for rotating logs, etc */
      pid_file = ( char * )XMALLOC( MAXPATHLEN + 1 );
      XMEMSET( pid_file, 0, MAXPATHLEN + 1 );
      XSTRNCPY( pid_file, optarg, MAXPATHLEN );

      break;

    case 'p':
      /* set ports to listen to, defaults to 80 */
      port_list = ( char * )XMALLOC( MAXPATHLEN + 1 );
      XMEMSET( port_list, 0, MAXPATHLEN + 1 );
      XSTRNCPY( port_list, optarg, MAXPATHLEN );
      break;

    case 'r':
      /* read packets from file */
      config->mode = MODE_INTERACTIVE;
      config->infile = ( char * )XMALLOC( MAXPATHLEN + 1 );
      XMEMSET( config->infile, 0, MAXPATHLEN + 1 );
      XSTRNCPY( config->infile, optarg, MAXPATHLEN );
      break;

    case 'u':

      /* set user to run as */
      user = ( char * )XMALLOC( (sizeof(char)*MAX_USER_LEN)+1 );
      XMEMSET( user, 0, (sizeof(char)*MAX_USER_LEN)+1 );
      XSTRNCPY( user, optarg, MAX_USER_LEN );
      if ( ( pwd_ent = getpwnam( user ) ) EQ NULL ) {
	fprintf( stderr, "ERR - Unknown user [%s]\n", user );
	endpwent();
	XFREE( user );
	cleanup();
	exit( EXIT_FAILURE );
      }
      config->uid = pwd_ent->pw_uid;
      endpwent();
      XFREE( user );

      break;

    case 'v':
      /* show the version */
      print_version();
      return( EXIT_SUCCESS );

    default:
      fprintf( stderr, "Unknown option code [0%o]\n", c);
    }
  }

  /* make sure key variables are defined or set defaults */

  if ( pid_file EQ NULL ) {
    pid_file = ( char * )XMALLOC( strlen( PID_FILE ) + 1 );
    XSTRNCPY( pid_file, PID_FILE, strlen( PID_FILE ) );
  }

  if ( port_list EQ NULL ) {
    port_list = ( char * )XMALLOC( strlen( PORT_LIST ) + 1 );
    XSTRNCPY( port_list, PORT_LIST, strlen( PORT_LIST ) );
  }
  /* convert port list to bpf */
  /* tcp port 80 or tcp port 443 */
  XMEMSET( tmpBpf, 0, sizeof( tmpBpf ) );
  curPos = nOff = done = 0;
  curBpfPtr = tmpBpf;
  while( curPos <= strlen( port_list ) & ! done ) {
    if ( port_list[curPos] EQ 0 ) {
      /* done */
      if ( nOff > 0 ) {
	sprintf( curBpfPtr, "tcp port %d", atoi( tmpNumber ) );
	curBpfPtr += strlen( curBpfPtr );
      }
      done = TRUE;
    } else if ( isdigit( port_list[curPos] ) ) {
      /* add char to digit buffer */
      if ( nOff >= 5 ) { /* port too big */
	fprintf( stderr, "ERR - Valid ports range from 0-65535\n" );
	cleanup();
	exit( EXIT_FAILURE );
      }
      tmpNumber[nOff++] = port_list[curPos++];
      tmpNumber[nOff] = 0;
    } else if ( port_list[curPos] EQ ',' ) {
      /* process digit buffer */
      if ( nOff > 0 ) {
	sprintf( curBpfPtr, "tcp port %d or ", atoi( tmpNumber ) );
	curBpfPtr += strlen( curBpfPtr );
	nOff = 0;
	curPos++;
      } else {
	fprintf( stderr, "ERR - Invalid port list format. Example [%s]\n", PORT_LIST );
	cleanup();
	exit( EXIT_FAILURE );
      }
    } else {
      /* unrecognized character */
      fprintf( stderr, "ERR - Unvalid character in port list\n" );
      cleanup();
      exit( EXIT_FAILURE );
    }
  }

  /****
   *
   * become a daemon
   *
   ****/

  /* if not interactive, then become a daemon */
  if ( config->mode != MODE_INTERACTIVE ) {
    /* let everyone know we are running */
    fprintf( stderr, "%s v%s [%s - %s] starting in daemon mode\n", PROGNAME, VERSION, __DATE__, __TIME__ );

    /* check if we are already in the background */
    if ( getppid() EQ 1 ) {
      /* already owned by init */
    } else {
      /* ignore terminal signals */
      signal( SIGTTOU, SIG_IGN );
      signal( SIGTTIN, SIG_IGN );
      signal( SIGTSTP, SIG_IGN );

      /* first fork */
      if ( ( pid = fork() ) < 0 ) {
        /* that didn't work, bail */
        fprintf( stderr, "Unable to fork, forker must be broken\n" );
        exit( EXIT_FAILURE );
      } else if ( pid > 0 ) {
        /* this is the parent, quit */
        exit( EXIT_SUCCESS );
      }

      /* this is the first child, confused? */

      /* set process group leader AKA: I AM THE LEADER */
      if ( setpgid( 0, 0 ) != 0 ) {
        fprintf( stderr, "Unable to become the process group leader\n" );
        exit( EXIT_FAILURE );
      }

      /* ignore hup */
      signal( SIGHUP, SIG_IGN );

      /* second fork */
      if ( ( pid = fork() ) < 0 ) {
        /* that didn't work, bail */
        fprintf( stderr, "Unable to fork, forker must be broken\n" );
        exit( EXIT_FAILURE );
      } else if ( pid > 0 ) {
        /* this is the first child, quit */
        exit( EXIT_SUCCESS );
      }

      /* this is the second child, really confused? */

      /* move to '/' */
      if ( chdir( "/" ) EQ FAILED ) {
          fprintf( stderr, "Unable to set CWD\n" );
          exit ( EXIT_FAILURE );
      }

      /* close all open files */
      if ( ( fds = getdtablesize() ) EQ FAILED ) fds = MAX_FILE_DESC;
      for ( i = 0; i < fds; i++ ) close( i );

      /* reopen stdin, stdout and stderr to the null device */

      /* reset umask */
      umask( 0027 );

      /* stir randoms if used */

      /* done forking off */

      /* enable syslog */
      openlog( PROGNAME, LOG_CONS & LOG_PID, LOG_LOCAL0 );
    }
  } else {
    show_info();
    display( LOG_INFO, "Running in interactive mode" );
  }

  if ( config->mode EQ MODE_DAEMON ) {
    /* write pid to file */
#ifdef DEBUG
    display( LOG_DEBUG, "PID: %s", pid_file );
#endif
    if ( create_pid_file( pid_file ) EQ FAILED ) {
      display( LOG_ERR, "Creation of pid file failed" );
      cleanup();
      exit( EXIT_FAILURE );
    }
  }

  /* check dirs and files for danger */

  /* figure our where our default dir will be */
  if ( chroot_dir EQ NULL ) {
    /* if chroot not defined, use user's home dir */
#ifdef DEBUG
    display( LOG_DEBUG, "CWD: %s", home_dir );
#endif
    /* move into home dir */
    if ( chdir( home_dir ) EQ FAILED ) {
        fprintf( stderr, "Unable to set CWD to [%s]\n", home_dir );
        exit ( EXIT_FAILURE );
    }
  } else {
    /* chroot this puppy */
#ifdef DEBUG
    if ( config->debug >= 3 ) {
      display( LOG_DEBUG, "chroot to [%s]", chroot_dir );
    }
#endif
    if ( chroot( chroot_dir ) != 0 ) {
      display( LOG_ERR, "Can't chroot to [%s]", chroot_dir );
      cleanup();
      exit( EXIT_FAILURE );
    }
    if ( chdir( "/" ) EQ FAILED ) {
        fprintf( stderr, "Unable to set CWD\n" );
        exit ( EXIT_FAILURE );
    }
  }

  /* setup gracefull shutdown */
  signal( SIGINT, sigint_handler );
  signal( SIGTERM, sigterm_handler );
  signal( SIGFPE, sigfpe_handler );
  signal( SIGBUS, sigbus_handler );
  signal( SIGILL, sigill_handler );
  signal( SIGHUP, sighup_handler );
  signal( SIGSEGV, sigsegv_handler );

  /* setup current time updater */
  signal( SIGALRM, ctime_prog );
  alarm( 5 );

  if ( time( &config->current_time ) EQ -1 ) {
    display( LOG_ERR, "Unable to get current time" );

    /* cleanup buffers */
    cleanup();
    return EXIT_FAILURE;
  }

  /* initialize program wide config options */
  config->hostname = (char *)XMALLOC( MAXHOSTNAMELEN+1 );

  /* get processor hostname */
  if ( gethostname( config->hostname, MAXHOSTNAMELEN ) != 0 ) {
    display( LOG_ERR, "Unable to get hostname" );
    strcpy( config->hostname, "unknown" );
  }

  /* get current pid after forking */
  config->cur_pid = getpid();

  /* setup current time updater */
  signal( SIGALRM, ctime_prog );
  alarm( 60 );

  /*
   * get to work
   */

  if ( config->infile EQ NULL ) {
    if ( config->iface EQ NULL ) {
      /* monitor the first available interface */
      /* XXX add code to pick an interface to monitor using pcap */
      fprintf( stderr, "ERR - You must specify a pcap file to read or an interface to monitor.\n" );
      return(EXIT_FAILURE);
    } else {
      /* monitor the defined interface */
      nids_params.device = config->iface;
    }
  } else {
    /* read packet from infile */
    nids_params.filename = config->infile;
  }

  /* common nids settings */
  nids_params.syslog = null_syslog;
  nids_params.scan_num_hosts = 0;
  nids_params.pcap_filter = tmpBpf;

  if (!nids_init()) {
    fprintf( stderr, "%s\n", nids_errbuf );
    return(EXIT_FAILURE);
  }

  struct nids_chksum_ctl ctl;
  bzero(&ctl, sizeof(ctl));
  ctl.action = NIDS_DONT_CHKSUM;
  nids_register_chksum_ctl(&ctl, 1);
  
  nids_register_tcp( tcp_sniff_callback );

  /* get rid of elivated privs if we can, we don't need them anymore */
  drop_privileges();

  nids_run();

  /*
   * finished with the work
   */

  cleanup();

  return( EXIT_SUCCESS );
}

/****
 *
 * display prog info
 *
 ****/

void show_info( void ) {
  fprintf( stderr, "%s v%s [%s - %s]\n", PROGNAME, VERSION, __DATE__, __TIME__ );
  fprintf( stderr, "By: Ron Dilley\n" );
  fprintf( stderr, "\n" );
  fprintf( stderr, "%s comes with ABSOLUTELY NO WARRANTY.\n", PROGNAME );
  fprintf( stderr, "This is free software, and you are welcome\n" );
  fprintf( stderr, "to redistribute it under certain conditions;\n" );
  fprintf( stderr, "See the GNU General Public License for details.\n" );
  fprintf( stderr, "\n" );
}

/*****
 *
 * display version info
 *
 *****/

PRIVATE void print_version( void ) {
  printf( "%s v%s [%s - %s]\n", PROGNAME, VERSION, __DATE__, __TIME__ );
}

/*****
 *
 * print help info
 *
 *****/

PRIVATE void print_help( void ) {
  print_version();

  fprintf( stderr, "\n" );
  fprintf( stderr, "syntax: %s [options] -r {fname}|-i {iface}\n", PACKAGE );

#ifdef HAVE_GETOPT_LONG
  fprintf( stderr, " -c|--chroot {dir}     chroot to {dir}\n" );
  fprintf( stderr, " -D|--daemon           run as a daemon, output goes to syslog\n" );
  fprintf( stderr, " -d|--debug (0-9)      enable debugging info\n" );
  fprintf( stderr, " -g|--group {group}    run as a different group\n" );
  fprintf( stderr, " -h|--help             this info\n" );
  fprintf( stderr, " -i|--int {iface}      specify interface to read from\n" );
  fprintf( stderr, " -P|--pid {fname}      specify pid file (default: %s)\n", PID_FILE );
  fprintf( stderr, " -p|--ports {ports}    comma separated list of ports to monitor (default: %s)\n", PORT_LIST );
  fprintf( stderr, " -r|--read {fname}     read packets from pcap file\n" );
  fprintf( stderr, " -u|--user {name}      run as a different user\n" );
  fprintf( stderr, " -v|--version          display version information\n" );
#else
  fprintf( stderr, " -c {dir}      chroot to {dir}\n" );
  fprintf( stderr, " -D            run as a daemon, output goes to syslog\n" );
  fprintf( stderr, " -d (0-9)      enable debugging info\n" );
  fprintf( stderr, " -g {group}    run as a different group\n" );
  fprintf( stderr, " -h            this info\n" );
  fprintf( stderr, " -i {iface}    specify interface to read from\n" );
  fprintf( stderr, " -P {fname}    specify pid file (default: %s)\n", PID_FILE );
  fprintf( stderr, " -p {ports}    comma separated list of ports to monitor (default: %s)\n", PORT_LIST );
  fprintf( stderr, " -r {fname}    read packets from pcap file\n" );
  fprintf( stderr. " -u {name}     run as a different user\n" );
  fprintf( stderr, " -v            display version information\n" );
#endif

  fprintf( stderr, "\n" );
}

/****
 *
 * cleanup
 *
 ****/

PRIVATE void cleanup( void ) {
  if ( config->hostname != NULL )
    XFREE( config->hostname );
  if ( config->iface != NULL )
    XFREE( config->iface );
  if ( config->infile != NULL )
    XFREE( config->infile );
  if ( config->ports != NULL )
    XFREE( config->ports );
#ifdef MEM_DEBUG
  XFREE_ALL();
#else
  XFREE( config );
#endif
}

/****
 *
 * SIGINT handler
 *
 ****/
 
void sigint_handler( int signo ) {
  signal( signo, SIG_IGN );

  /* do a calm shutdown as time and pcap_loop permit */
  quit = TRUE;
  signal( signo, sigint_handler );
}

/****
 *
 * SIGTERM handler
 *
 ****/
 
void sigterm_handler( int signo ) {
  signal( signo, SIG_IGN );

  /* do a calm shutdown as time and pcap_loop permit */
  quit = TRUE;
  signal( signo, sigterm_handler );
}

/****
 *
 * SIGHUP handler
 *
 ****/
 
void sighup_handler( int signo ) {
  signal( signo, SIG_IGN );

  /* time to rotate logs and check the config */
  reload = TRUE;
  signal( SIGHUP, sighup_handler );
}

/****
 *
 * SIGSEGV handler
 *
 ****/
 
void sigsegv_handler( int signo ) {
  signal( signo, SIG_IGN );

  fprintf( stderr, "Caught a sig%d, shutting down fast\n", signo );
  /* pcmcia nics seem to do strange things sometimes if pcap does not close clean */
#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
  /* core out */
  abort();
}

/****
 *
 * SIGBUS handler
 *
 ****/
 
void sigbus_handler( int signo ) {
  signal( signo, SIG_IGN );
  
  fprintf( stderr, "Caught a sig%d, shutting down fast\n", signo );
  /* pcmcia nics seem to do strange things sometimes if pcap does not close clean */
#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
  /* core out */
  abort();
}

/****
 *
 * SIGILL handler
 *
 ****/
 
void sigill_handler ( int signo ) {
  signal( signo, SIG_IGN );

  fprintf( stderr, "Caught a sig%d, shutting down fast\n", signo );
  /* pcmcia nics seem to do strange things sometimes if pcap does not close clean */
#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
  /* core out */
  abort();
}

/****
 *
 * SIGFPE handler
 *
 ****/
 
void sigfpe_handler( int signo ) {
  signal( signo, SIG_IGN );

  fprintf( stderr, "Caught a sig%d, shutting down fast\n", signo );
  /* pcmcia nics seem to do strange things sometimes if pcap does not close clean */
#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
  /* core out */
  abort();
}

/*****
 *
 * interrupt handler (current time)
 *
 *****/

void ctime_prog( int signo ) {
  time_t ret;

  /* disable SIGALRM */
  signal( SIGALRM, SIG_IGN );
  /* update current time */

  /* reset SIGALRM */
  signal( SIGALRM, ctime_prog );
  /* reset alarm */
  alarm( 60 );
}

/****
 *
 * drop privs
 *
 ****/

void drop_privileges( void ) {
  gid_t oldgid = getegid();
  uid_t olduid = geteuid();

#ifdef DEBUG
  if ( config->debug >= 5 ) {
    display( LOG_DEBUG, "dropping privs - uid: %i gid: %i euid: %i egid: %i", config->uid, config->gid, olduid, oldgid );
  }
#endif

  if ( !olduid ) setgroups( 1, &config->gid );

  if ( config->gid != oldgid ) {
    if ( setgid( config->gid ) EQ FAILED ) abort();
  }

  if ( config->uid != olduid ) {
    if ( setuid( config->uid ) EQ FAILED ) abort();
  }

#ifdef DEBUG
  if ( config->debug >= 4 ) {
    display( LOG_DEBUG, "dropped privs - uid: %i gid: %i euid: %i egid: %i", config->uid, config->gid, geteuid(), getegid() );
  }
#endif

  /* verify things are good */
  if ( config->gid != oldgid && ( setegid( oldgid ) != FAILED || getegid() != config->gid ) ) abort();
  if ( config->uid != olduid && ( seteuid( olduid ) != FAILED || geteuid() != config->uid ) ) abort();
}
