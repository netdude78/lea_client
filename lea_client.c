/***************************************************************************
 *                                                                         *
 *  LEA Client                                                             * 
 *  Copyright (C) 2012                                                     *
 *  Dave Stoll dave.stoll@gmail.com                                        *
 *                                                                         *
 *  This program is free software: you can redistribute it and/or modify   *
 *  it under the terms of the GNU General Public License as published by   *
 *  the Free Software Foundation, either version 3 of the License, or      *
 *  (at your option) any later version.                                    *
 *                                                                         *
 *  This program is distributed in the hope that it will be useful,        *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *  GNU General Public License for more details.                           *
 *                                                                         *
 *  You should have received a copy of the GNU General Public License      *
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.  *
 *                                                                         *
 *  This program based upon example code provided by Checkpont.            *
 *                                                                         *
 ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include "opsec/lea.h"
#include "opsec/lea_filter.h"
#include "opsec/opsec.h"
#include <netinet/in.h>
#include <arpa/inet.h>


void                 CleanUpEnvironment();
int                  LeaStartHandler(OpsecSession *);
int                  LeaEndHandler(OpsecSession *);
int                  LeaRecordHandler(OpsecSession *, lea_record *, int []);
int                  LeaDictionaryHandler(OpsecSession *, int, LEA_VT, int);
int                  LeaEofHandler(OpsecSession *);
int                  LeaSwitchHandler(OpsecSession *);
int                  LeaSessionEstablished(OpsecSession *);
void                 quitApp(int);
int                  sendTcp(int, char *, int *);
int                  sendUdp(int, char *, int *);
void                 *get_in_addr(struct sockaddr *);
void                 printUsage(char *);
void                 establishTcpSession(char *, int);
void                 establishUdpSession(char *, int);
void                 exitApp(int);

 
#define DATEFORMAT "%b %e %H:%M:%S"
 
OpsecEntity    *pClient  = NULL;
OpsecEntity    *pServer  = NULL;
OpsecSession   *pSession = NULL;
OpsecEnv       *pEnv     = NULL;
int sd, resolve_names = 1, useTcp = 1, useSyslogFormat = 0, syslog_facility, syslog_severity;
struct sockaddr_in serveraddr;
char pidfile[1024];

void printUsage(char *progname) {
    fprintf(stderr, "%s -c CONFIGFILE [-i process_name]\n", progname);
}


/*

    Main
    
    This method will initialize the environment, validate command line and config file
    directives and start the OPSEC loop to process log events.
    
    Most program log events are sent to the system's syslog daemon for processing
    
*/
int main(int argc, char *argv[]) {
    char *configfile = NULL, *progname = "lea_client";
    char *server = NULL, *log_file = NULL, *transport_mode = NULL;
    int online_mode, serverport;
    
    // before we fork, check that we have the right arguments.
    if (argc < 3) {
        fprintf(stderr, "Missing arguments.\n");
        printUsage(argv[0]);
        exitApp(1);
    }
    
    // Fork to new process
    int z;
    z=fork();
	if (z<0) {
	    fprintf(stderr, "Error, unable to fork.\n");
	    exit(1); /* fork error */
	}
	if (z>0)
	    exit(0); /* parent exits */
	/* child (daemon) continues */	

    int pid = getpid();    	

    // process command line args
    // -c must come first
    if (strcmp("-c", argv[1]) != 0) {
        fprintf(stderr, "First program argument must be -c\n");
        printUsage(argv[0]);
        
        exitApp(1);
    }
    
    // check to make sure config file exists
    FILE *file;
    if ((file = fopen(argv[2], "r")) != NULL) {
        configfile = argv[2];
        fclose(file);
    } else {
        fprintf(stderr, "ERROR: Can not open config file: %s for reading.\n", argv[2]);
        exitApp(1);
    }

    /* check for optoinal -i arg */
    if (argc > 3) {
        if(strcmp("-i", argv[3]) != 0) {
            fprintf(stderr, "Invalid option: %s\n", argv[3]);
            printUsage(argv[0]);
            exitApp(1);
        } else if (argc > 4) {
            if (strlen(argv[4]) > 0) {
                if(strlen(argv[4]) < 1019) {
                    progname = argv[4]; 
                } else {
                    fprintf(stderr, "ERROR: instance name longer than 1019 characters.\n");
                    exitApp(1);
                }
                 
            } else {
                fprintf(stderr, "Invalid argument.\n");
                printUsage(argv[0]);
                exitApp(1);
            }
        } else {
            fprintf(stderr, "Invalid argument.\n");
            printUsage(argv[0]);
            exitApp(1);
        }
    }
    
    // write pid file.
    sprintf(pidfile, "%s.pid", progname);
    if(( file = fopen(pidfile, "w")) != NULL) {
        fprintf(file, "%d\n", pid);
        fclose(file);
    } else {
        fprintf(stderr, "Unable to wreate PID file: %s\n", pidfile);
        exitApp(1);
    }

    printf("\nForking to background process.\n");
    printf("Use `kill %d` to end program\n", pid);
    printf("Log messages are written to syslog\n");

    openlog(progname, LOG_PID,LOG_DAEMON);
	syslog(LOG_INFO, "lea_client starting.");
    
    /* Register handlers to quit app when called. */
    signal (SIGTERM, quitApp);
    signal (SIGQUIT, quitApp);
    signal (SIGINT, quitApp);
    signal (SIGHUP, quitApp);

    if ((pEnv = opsec_init (OPSEC_CONF_FILE, configfile,
		        OPSEC_EOL)) == NULL) {
	    syslog(LOG_ALERT, "ERROR: unable to create environment (%s)",
		opsec_errno_str (opsec_errno));
	    CleanUpEnvironment();
	    exitApp(1);
	}

    // Get config info from the config file
    if ((server = opsec_get_conf(pEnv, "destination_server", NULL)) == NULL) {
        syslog(LOG_ALERT, "destination_server not set in config file.");
        fprintf(stderr, "Error.  See log for details.\n");
        exitApp(1);
    } else
        syslog(LOG_INFO, "Destination server: %s", server);
    
    if ((log_file = opsec_get_conf(pEnv, "log_filename", NULL)) == NULL) {
        syslog(LOG_ALERT, "log_filename not set in config file.");
        fprintf(stderr, "Error.  See log for details.\n");
        exitApp(1);
    } else
        syslog(LOG_INFO, "Checkpoint log name: %s", log_file);
    
    if ((transport_mode = opsec_get_conf(pEnv, "transport_mode", NULL)) == NULL) {
        syslog(LOG_ALERT, "transport_mode not set in config file.");
        fprintf(stderr, "Error.  See log for details.\n");
        exitApp(1);
    } 
    
    if (((strcmp("tcp", transport_mode)) == 0 ) || ((strcmp("udp", transport_mode)) == 0 )) {
        if ((strcmp("tcp", transport_mode)) == 0) 
            useTcp = 1;
        else
            useTcp = 0;
        syslog(LOG_INFO, "Setting transport to: %s", transport_mode);
    } else {
        syslog(LOG_ALERT, "Invalid transport_mode set in config file: %s.  Must be tcp or udp.", transport_mode);
        fprintf(stderr, "Error.  See log for details.\n");
        exitApp(1);
    }

    if (opsec_get_conf(pEnv, "online_mode", NULL) == NULL) {
        syslog(LOG_ALERT, "online_mode not set in config file.");
        fprintf(stderr, "Error.  See log for details.\n");
        exitApp(1);
    } else {
        if (strcmp("true", opsec_get_conf(pEnv, "online_mode", NULL)) == 0) {
            online_mode = 1;
            syslog(LOG_INFO, "Setting online mode to TRUE");
        } else {
            online_mode = 0;
            syslog(LOG_INFO, "Setting online mode to FALSE");
        }
    }
    
    if ((serverport = atoi(opsec_get_conf(pEnv, "destination_port", NULL))) == 0) {
        syslog(LOG_ALERT, "destination_port not set in config file.");
        fprintf(stderr, "Error.  See log for details.\n");
        exitApp(1);
    } else {
        syslog(LOG_INFO, "Setting destination port to: %d", serverport);
    }
    
    if (opsec_get_conf(pEnv, "resolve_names", NULL) == NULL) {
        syslog(LOG_ALERT, "resolve_names not set in config file.");
        fprintf(stderr, "Error.  See log for details.\n");
        exitApp(1);
    } else {
        if (strcmp("true", opsec_get_conf(pEnv, "resolve_names", NULL)) == 0) {
            resolve_names = 1;
            syslog(LOG_INFO, "Setting resolve_names to TRUE");
        } else {
            resolve_names = 0;
            syslog(LOG_INFO, "Setting resolve_names to FALSE");
        }
    }

    if (opsec_get_conf(pEnv, "use_syslog_format", NULL) == NULL) {
        syslog(LOG_ALERT, "use_syslog_format not set in config file.");
        fprintf(stderr, "Error.  See log for details.\n");
        exitApp(1);
    } else {
        if (strcmp("true", opsec_get_conf(pEnv, "use_syslog_format", NULL)) == 0) {
            useSyslogFormat = 1;
            syslog(LOG_INFO, "Setting useSyslogFormat to TRUE");

            // set facility
            if (opsec_get_conf(pEnv, "syslog_facility", NULL) == NULL) {
                syslog(LOG_ALERT, "Required syslog_facility not set in config file.");
                fprintf(stderr, "Error.  See log for details.\n");
                exitApp(1);
            } else {
                if ((syslog_facility = atoi(opsec_get_conf(pEnv, "syslog_facility", NULL))) == 0) {
                    syslog(LOG_ALERT, "Syslog facility should be numeric and non-zero.");
                    fprintf(stderr, "Error.  See log for details.\n");
                    exitApp(1);
                }
            }
                    
            // set severity
            if (opsec_get_conf(pEnv, "syslog_severity", NULL) == NULL) {
                syslog(LOG_ALERT, "Required syslog_severity not set in config file.");
                fprintf(stderr, "Error.  See log for details.\n");
                exitApp(1);
            } else {
                if ((syslog_severity = atoi(opsec_get_conf(pEnv, "syslog_severity", NULL))) == 0) {
                    syslog(LOG_ALERT, "Syslog severity should be numeric and non-zero.");
                    fprintf(stderr, "Error.  See log for details.\n");
                    exitApp(1);
                }
            }
        } else {
            syslog(LOG_INFO, "Setting useSyslogFormat to FALSE.");
            useSyslogFormat = 0;
        }
    }




    /* Establish Network connection */
    if (useTcp)
        establishTcpSession(server, serverport);
    else    
        establishUdpSession(server, serverport);

    /*
    * initialize opsec-client
    */
    pClient = opsec_init_entity (pEnv, LEA_CLIENT,
    		   LEA_RECORD_HANDLER,
    		   LeaRecordHandler,
    		   LEA_DICT_HANDLER, LeaDictionaryHandler,
    		   LEA_EOF_HANDLER, LeaEofHandler,
    		   LEA_SWITCH_HANDLER, LeaSwitchHandler,
    		   OPSEC_SESSION_START_HANDLER, LeaStartHandler,
    		   OPSEC_SESSION_END_HANDLER, LeaEndHandler,
    		   OPSEC_SESSION_ESTABLISHED_HANDLER, LeaSessionEstablished, 
    		   OPSEC_EOL);
    
    /*
    * initialize opsec-server for authenticated and unauthenticated connections
    */
    
    pServer = opsec_init_entity (pEnv, LEA_SERVER, OPSEC_ENTITY_NAME, "lea_server",
    	    OPSEC_EOL);
    	    
    /*
    * continue only if opsec initializations were successful
    */
    if ((!pClient) || (!pServer)) {
        syslog(LOG_ALERT,
           "ERROR: failed to initialize client/server-pair (%s)\n",
        opsec_errno_str (opsec_errno));
        exitApp(1);
    }
	
	if (online_mode == 1)
	    pSession = lea_new_suspended_session (pClient, pServer, LEA_ONLINE, LEA_FILENAME, log_file, LEA_AT_END);
	else    
	    pSession = lea_new_suspended_session (pClient, pServer, LEA_OFFLINE, LEA_FILENAME, log_file, LEA_AT_START);

    if (!pSession) {
        syslog(LOG_ALERT, "ERROR: failed to create session (%s)\n",
        opsec_errno_str (opsec_errno));
        exitApp (1);
    }

	lea_session_resume (pSession);    
	opsec_start_keep_alive (pSession, 0);
	opsec_mainloop(pEnv);
	

	/*
	 *  Free the OPSEC entities and the environment before exiting.
	*/
	CleanUpEnvironment();

    close(sd);
    closelog();
	return 0;
}

void exitApp(int retCode) {
    CleanUpEnvironment();
    exit(retCode);
}

void CleanUpEnvironment() {    
    syslog(LOG_INFO, "Cleaning up for exit.");
	if (pClient) opsec_destroy_entity(pClient);
	if (pServer) opsec_destroy_entity(pServer);
	if (pEnv)    opsec_env_destroy(pEnv);
	unlink(pidfile);
	closelog();
    close(sd);
}

/* 
 * Handle signals to grawefully shut down.
 */
void quitApp(int sig) {
    if (sig == SIGTERM) {
        syslog(LOG_INFO, "Caught SIGTERM, Exiting.\n");
    } else if (sig == SIGQUIT) {
        syslog(LOG_INFO, "Caught SIGQUIT, Exiting.\n");
    } else if (sig == SIGINT) {
        syslog(LOG_INFO, "Caught SIGINT, Exiting.\n");
    } else if (sig == SIGHUP) {
        syslog(LOG_INFO, "Caught SIGHUP, Exiting.\n");
    } 

    CleanUpEnvironment();
    exit(0);
}

void establishTcpSession(char *server, int serverport) {
    /* get a socket descriptor */
    if((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        syslog(LOG_ALERT, "Client-socket() error");
        exit(-1);
    }
    else
        syslog(LOG_INFO, "Client-socket() OK");

    int rc;
     
    memset(&serveraddr, 0x00, sizeof(struct sockaddr_in));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(serverport);
    serveraddr.sin_addr.s_addr = inet_addr(server);
    
    /* connect() to server. */
    if((rc = connect(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0) {
        syslog(LOG_INFO, "Client-connect() error");
        close(sd);
        exitApp(1);
    }
    else
        syslog(LOG_INFO, "Connection established...");
}    

void establishUdpSession(char *server, int serverport) {
    /* get a socket descriptor */
    if((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        syslog(LOG_ALERT, "Client-socket() error");
        exitApp(1);
    }
    else
        syslog(LOG_INFO, "Client-socket() OK");

    memset(&serveraddr, 0x00, sizeof(struct sockaddr_in));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(serverport);
    serveraddr.sin_addr.s_addr = inet_addr(server);
}    


/*
 * This handler currently does nothing
 */
int LeaStartHandler(OpsecSession *session) {
	return OPSEC_SESSION_OK;
}

/*
 * This handler currently does nothing
 */
int LeaEndHandler(OpsecSession *session) {
	return OPSEC_SESSION_OK;
}

/*
 * This handler currently does nothing
 */
int LeaSessionEstablished(OpsecSession *session) {
	return OPSEC_SESSION_OK;
}

/*
 *  This is the log event handler.  This method is called for each log entry.
 *  Log parameters are in pairs of (k=v) strings separated by a double pipe (||).
 *  Log lines are ended with a newline character.
 */
int LeaRecordHandler(OpsecSession *pSession, lea_record *pRec, int pnAttribPerm[]) {
	int i;
	char *szResValue;
	char *szAttrib; 
	char logBuff[8192], tmptime[100], fworig[1024];
	int msgLen;
	unsigned long 	ul;
	unsigned short 	us;	
	time_t t;
	
	strcpy(logBuff, "");
	strcpy(tmptime, "");
	strcpy(fworig, "");
	
	
	struct tm *tmp;
	t = time(NULL);
    tmp = localtime(&t);
    
    if (useSyslogFormat) {
        if (tmp == NULL) {
            syslog(LOG_ALERT, "Unable to get local time");
            exitApp(1);
        }
        
        if (strftime(tmptime, sizeof(tmptime), DATEFORMAT, tmp) == 0) {
            syslog(LOG_ALERT, "strftime returned 0");
            exitApp(1);
        }
    } 
	
	/*
	 * Loop over all records fields
	 */
	 
	
	for (i=0; i<pRec->n_fields; i++)
	{
		/*
		 * Print each field
		 */
		szAttrib = lea_attr_name(pSession, pRec->fields[i].lea_attr_id);		
		
        if (useSyslogFormat) {
            if ((strcmp("orig", szAttrib)) == 0) {
                if(strlen(lea_resolve_field(pSession, pRec->fields[i])) < 1024)
                    strcpy(fworig, lea_resolve_field(pSession, pRec->fields[i]));
                else    
                    strcpy(fworig, "UNKNOWN_GW");
            }
        }

	    if (resolve_names) {
	        szResValue = lea_resolve_field(pSession, pRec->fields[i]);
	    } else {
            switch (pRec->fields[i].lea_val_type) {
                /*
                * create dotted string of IP address. this differs between
                * Linux and Solaris.
                */
                case LEA_VT_IP_ADDR:
                    ul = pRec->fields[i].lea_value.ul_value;
                    if (BYTE_ORDER == LITTLE_ENDIAN) {
                        sprintf(szResValue,"%d.%d.%d.%d", (int)((ul & 0xff) >> 0), (int)((ul & 0xff00) >> 8), (int)((ul & 0xff0000) >> 16), (int)((ul & 0xff000000) >> 24));
                    } else {
                        sprintf(szResValue,"%d.%d.%d.%d", (int)((ul & 0xff000000) >> 24), (int)((ul & 0xff0000) >> 16), (int)((ul & 0xff00) >> 8), (int)((ul & 0xff) >> 0));
                    }
                    break;
                /*
                * print out the port number of the used service
                */
                case LEA_VT_TCP_PORT:
                case LEA_VT_UDP_PORT:
                    us = pRec->fields[i].lea_value.ush_value;
                    if (BYTE_ORDER == LITTLE_ENDIAN) {
                    us = (us >> 8) + ((us & 0xff) << 8);
                    } 
                    sprintf(szResValue,"%d", us);
                    break;
                /* 
                * for all other data types, use the normal behaviour
                */	        
                default:
                    szResValue = lea_resolve_field(pSession, pRec->fields[i]);
            }
        }


	    if (strlen(logBuff) + strlen(szAttrib) < 8190) {
		    strcat(logBuff, szAttrib);
		    strcat(logBuff, "=");
		} else
		    return OPSEC_SESSION_OK;
		    
		if (strlen(logBuff) + strlen(szResValue) < 8190) 
		    strcat(logBuff, szResValue);
        else
		    return OPSEC_SESSION_OK;		
		if (i < pRec->n_fields - 1) {
    		if (strlen(logBuff) < 8188) 
	    	    strcat(logBuff, "||");
	    	else
		        return OPSEC_SESSION_OK;
		}     
	}

	/*
	 * End of line
	 */
	strcat(logBuff, "\n"); 
	
	if (useSyslogFormat) {
	    // 22 char + orig + message
	    if ((strlen(logBuff) + 22 + strlen(fworig)) < 8188) {
	        char logtmp[8192];
	        
	        sprintf(logtmp, "<%d> %s %s ", (syslog_facility * 8 + syslog_severity), tmptime, fworig);
	        strcat(logtmp, logBuff);
	        strcpy(logBuff, logtmp);
	    }
	}
	
	
	
	msgLen = strlen(logBuff);
	
	if (useTcp)
	    sendTcp(sd, logBuff, &msgLen);
	else
	    sendUdp(sd, logBuff, &msgLen);
	 
	return OPSEC_SESSION_OK;
}

/*
 * this sends the data to the network using TCP
 */
int sendTcp(int s, char *buf, int *len) {
    int total = 0;        // how many bytes we've sent
    int bytesleft = *len; // how many we have left to send
    int n;

    while(total < *len) {
        n = write(s, buf+total, bytesleft);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }

    *len = total; // return number actually sent here

    return n==-1?-1:0; // return -1 on failure, 0 on success
} 

/*
 * this sends the data to the network using UDP
 */
int sendUdp(int s, char *buf, int *len) {
    return sendto(s, buf, *len, 0, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
} 

/*
 * This does nothing for now
 */
int LeaDictionaryHandler(OpsecSession *session, int dict_id, LEA_VT val_type, int n_d_entries) {
	return OPSEC_SESSION_OK;
}

/*
 * This does nothing for now
 */
int LeaEofHandler(OpsecSession *pSession) {
	return OPSEC_SESSION_OK;
}

/*
 * This does nothing for now
 */
int LeaSwitchHandler(OpsecSession *pSession) {
	return OPSEC_SESSION_OK;
}
