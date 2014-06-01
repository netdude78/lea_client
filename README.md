lea_client README

Please note, large sections of this software were copied from examples provided
by Checkpoint in the OPSEC SDK.  Due to license restrictions, the SDK libraries
are not included in this project.

Installation prerequisites:
    * 32-bit linux operating system (tested on Centos 6.2)
    * CheckPoint NG / NGX Firewall Manager
    * libstdc++ compat-33.
    * Latest copy of the CheckPoint OPSEC SDK downloaded from:
	http://http://www.opsec.com/
    * OPSEC tools (opsec_pull_cert) from the CP SDK

    NOTE:  This software will only run on 32-bit operating systems.  CheckPoint 
    does not provide a 64-bit library to link against.

Usage:
    ./lea_client -c lea.conf [-i instance name]
    
    Command line arguments:
        -c  Configuration file to use.  This argument is required.  To run
            multiple instances for multiple firewall managers, create multiple
            config files.  Run this program for each instance.  Be sure not to
            overwrite the OPSEC certificate file.  Each connection will need its
            own cert.
            
        -i  Optional instance name.  If this is specified, the program will 
            create a .pid file in the current working directory with the name
            specified.  In addition, syslog messages will use this name instead
            of the default "lea_client" executable name.  This option may not 
            contain spaces.    
    
    The program will daemonize itself by default.  If a -i option is not
    specified, a file called lea_client.pid will be created with the process
    ID of the daemonized running program.
    

Pre-Install Steps:
    Run ldd against the opsec_pull_cert and opsec_putkey files.  If the output 
    looks similar to the following, you will need to install compatability 
    libraries.
    
        [user@centos lea_client]$ ldd opsec*
        opsec_pull_cert:
                linux-gate.so.1 =>  (0x009d0000)
                libpthread.so.0 => /lib/libpthread.so.0 (0x008db000)
                libresolv.so.2 => /lib/libresolv.so.2 (0x00ed3000)
                libdl.so.2 => /lib/libdl.so.2 (0x00ff4000)
                libpam.so.0 => /lib/libpam.so.0 (0x0058a000)
                libnsl.so.1 => /lib/libnsl.so.1 (0x004b0000)
                libstdc++.so.5 => not found
                libc.so.6 => /lib/libc.so.6 (0x00110000)
                /lib/ld-linux.so.2 (0x007a0000)
                libaudit.so.1 => /lib/libaudit.so.1 (0x00c6e000)
                libcrypt.so.1 => /lib/libcrypt.so.1 (0x00998000)
                libfreebl3.so => /lib/libfreebl3.so (0x00c98000)
        opsec_putkey:
                linux-gate.so.1 =>  (0x0076c000)
                libpthread.so.0 => /lib/libpthread.so.0 (0x0012b000)
                libresolv.so.2 => /lib/libresolv.so.2 (0x00b00000)
                libdl.so.2 => /lib/libdl.so.2 (0x00c93000)
                libpam.so.0 => /lib/libpam.so.0 (0x008e7000)
                libnsl.so.1 => /lib/libnsl.so.1 (0x00fbb000)
                libstdc++.so.5 => not found
                libc.so.6 => /lib/libc.so.6 (0x005b2000)
                /lib/ld-linux.so.2 (0x00e6e000)
                libaudit.so.1 => /lib/libaudit.so.1 (0x00b63000)
                libcrypt.so.1 => /lib/libcrypt.so.1 (0x00146000)
                libfreebl3.so => /lib/libfreebl3.so (0x00d95000)    
                
    NOTE the libstdc++.so.5 => not found line.  On CentOS, the required 
    library is provided by the compat-libstdc++-33.i686 package.
    
    If you install new libraries, be sure to run ldconfig as root to 
    update the ldconfig cache.
    
    After installing the libraries, ldd should not return any "not found" 
    messages.  Test the installation by running one of the provided 
    utilities withort any command line options.  If the usage message 
    appears, all is good.

Establishing Communication to the Manager:
    NOTE:  Certificate authentication requires the time, date and 
    timezone be correctly configured on both the firewall manager and
    log collection machine.  The usage of NTP is highly encouraged.

    Log in to the Smart Center.

    First create a host object corresponding to the IP address of your
    log collection machine.
    
    Next, navigate to the "Servers and OPSEC Applications" tab.  Create a new 
    OPSEC application.  The config should be:
        Name:  a useful name you choose
        Host:  This should correspond to the host you created in the last step
        Vendor: user defined
        Client Entities:  LEA
        
    Click Communication and specify a one-time password.  You will need this
    later to retrieve the OPSEC client cert.
    
    Click OK.
    
    Install the security policy.  Make sure the log collector can communicate
    with the manager on the LEA port.  The default is TCP 18184.    
    
    Log back in to your log collector system and run the opsec_pull_cert 
    command as follows:
    
        [dstoll@dstoll-test lea_client]$ ./opsec_pull_cert -h 10.10.10.10 -n dave_opsec -p password -o opsec.p12
         The full entity sic name is:
        CN=dave_opsec,O=LABCMA.labfw.9q6x6y
         Certificate was created successfully and written to "opsec.p12".
    
    Save the DN above because you will need to copy it to the lea.conf file.
    The config directive you should copy that to is opsec_sic_name.
    
    Finally you need to retrieve the SIC name of the firewall manager.  
    Follow the instructions in CheckPoint Knowledgebase article sk61833.
    If the SIC name is not displayed in smart dashboard, you will need to
    use the GuiDbEdit program.  Find the CheckPoint maanager object and
    copy the sic_name value to the lea_server opsec_entity_sic_name
    field in lea.conf.
    
    NOTE: When exiting the Database Editor do NOT save the changes.
    
Configuration:

    Sample Application Configuration File:
        ## LEA Config Section
        lea_server auth_type sslca
        lea_server ip 192.168.181.90
        lea_server auth_port 18184
        opsec_sic_name "CN=lea_logger,O=vmfw..ktz7qd"
        opsec_sslca_file /home/dstoll/lea_client/opsec.p12
        lea_server opsec_entity_sic_name "cn=cp_mgmt,o=vmfw..ktz7qd"
        
        ## Log Program Section
        destination_server 127.0.0.1
        destination_port 9999
        transport_mode tcp
        online_mode true
        log_filename fw.log
        resolve_names true
        
        ## SYSLOG configuration
        ## Use numeric values for facility and severity
        use_syslog_format false
        syslog_facility 16
        syslog_severity 5

    Config Directives Explained:
        lea_server auth_type
            This config directive instructs the API which authentication
            type you would like to use for the session.  The default for
            CheckPoint NG and NGX is sslca.  It is not recommended to 
            change this item.  
        
        lea_server ip 
            Set this to the IP address of the firewall manager/CMA/CLM you
            wish to pull logs from.
        
        lea_server auth_port
            The port LEA is defined to use on your firewall manager.  Default 
            value is 18184.
            
        opsec_sic_name
            This entry should match the DN of the LEA application exactly as 
            shown in the "communication" tab on the firewall manager.  Quotes 
            are required when there is a space in the DN.
            
        opsec_sslca_file
            Full path of the SSL client cert used for sslca authentication. 
            If spaces are present in the filename, surround this config item 
            in quotes.  The certificate is retrieved using the opsec_pull_cert 
            utility.    
            
        lea_server opsec_entity_sic_name
            The exact DN of the firewall manager as shown in the communication 
            tab.  The o or dc components of the manager and LEA application 
            should match.
            
        destination_server  
            The IPv4 address of the destination log receiver.  IPv6 is not
            currently supported.  This can not be a hostname, only an IP.
              
        destination_port
            Log receiver destination port.
            
        transport_mode
            Valid entries are tcp or udp.  The value must be all lower case.
            
        online_mode
            Valid entries: true or false.

            This config directive controls the behavior of the log forwarder. 
            
            If this entry is true, the program will begin listening for log 
            events at the end of the log file and will continue to forward 
            events as they are generated.
            
            If online_mode is set to false, the log forwarder will read the 
            specified log file from the beginning and exit when all log 
            entries have been processed.
            
        log_filename
            File name to request from the firewall manager.  The default 
            active log is fw.log.  If online_mode is set to true, this item
            should be set to fw.log.
            
        resolve_names
            Valid entries: true or false.
            
            When this is set to true, the program will convert source and
            destination IP addresses and services to the configured object 
            names.  The program will not use DNS, but will resolve names 
            similar to the CheckPoint log viewer application.
        
        use_syslog_format
            Valid entries: true or false.
            
            If this is set to true, the log forwarder will generate messages 
            in standard syslog format.  The syslog timestamp is generated when 
            the app receives messages.  The firewall generates a timestamp 
            which is embedded in the log message.  The firewall origin record 
            is copied to the hostname field in the output message.
            
            Sample:
            
            Jan  1 19:22:03 myfw LOG MESSAGE
            
            The LOG MESSAGE is a string of key/value pairs separated by ||
            
            If this config item is set to false, the output is just the 
            log message with no syslog header.
            
        syslog_facility
            Integer syslog facility value.  This item is only used if
            use_syslog_format is set to true.
            
            NOTE:  Facility zero is typically reserved, therefore the 
            program will exit if you attempt to use facility zero.
            
              Numerical             Facility
                   Code
        
                      0             kernel messages
                      1             user-level messages
                      2             mail system
                      3             system daemons
                      4             security/authorization messages
                      5             messages generated internally by syslogd
                      6             line printer subsystem
                      7             network news subsystem
                      8             UUCP subsystem
                      9             clock daemon
                     10             security/authorization messages
                     11             FTP daemon
                     12             NTP subsystem
                     13             log audit
                     14             log alert
                     15             clock daemon (note 2)
                     16             local use 0  (local0)
                     17             local use 1  (local1)
                     18             local use 2  (local2)
                     19             local use 3  (local3)
                     20             local use 4  (local4)
                     21             local use 5  (local5)
                     22             local use 6  (local6)
                     23             local use 7  (local7)

        syslog_severity
            Integer syslog severity.  This item is onsy used if
            use_syslog_format is set to true.
            
            NOTE:  Severity zero is typically reserved, therefore the 
            program will exit if you attempt to use severity zero.
            
                Numerical     Severity
                     Code
        
                      0       Emergency: system is unusable
                      1       Alert: action must be taken immediately
                      2       Critical: critical conditions
                      3       Error: error conditions
                      4       Warning: warning conditions
                      5       Notice: normal but significant condition
                      6       Informational: informational messages
                      7       Debug: debug-level messages        
