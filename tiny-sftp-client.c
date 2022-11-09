/*
 * Sample showing how to use libssh2 to execute a command remotely.
 *
 * The sample code has fixed values for host name, user name, password
 * and command to run.
 *
 * Run it like this:
 *
 * $ ./ssh2_ftp 127.0.0.1 22 user password 
 *
 */ 
 
/* need to install libssh2 */
#include <libssh2.h>
#include <libssh2_sftp.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

#define STORAGE "/tmp/sftp-storage" 

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session) {

    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;
 
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
 
    FD_ZERO(&fd);
    FD_SET(socket_fd, &fd);
 
    /* now make sure we wait in the correct direction */ 
    dir = libssh2_session_block_directions(session);
 
    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND){
        readfd = &fd;
    }
 
    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
        writefd = &fd;
    }
 
    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);
 
    return rc;
}

/* Request a file via SFTP */ 
int download_file(LIBSSH2_SESSION *session, LIBSSH2_SFTP *sftp_session, int sock ,const char *dest) {

    LIBSSH2_SFTP_HANDLE *sftp_handle; 
    FILE *tempstorage;
    const char *sftppath = "/tmp/TEST";

    tempstorage = fopen(STORAGE, "rb");
    if(!tempstorage) {
        fprintf(stderr, "can't open %s for reading\n", STORAGE);
        return -1;
        // goto shutdown;
    }
    
    while(!(sftp_handle = 
                libssh2_sftp_open(sftp_session, sftppath, LIBSSH2_FXF_READ, 0))) {
        if(libssh2_session_last_errno(session) != LIBSSH2_ERROR_EAGAIN) {
            fprintf(stderr, "Unable to open file with SFTP\n");
            return -1;
            // goto shutdown;
        }

        fprintf(stdout, "non-blocking open\n");
        waitsocket(sock, session);  
    }

    fprintf(stdout, "libssh2_sftp_open() is done, now receive data!\n");

    int rc;
    char mem[1000];
    struct timeval timeout;
    fd_set fd;
    fd_set fd2;

    while(1) {

        /* read in a loop until we block */ 
        while((rc = libssh2_sftp_read(sftp_handle, mem, sizeof(mem))) > 0) {
            /* write to stderr */ 
            write(2, mem, rc);
            /* write to temporary storage area */ 
            fwrite(mem, rc, 1, tempstorage);
        }

        /* error or end of file */ 
        if(rc != LIBSSH2_ERROR_EAGAIN) {
            break;
        }

        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        FD_ZERO(&fd);
        FD_ZERO(&fd2);
        FD_SET(sock, &fd);
        FD_SET(sock, &fd2);

        /* wait for readable or writeable */ 
        rc = select(sock + 1, &fd, &fd2, NULL, &timeout);
        if(rc <= 0) {
            /* negative is error, 0 is timeout */ 
            fprintf(stderr, "SFTP download timed out: %d\n", rc);
            break;
        }

    }

    libssh2_sftp_close(sftp_handle);
    fclose(tempstorage);
    return 0;
}

int upload_file(LIBSSH2_SFTP *sftp_session, int sock ,const char *dest) {

    LIBSSH2_SFTP_HANDLE *sftp_handle; 
    FILE *tempstorage;

    tempstorage = fopen(STORAGE, "rb");
    if(!tempstorage) {
        fprintf(stderr, "can't open %s for reading\n", STORAGE);
        return -1;
        // goto shutdown;
    }

    sftp_handle = libssh2_sftp_open(sftp_session, dest,
            LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT,
            LIBSSH2_SFTP_S_IRUSR|LIBSSH2_SFTP_S_IWUSR|
            LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IROTH);
    if(!sftp_handle) {
        fprintf(stderr, "SFTP failed to open destination path: %s\n", dest);
        return -1;
    }

    int rc;
    size_t nread;
    char mem[1000];
    char *ptr;
    struct timeval timeout;
    fd_set fd;
    fd_set fd2;

    while ((nread = fread(mem, 1, sizeof(mem), tempstorage)) >= 0) {
        ptr = mem;

        /* write data in a loop until we block */ 
        while((rc = libssh2_sftp_write(sftp_handle, ptr, nread)) >= 0) {
            rc = libssh2_sftp_write(sftp_handle, ptr, nread);
            ptr += rc;
            nread -= nread;
        }

        /* error or end of file */ 
        if(rc != LIBSSH2_ERROR_EAGAIN) {
            break;
        }

        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        FD_ZERO(&fd);
        FD_ZERO(&fd2);
        FD_SET(sock, &fd);
        FD_SET(sock, &fd2);

        /* wait for readable or writeable */ 
        rc = select(sock + 1, &fd, &fd2, NULL, &timeout);
        if(rc <= 0) {
            /* negative is error, 0 is timeout */ 
            fprintf(stderr, "SFTP upload timed out: %d\n", rc);
            break;
        }

    }
    fprintf(stdout, "SFTP upload done!\n");

    libssh2_sftp_close(sftp_handle);
    fclose(tempstorage);
    return 0;
}
 
 
int main(int argc, char *argv[]) {

    const char *hostname = "127.0.0.1";
    int  port = 22;
    const char *commandline = "uptime";
    const char *username    = "user";
    const char *password    = "password";

    unsigned long hostaddr;
    int sock;
    struct sockaddr_in sin;
    const char *fingerprint;
    LIBSSH2_SESSION *session;
    LIBSSH2_SFTP *sftp_session;
    int rc;
    int bytecount = 0;
    size_t len;
    LIBSSH2_KNOWNHOSTS *nh;
    int type;

    switch(argc) {
        /* 1 is default. */
        case 1:
            break;
        case 5:
            password = argv[4];
        case 4:
            username = argv[3];
        case 3:
            port = atoi(argv[2]);
        case 2:
            hostname = argv[1];
            break;
        /* default is error */
        default:
            fprintf(stdout, "argument should have 1 to 5. now (%d)", argc);
            return 1;
    }
 
    rc = libssh2_init(0);

    if(rc != 0) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
        return 1;
    }
 
    sock = socket(AF_INET, SOCK_STREAM, 0);
    hostaddr = inet_addr(hostname);

    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = hostaddr;

    if(connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0) {
        fprintf(stderr, "failed to connect!\n");
        return -1;
    }
 
    /* Create a session instance */ 
    session = libssh2_session_init();
    if(!session) {
        return -1;
    }
 
    /* tell libssh2 we want it all done non-blocking */ 
    libssh2_session_set_blocking(session, sock);

    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */ 
    while((rc = libssh2_session_handshake(session, sock)) == LIBSSH2_ERROR_EAGAIN);
    if(rc) {
        fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
        return -1;
    }
 
    nh = libssh2_knownhost_init(session);
    if(!nh) {
        return 2;
    }
 
    /* read all hosts from here */ 
    libssh2_knownhost_readfile(nh, "known_hosts", LIBSSH2_KNOWNHOST_FILE_OPENSSH);
 
    /* store all known hosts to here */ 
    libssh2_knownhost_writefile(nh, "dump-known_hosts", LIBSSH2_KNOWNHOST_FILE_OPENSSH);
 
    fingerprint = libssh2_session_hostkey(session, &len, &type);

    if(!fingerprint) {
        return 3;
    }

    /*****
     * At this point, we could verify that 'check' tells us the key is
     * fine or bail out.
     *****/ 
    struct libssh2_knownhost *host;
#if LIBSSH2_VERSION_NUM >= 0x010206
    /* introduced in 1.2.6 */ 
    int check = libssh2_knownhost_checkp(nh, 
                                          hostname, 
                                          port, 
                                          fingerprint, 
                                          len,
                                          LIBSSH2_KNOWNHOST_TYPE_PLAIN|
                                          LIBSSH2_KNOWNHOST_KEYENC_RAW,
                                          &host);
#else
    /* 1.2.5 or older */ 
    int check = libssh2_knownhost_check(nh, 
                                         hostname,
                                         fingerprint, 
                                         len,
                                         LIBSSH2_KNOWNHOST_TYPE_PLAIN|
                                         LIBSSH2_KNOWNHOST_KEYENC_RAW,
                                         &host);
#endif

    fprintf(stderr, "Host check: %d, key: %s\n", check,
            (check <= LIBSSH2_KNOWNHOST_CHECK_MISMATCH)?
            host->key:"<none>");

    libssh2_knownhost_free(nh);
 
    if(strlen(password) != 0) {
        /* We could authenticate via password */ 
        while((rc = libssh2_userauth_password(session, 
                                               username, 
                                               password)) 
                                                == LIBSSH2_ERROR_EAGAIN);

        if(rc) {
            fprintf(stderr, "Authentication by password failed.\n");
            goto shutdown;
        }

    } else {
        /* Or by public key */ 
        while((rc = libssh2_userauth_publickey_fromfile(session, 
                                                         username,
                                                         "/home/user/"
                                                         ".ssh/id_rsa.pub",
                                                         "/home/user/"
                                                         ".ssh/id_rsa",
                                                         password)) 
                                                          == LIBSSH2_ERROR_EAGAIN);

        if(rc) {
            fprintf(stderr, "\tAuthentication by public key failed\n");
            goto shutdown;
        }
    }
 
    while(!(sftp_session = libssh2_sftp_init(session))) {
        if(libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN) {
            fprintf(stderr, "non-blocking init\n");
            waitsocket(sock, session); /* now we wait */ 
        } else {
            fprintf(stderr, "Unable to init SFTP session\n");
            goto shutdown;
        }
    }

    /* tiny-client-shell 
     *
     * need to prepare null byte and except other one.
     * so take 5 byte
     */
    char input[5];

    while(fgets(input, sizeof(input), stdin) != NULL) {

        if (sizeof(input)-1 <= strlen(input)) {
            continue;
        }

        if (input[strlen(input)-1] == '\n') {
            input[strlen(input)-1] = '\0';
        }

        if (strncmp(input, "DWN", 3) == 0 ) {
            download_file(session, sftp_session, sock, destfile);
        }
        if (strncmp(input, "UPL", 3) == 0 ) {
            upload_file(sftp_sesion, sock, destfile);
        }
        if (strncmp(input, "EXT", 3) == 0 ) {
            goto shutdown;
        }
        printf("ssc > ");
    }

 
shutdown:
    libssh2_session_disconnect(session,"Normal Shutdown, Thank you for using");
    libssh2_session_free(session);
    close(sock);
    fprintf(stderr, "all done\n");
    libssh2_exit();
    return 0;
}
