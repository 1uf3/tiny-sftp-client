/*
 * Run it like this:
 * $ ./ssh2_ftp -h 127.0.0.1 -p 22 -u user -P password 
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
#include <termios.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <getopt.h>

/*
 * On Linux: The maximum length for a file name is 255 bytes.
 * The maximum combined length of both the file name and path
 * name is 4096 bytes. This length matches the PATH_MAX that 
 * is supported by the operating system.
 */
#define MAX_PATH 4096
#define OPTSTRING "h:p:u:P::"

typedef struct {
    char* hostname;
    int*  port;
    char* username;
    char* password;
} data_t;

typedef struct {
	unsigned int h:1;	
  char* hp;
	unsigned int p:1;	
  char *pp;
	unsigned int u:1;	
  char *up;
	unsigned int P:1;	
  char *Pp;
	unsigned int no_option:1;
} options;

static struct option long_options[] = {
    {"hostname", required_argument, NULL, 'h'},
    {"port", required_argument, NULL, 'p'},
    {"username", required_argument, NULL, 'u'},
    {"password", optional_argument, NULL, 'P'},
    {NULL, 0, NULL, 0}
};

void* initialize(data_t*);
int parse_opts(options*, int, char**);
static int waitsocket(int, LIBSSH2_SESSION*);
int sdfilename(char*, char*, char*);
int download_file(LIBSSH2_SESSION*, LIBSSH2_SFTP*, int);
int upload_file(LIBSSH2_SFTP*, int);
char* input_password();
int shell(LIBSSH2_SESSION*, LIBSSH2_SFTP*, int);

int main(int argc, char** argv) {
    unsigned long hostaddr;
    int sock, type, rc;
    struct sockaddr_in sin;
    const char* fingerprint;
    LIBSSH2_SESSION *session;
    LIBSSH2_SFTP* sftp_session;
    LIBSSH2_KNOWNHOSTS* nh;
    int bytecount = 0;
    size_t len;
    data_t* d;
    options opts = {};

    d = (data_t*)initialize(d);
    if(d == NULL) {
        fprintf(stderr, "Failed to malloc area\n");
        return -1;
    }
    if(parse_opts(&opts, argc, argv) == -1) {
        puts("Try 'wc --help' for more information.");
        return -1;
    }

    if(opts.h)
        d->hostname = opts.hp;
    if(opts.p)
        *d->port = atoi(opts.pp);
    if(opts.u)
        d->username = opts.up;
    if(opts.no_option) {
        d->hostname = "127.0.0.1";
        *d->port = 22;
        d->username = "user";
    }

    printf("Now you logging in : %s\n", d->username);
    if(opts.P) {
        d->password = opts.Pp;
    } else {
        d->password = input_password();
    }

    puts("=== debug ===");
    printf("hostname: %s\n",d->hostname);
    printf("port: %d\n",*d->port);
    printf("username: %s\n",d->username);
    printf("password: %s\n",d->password);
    puts("=============");
 
    rc = libssh2_init(0);

    if(rc != 0) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
        return 1;
    }
 
    sock = socket(AF_INET, SOCK_STREAM, 0);
    hostaddr = inet_addr(d->hostname);

    sin.sin_family = AF_INET;
    sin.sin_port = htons(*d->port);
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
                                          d->hostname, 
                                          *d->port, 
                                          fingerprint, 
                                          len,
                                          LIBSSH2_KNOWNHOST_TYPE_PLAIN|
                                          LIBSSH2_KNOWNHOST_KEYENC_RAW,
                                          &host);
#else
    /* 1.2.5 or older */ 
    int check = libssh2_knownhost_check(nh, 
                                         d->hostname,
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

    /* authenticate via password */ 
    while((rc = libssh2_userauth_password(session, 
                    d->username, 
                    d->password)) 
            == LIBSSH2_ERROR_EAGAIN);

    if(rc) {
        fprintf(stderr, "Authentication by password failed.\n");
        goto shutdown;
    }

    while(!(sftp_session = libssh2_sftp_init(session))) {
        if(libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN) {
            puts("non-blocking init");
            waitsocket(sock, session); /* now we wait */ 
        } else {
            fprintf(stderr, "Unable to init SFTP session\n");
            goto shutdown;
        }
    }

    shell(session, sftp_session, sock);

shutdown:
    libssh2_session_disconnect(session,"Normal Shutdown, Thank you for using");
    libssh2_session_free(session);
    close(sock);
    libssh2_exit();
    free(d->username);
    free(d->password);
    free(d->port);
    free(d->hostname);
    free(d);
    puts("all done");
    return 0;
}

void* initialize(data_t* d) {
    d = (data_t*)calloc(1, sizeof(data_t));
    if(d == NULL) {
        return NULL;
    }
    d->hostname = (char*)calloc(30, sizeof(char));
    d->port = (int*)calloc(1, sizeof(int));
    d->username = (char*)calloc(30, sizeof(char));
    d->password = (char*)calloc(30, sizeof(char));
    if(d->hostname == NULL || d->port == NULL || 
            d->username == NULL || d->password == NULL) {
        return NULL;
    }

    return d;
}

static int waitsocket(int socket_fd, LIBSSH2_SESSION* session) {

    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set* writefd = NULL;
    fd_set* readfd = NULL;
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

int sdfilename(char* remote, char* local, char* type) {
    char tmp[MAX_PATH];

    puts("remote file path need to write full path.");

    printf("ssc %s > ENTER remote filename : ", type);
    fgets(tmp, sizeof(tmp), stdin);
    if(tmp[strlen(tmp)-1] == '\n') {
        tmp[strlen(tmp)-1] = '\0';
    }
    memcpy(remote, tmp, sizeof(tmp));

    memset(tmp, 0, sizeof(tmp));

    printf("ssc %s > ENTER local filename : ", type);
    fgets(tmp, sizeof(tmp), stdin);
    if(tmp[strlen(tmp)-1] == '\n') {
        tmp[strlen(tmp)-1] = '\0';
    } 

    if(tmp[0] == '/') {
        memcpy(local, tmp, sizeof(tmp));
    } else {
        if(strlen(tmp) + strlen(local) >= MAX_PATH) {
            fprintf(stderr, "path is over 4096 byte.");
            exit(-1);
        }

        strncat(local, "/", sizeof("/"));
        strncat(local, tmp, strlen(tmp));
    }

    memset(tmp, 0, sizeof(tmp));
    return 0;
}

/* Download a file via SFTP */ 
int download_file(LIBSSH2_SESSION* session, LIBSSH2_SFTP* sftp_session, int sock) {

    LIBSSH2_SFTP_HANDLE* sftp_handle; 
    char spath[MAX_PATH] = "/tmp";
    char dpath[MAX_PATH];
    FILE* fp;

    /* initialize spath */
    getcwd(dpath, MAX_PATH);
    sdfilename(spath, dpath, "DWN");

    fp = fopen(dpath, "ab+");
    if(!fp) {
        fprintf(stderr, "can't open %s for reading\n", dpath);
        return -1;
    }
    
    while(!(sftp_handle = 
                libssh2_sftp_open(sftp_session, spath, LIBSSH2_FXF_READ, 0))) {
        if(libssh2_session_last_errno(session) != LIBSSH2_ERROR_EAGAIN) {
            fprintf(stderr, "Unable to open file with SFTP\n");
            return -1;
        }

        puts("non-blocking open");
        waitsocket(sock, session);  
    }

    puts("libssh2_sftp_open() is done, now receive data!");

    int rc;
    char mem[1000];
    struct timeval timeout;
    fd_set fd;
    fd_set fd2;

    while(1) {

        /* get a file from sever to local */
        while((rc = libssh2_sftp_read(sftp_handle, mem, sizeof(mem))) > 0) {
            /* write to stderr */ 
            write(2, mem, rc);
            /* write to temporary storage area */ 
            fwrite(mem, rc, 1, fp);
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
    fclose(fp);
    return 0;
}

/* Upload a file via SFTP */ 
int upload_file(LIBSSH2_SFTP* sftp_session, int sock) {

    LIBSSH2_SFTP_HANDLE *sftp_handle; 
    char spath[MAX_PATH] = "/tmp";
    char dpath[MAX_PATH];
    FILE* fp;

    /* initialize spath */
    getcwd(spath, MAX_PATH);
    sdfilename(dpath, spath, "UPD");

    fp = fopen(spath, "rb");
    if(!fp) {
        fprintf(stderr, "can't open %s for reading\n", spath);
        return -1;
        // goto shutdown;
    }

    sftp_handle = libssh2_sftp_open(sftp_session, dpath,
            LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT,
            LIBSSH2_SFTP_S_IRUSR|LIBSSH2_SFTP_S_IWUSR|
            LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IROTH);
    if(!sftp_handle) {
        fprintf(stderr, "SFTP failed to open destination path: %s\n", dpath);
        return -1;
    }

    int rc;
    size_t nread;
    char mem[1000];
    char* ptr;
    struct timeval timeout;
    fd_set fd;
    fd_set fd2;

    while ((nread = fread(mem, 1, sizeof(mem), fp)) > 0) {
        ptr = mem;

        /* write data in a loop until we block */ 
        while((rc = libssh2_sftp_write(sftp_handle, ptr, nread)) > 0) {
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
    puts("SFTP upload done!");

    libssh2_sftp_close(sftp_handle);
    fclose(fp);
    return 0;
}

/*
 * password acceptable length max 256.
 */
char* input_password() {
    struct termios oflags, nflags;
    char tmp[256];
    char *password;

    /* disabling echo */
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
        perror("tcsetattr");
        exit(-1);
    }

    printf("INPUT PASSWORD : ");
    while(fgets(tmp, sizeof(tmp), stdin)) {
        if (strlen(tmp) > 1) {
            break;
        }
    }

    if (tmp[strlen(tmp)-1] == '\n') {
        tmp[strlen(tmp)-1] = '\0';
    }

    password = (char*)calloc(strlen(tmp)+1, sizeof(char));
    if (password == NULL) {
        return NULL;
    }

    memcpy(password, tmp, sizeof(tmp));

    /* restore terminal */
    if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
        perror("tcsetattr");
        exit(-1);
    }

    return password;
}

/* tiny shell 
 *
 * need to prepare null byte and except other one.
 * so take 5 byte
 *
 * want to upgrade this content for add any control.
 */
int shell(LIBSSH2_SESSION* session, LIBSSH2_SFTP* sftp_session, int sock) {
    char cmd[10];

    while(fgets(cmd, sizeof(cmd), stdin) != NULL) {

        if (sizeof(cmd)-1 <= strlen(cmd)) {
            continue;
        }

        if (cmd[strlen(cmd)-1] == '\n') {
            cmd[strlen(cmd)-1] = '\0';
        }

        if (strncmp(cmd, "DWN", 3) == 0 ) {
            puts("DEBUG > downloading!");
            download_file(session, sftp_session, sock);
        }
        if (strncmp(cmd, "UPD", 3) == 0 ) {
            puts("DEBUG > uploading!");
            upload_file(sftp_session, sock);
        }
        if (strncmp(cmd, "EXT", 3) == 0 ) {
            return 0;
        }
        printf("ssc > ");
        rewind(stdin);
    }
}

int parse_opts(options* opts, int argc, char** argv) {
    int c, option_index;

    while (1) {
        option_index = 0;

        if ((c = getopt_long(argc, argv, OPTSTRING, long_options,
                        &option_index)) == -1) {
            break;
        }

        switch (c) {
            case 'h':
                opts->h = 1;
                opts->hp = optarg;
                break;

            case 'p':
                opts->p = 1;
                opts->pp = optarg;
                break;

            case 'u':
                opts->u = 1;
                opts->up = optarg;
                break;

            case 'P':
                opts->P = 1;
                opts->Pp = optarg;
                break;

            default:
                fprintf(stderr, "Error: Unknown character code %c\n", c);
                return -1;
        }
    }

    if(!opts->h && !opts->p && !opts->u && !opts->P) {
        opts->no_option = 1;
    }

    return 0;
}
