#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <stdlib.h>

#include "strerr.h"
#include "pathexec.h"
#include "sgetopt.h"

int main(int argc, char **argv)
{
    int opt;
    int timeout = 60;
    int payload_size = 1024;     
    while ((opt = getopt(argc,argv,"t:s:")) != opteof) {
        switch(opt) {
          case 't': scan_ulong(optarg,&timeout); 
                    break;
          case 's': scan_ulong(optarg,&payload_size);
                    break;
        } 
    }
    argv += optind;
    int fd[2], child;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0)
        strerr_die2sys(111,"udppipe: ","unable create socketpair: ");

    switch(fork()) {
        case 0:
            close(fd[0]);
            if ((fd_move(0,fd[1]) == -1) || (fd_copy(1,0) == -1))
	            strerr_die2sys(111,"udppipe: ","unable to set up descriptors: ");
            pathexec(argv);
            strerr_die2sys(111,"udppipe: ","unable to exec: ");
        case -1:
            strerr_die2sys(111,"udppipe: ","unable to fork: ");
    }

    struct timeval to;        
    to.tv_sec  = timeout;
    to.tv_usec = 0;
    for (;;) {
        fd_set rfd;
        FD_ZERO(&rfd);    
        FD_SET(0,&rfd);
        FD_SET(fd[0],&rfd);
        int n = select(fd[0]+1,&rfd,NULL,NULL,&to);
        if (!n) break;
        if (FD_ISSET(fd[0],&rfd)) {
            char buf[payload_size];
            int nbytes = read(fd[0],buf,sizeof(buf));
            if (nbytes>0) send(1,buf,nbytes,0);
        }
        if (FD_ISSET(0,&rfd)) {
            char buf[1500]; // FIXME
            int nbytes = recv(0,buf,sizeof(buf),0);
            if (nbytes>0) write(fd[0],buf,nbytes);
        }

    }
    return 0;
}
