#include <sys/types.h>
#include <sys/param.h>
#include <netdb.h>
#include "sig.h"
#include "exit.h"
#include "sgetopt.h"
#include "uint16.h"
#include "fmt.h"
#include "scan.h"
#include "str.h"
#include "ip4.h"
#include "uint16.h"
#include "socket.h"
#include "fd.h"
#include "stralloc.h"
#include "buffer.h"
#include "error.h"
#include "strerr.h"
#include "pathexec.h"
#include "timeoutconn.h"
#include "remoteinfo.h"
#include "dns.h"

#define FATAL "udpclient: fatal: "
#define CONNECT "udpclient: unable to connect to "

void nomem(void)
{
  strerr_die2x(111,FATAL,"out of memory");
}
void usage(void)
{
  strerr_die1x(100,"udpclient: usage: udpclient \
[ -hHrRdDqQv ] \
[ -i localip ] \
[ -p localport ] \
[ -T timeoutconn ] \
[ -l localname ] \
[ -t timeoutinfo ] \
host port program");
}

int verbosity = 1;
int flagremoteinfo = 1;
int flagremotehost = 1;
int flagfakehandshake = 0;
unsigned long itimeout = 26;
unsigned long ctimeout[2] = { 2, 58 };

char iplocal[4] = { 0,0,0,0 };
uint16 portlocal = 0;
char *forcelocal = 0;

char ipremote[4];
uint16 portremote;

char *hostname;
static stralloc addresses;
static stralloc moreaddresses;

static stralloc tmp;
static stralloc fqdn;
char strnum[FMT_ULONG];
char ipstr[IP4_FMT];

char seed[128];

main(int argc,char **argv)
{
  unsigned long u;
  int opt;
  char *x;
  int j;
  int s;
  int cloop;

  dns_random_init(seed);
  
  int fd = 6;
 
  while ((opt = getopt(argc,argv,"vqQhHrRi:p:t:T:l:1fF")) != opteof)
    switch(opt) {
      case 'v': verbosity = 2; break;
      case 'q': verbosity = 0; break;
      case 'Q': verbosity = 1; break;
      case 'l': forcelocal = optarg; break;
      case 'H': flagremotehost = 0; break;
      case 'h': flagremotehost = 1; break;
      case 'R': flagremoteinfo = 0; break;
      case 'r': flagremoteinfo = 1; break;
      case 't': scan_ulong(optarg,&itimeout); break;
      case 'T': j = scan_ulong(optarg,&ctimeout[0]);
		if (optarg[j] == '+') ++j;
		scan_ulong(optarg + j,&ctimeout[1]);
		break;
      case 'i': if (!ip4_scan(optarg,iplocal)) usage(); break;
      case 'p': scan_ulong(optarg,&u); portlocal = u; break;
      case '1': fd = 0; break;
      case 'f': flagfakehandshake = 1; break;
      case 'F': flagfakehandshake = 0; break;
      default: usage();
    }
  argv += optind;

  close(fd);
  close(fd+1);
  sig_ignore(sig_pipe);

  if (!verbosity)
    buffer_2->fd = -1;

  hostname = *argv;
  if (!hostname) usage();
  if (str_equal(hostname,"")) hostname = "127.0.0.1";
  if (str_equal(hostname,"0")) hostname = "127.0.0.1";

  x = *++argv;
  if (!x) usage();
  if (!x[scan_ulong(x,&u)])
    portremote = u;
  else {
    struct servent *se;
    se = getservbyname(x,"udp");
    if (!se)
      strerr_die3x(111,FATAL,"unable to figure out port number for ",x);
    portremote = ntohs(se->s_port);
    /* i continue to be amazed at the stupidity of the s_port interface */
  }

  if (!*++argv) usage();

  if (!stralloc_copys(&tmp,hostname)) nomem();
  if (dns_ip4_qualify(&addresses,&fqdn,&tmp) == -1)
    strerr_die4sys(111,FATAL,"temporarily unable to figure out IP address for ",hostname,": ");
  if (addresses.len < 4)
    strerr_die3x(111,FATAL,"no IP address for ",hostname);

  if (addresses.len == 4) {
    ctimeout[0] += ctimeout[1];
    ctimeout[1] = 0;
  }

  for (cloop = 0;cloop < 2;++cloop) {
    if (!stralloc_copys(&moreaddresses,"")) nomem();
    for (j = 0;j + 4 <= addresses.len;j += 4) {
      s = socket_udp();
      if (s == -1)
        strerr_die2sys(111,FATAL,"unable to create socket: ");
      if (socket_bind4(s,iplocal,portlocal) == -1)
        strerr_die2sys(111,FATAL,"unable to bind socket: ");
        socket_connect4(s,addresses.s+j,portremote);
        if (ctimeout[0] && flagfakehandshake) {
          send(s,"",0,0);
          fd_set rfds,efds;
          FD_ZERO(&rfds);
          FD_SET(s,&rfds);
          FD_ZERO(&efds);
          FD_SET(s,&efds);
          struct timeval tv;
          tv.tv_sec  = ctimeout[cloop];
          tv.tv_usec = 0;
          select(s+1,&rfds,0,&efds,&tv);
          if (FD_ISSET(s,&efds)) goto NOT_CONNECTED;
          char buf[1];
          struct sockaddr_in sa;
          socklen_t sl = sizeof(sa);
          int t = recvfrom(s,buf,sizeof(buf),0,(struct sockaddr *)&sa,&sl);
          if (t<0) goto NOT_CONNECTED;
        }
        goto CONNECTED;
      NOT_CONNECTED: 
      close(s);
      if (!cloop && ctimeout[1] && (errno == error_timeout)) {
        if (!stralloc_catb(&moreaddresses,addresses.s + j,4)) nomem();
      }
      else {
        strnum[fmt_ulong(strnum,portremote)] = 0;
        ipstr[ip4_fmt(ipstr,addresses.s + j)] = 0;
        strerr_warn5(CONNECT,ipstr," port ",strnum,": ",&strerr_sys);
      }
    }
    if (!stralloc_copy(&addresses,&moreaddresses)) nomem();
  }

  _exit(111);

  CONNECTED:
  
  ndelay_off(s);

  if (!pathexec_env("PROTO","UDP")) nomem();

  if (socket_local4(s,iplocal,&portlocal) == -1)
    strerr_die2sys(111,FATAL,"unable to get local address: ");

  strnum[fmt_ulong(strnum,portlocal)] = 0;
  if (!pathexec_env("TCPLOCALPORT",strnum)) nomem();
  ipstr[ip4_fmt(ipstr,iplocal)] = 0;
  if (!pathexec_env("TCPLOCALIP",ipstr)) nomem();

  x = forcelocal;
  if (!x)
    if (dns_name4(&tmp,iplocal) == 0) {
      if (!stralloc_0(&tmp)) nomem();
      x = tmp.s;
    }
  if (!pathexec_env("TCPLOCALHOST",x)) nomem();

  if (socket_remote4(s,ipremote,&portremote) == -1)
    strerr_die2sys(111,FATAL,"unable to get remote address: ");

  strnum[fmt_ulong(strnum,portremote)] = 0;
  if (!pathexec_env("TCPREMOTEPORT",strnum)) nomem();
  ipstr[ip4_fmt(ipstr,ipremote)] = 0;
  if (!pathexec_env("TCPREMOTEIP",ipstr)) nomem();
  if (verbosity >= 2)
    strerr_warn4("udpclient: connected to ",ipstr," port ",strnum,0);

  x = 0;
  if (flagremotehost)
    if (dns_name4(&tmp,ipremote) == 0) {
      if (!stralloc_0(&tmp)) nomem();
      x = tmp.s;
    }
  if (!pathexec_env("TCPREMOTEHOST",x)) nomem();

  x = 0;
  if (flagremoteinfo)
    if (remoteinfo(&tmp,ipremote,portremote,iplocal,portlocal,itimeout) == 0) {
      if (!stralloc_0(&tmp)) nomem();
      x = tmp.s;
    }
  if (!pathexec_env("TCPREMOTEINFO",x)) nomem();

  if (fd_move(fd,s) == -1)
    strerr_die2sys(111,FATAL,"unable to set up descriptor 6: ");
  if (fd_copy(fd+1,fd) == -1)
    strerr_die2sys(111,FATAL,"unable to set up descriptor 7: ");
  sig_uncatch(sig_pipe);
 
  pathexec(argv);
  strerr_die4sys(111,FATAL,"unable to run ",*argv,": ");
}
