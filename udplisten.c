#include <sys/types.h>
#include <sys/param.h>
#include <netdb.h>
#include "uint16.h"
#include "str.h"
#include "byte.h"
#include "fmt.h"
#include "scan.h"
#include "ip4.h"
#include "fd.h"
#include "exit.h"
#include "env.h"
#include "prot.h"
#include "open.h"
#include "wait.h"
#include "readwrite.h"
#include "stralloc.h"
#include "alloc.h"
#include "buffer.h"
#include "error.h"
#include "strerr.h"
#include "sgetopt.h"
#include "pathexec.h"
#include "socket.h"
#include "ndelay.h"
#include "remoteinfo.h"
#include "rules.h"
#include "sig.h"
#include "dns.h"

#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>

int verbosity = 1;
int flagkillopts = 1;
char *banner = "";
int flagremoteinfo = 1;
int flagremotehost = 1;
int flagparanoid = 0;
unsigned long timeout = 26;

static stralloc tcpremoteinfo;

uint16 localport;
char localportstr[FMT_ULONG];
char localip[4];
char localipstr[IP4_FMT];
static stralloc localhostsa;
char *localhost = 0;

uint16 remoteport;
char remoteportstr[FMT_ULONG];
char remoteip[4];
char remoteipstr[IP4_FMT];
static stralloc remotehostsa;
char *remotehost = 0;

char strnum[FMT_ULONG];
char strnum2[FMT_ULONG];

static stralloc tmp;
static stralloc fqdn;
static stralloc addresses;

char bspace[16];
buffer b;

/* ---------------------------- child */

#define DROP "udppserver: warning: dropping connection, "

int flagdeny = 0;
int flagallownorules = 0;
char *fnrules = 0;

void drop_nomem(void)
{
  strerr_die2sys(111,DROP,"out of memory");
}
void cats(char *s)
{
  if (!stralloc_cats(&tmp,s)) drop_nomem();
}
void append(char *ch)
{
  if (!stralloc_append(&tmp,ch)) drop_nomem();
}
void safecats(char *s)
{
  char ch;
  int i;

  for (i = 0;i < 100;++i) {
    ch = s[i];
    if (!ch) return;
    if (ch < 33) ch = '?';
    if (ch > 126) ch = '?';
    if (ch == '%') ch = '?'; /* logger stupidity */
    if (ch == ':') ch = '?';
    append(&ch);
  }
  cats("...");
}
void env(char *s,char *t)
{
  if (!pathexec_env(s,t)) drop_nomem();
}
void drop_rules(void)
{
  strerr_die4sys(111,DROP,"unable to read ",fnrules,": ");
}

void found(char *data,unsigned int datalen)
{
  unsigned int next0;
  unsigned int split;

  while ((next0 = byte_chr(data,datalen,0)) < datalen) {
    switch(data[0]) {
      case 'D':
	flagdeny = 1;
	break;
      case '+':
	split = str_chr(data + 1,'=');
	if (data[1 + split] == '=') {
	  data[1 + split] = 0;
	  env(data + 1,data + 1 + split + 1);
	}
	break;
    }
    ++next0;
    data += next0; datalen -= next0;
  }
}

void doit(int t)
{
  int j;

  remoteipstr[ip4_fmt(remoteipstr,remoteip)] = 0;

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    strerr_warn4("udplisten: pid ",strnum," from ",remoteipstr,0);
  }

  if (flagkillopts)
    socket_ipoptionskill(t);

  if (*banner) {
    buffer_init(&b,write,t,bspace,sizeof bspace);
    if (buffer_putsflush(&b,banner) == -1)
      strerr_die2sys(111,DROP,"unable to print banner: ");
  }

  if (socket_local4(t,localip,&localport) == -1)
    strerr_die2sys(111,DROP,"unable to get local address: ");

  localipstr[ip4_fmt(localipstr,localip)] = 0;
  remoteportstr[fmt_ulong(remoteportstr,remoteport)] = 0;

  if (!localhost)
    if (dns_name4(&localhostsa,localip) == 0)
      if (localhostsa.len) {
	if (!stralloc_0(&localhostsa)) drop_nomem();
	localhost = localhostsa.s;
      }
  env("PROTO","UDP");
  env("TCPLOCALIP",localipstr);
  env("TCPLOCALPORT",localportstr);
  env("TCPLOCALHOST",localhost);

  if (flagremotehost)
    if (dns_name4(&remotehostsa,remoteip) == 0)
      if (remotehostsa.len) {
	if (flagparanoid)
	  if (dns_ip4(&tmp,&remotehostsa) == 0)
	    for (j = 0;j + 4 <= tmp.len;j += 4)
	      if (byte_equal(remoteip,4,tmp.s + j)) {
            flagparanoid = 0;
            break;
	      }
	if (!flagparanoid) {
	  if (!stralloc_0(&remotehostsa)) drop_nomem();
	  remotehost = remotehostsa.s;
	}
      }
  env("TCPREMOTEIP",remoteipstr);
  env("TCPREMOTEPORT",remoteportstr);
  env("TCPREMOTEHOST",remotehost);

  if (flagremoteinfo) {
    if (remoteinfo(&tcpremoteinfo,remoteip,remoteport,localip,localport,timeout) == -1)
      flagremoteinfo = 0;
    if (!stralloc_0(&tcpremoteinfo)) drop_nomem();
  }
  env("TCPREMOTEINFO",flagremoteinfo ? tcpremoteinfo.s : 0);

  if (fnrules) {
    int fdrules;
    fdrules = open_read(fnrules);
    if (fdrules == -1) {
      if (errno != error_noent) drop_rules();
      if (!flagallownorules) drop_rules();
    }
    else {
      if (rules(found,fdrules,remoteipstr,remotehost,flagremoteinfo ? tcpremoteinfo.s : 0) == -1) drop_rules();
      close(fdrules);
    }
  }

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    if (!stralloc_copys(&tmp,"udplisten: ")) drop_nomem();
    safecats(flagdeny ? "deny" : "ok");
    cats(" "); safecats(strnum);
    cats(" "); if (localhost) safecats(localhost);
    cats(":"); safecats(localipstr);
    cats(":"); safecats(localportstr);
    cats(" "); if (remotehost) safecats(remotehost);
    cats(":"); safecats(remoteipstr);
    cats(":"); if (flagremoteinfo) safecats(tcpremoteinfo.s);
    cats(":"); safecats(remoteportstr);
    cats("\n");
    buffer_putflush(buffer_2,tmp.s,tmp.len);
  }

  if (flagdeny) _exit(100);
}

/* ---------------------------- parent */

#define FATAL "udplisten: fatal: "

void usage(void)
{
  strerr_warn1("\
udplisten: usage: udplisten \
[ -1UXpPhHrRoOdDqQv ] \
[ -c limit ] \
[ -x rules.cdb ] \
[ -B banner ] \
[ -g gid ] \
[ -u uid ] \
[ -l localname ] \
[ -t timeout ] \
host port program",0);
  _exit(100);
}

unsigned long limit = 40;
unsigned long numchildren = 0;

unsigned long uid = 0;
unsigned long gid = 0;

void printstatus(void)
{
  if (verbosity < 2) return;
  strnum[fmt_ulong(strnum,numchildren)] = 0;
  strnum2[fmt_ulong(strnum2,limit)] = 0;
  strerr_warn4("udplisten: status: ",strnum,"/",strnum2,0);
}

void sigterm()
{
  _exit(0);
}

void sigchld()
{
  int wstat;
  int pid;
 
  while ((pid = wait_nohang(&wstat)) > 0) {
    if (verbosity >= 2) {
      strnum[fmt_ulong(strnum,pid)] = 0;
      strnum2[fmt_ulong(strnum2,wstat)] = 0;
      strerr_warn4("udplisten: end ",strnum," status ",strnum2,0);
    }
    if (numchildren) --numchildren; printstatus();
  }
}

int exec_cmd(int ss, int s, int t, char *buf, int sizeof_buf, struct sockaddr_in *sa, socklen_t sl, int fd, char **argv)
{
  close(ss);
  if (!t) {
    t = recvfrom(s,buf,sizeof_buf,0,(struct sockaddr *)sa,&sl);
    sendto(s,"",0,0,(struct sockaddr *)sa,sl);
  }
  if (gid) if (prot_gid(gid) == -1)
    strerr_die2sys(111,FATAL,"unable to set gid: ");
  if (uid) if (prot_uid(uid) == -1)
    strerr_die2sys(111,FATAL,"unable to set uid: ");
  if (connect(s,(struct sockaddr *)sa,sl)<0)
    strerr_die2sys(111,FATAL,"unable to connect: ");
  byte_copy(remoteip,4,(char *)&sa->sin_addr);
  uint16_unpack_big((char *)&sa->sin_port,&remoteport);
  ndelay_off(s);
  doit(s);
  if ((fd_move(fd,s) == -1) || (fd_copy(fd+1,fd) == -1))
    strerr_die2sys(111,DROP,"unable to set up descriptors: ");
  sig_uncatch(sig_child);
  sig_unblock(sig_child);
  sig_uncatch(sig_term);
  sig_uncatch(sig_pipe);
  pathexec(argv);
  strerr_die4sys(111,DROP,"unable to run ",*argv,": ");
  return -1;
}

main(int argc,char **argv)
{
  char *hostname;
  char *portname;
  int opt;
  struct servent *se;
  char *x;
  unsigned long u;
  int s;
  int t;
  int fd = 0;
  int foreground = 0;
 
  while ((opt = getopt(argc,argv,"dDvqQhHrR1UXx:t:u:g:l:B:c:pPoOCn:L:8:0:f")) != opteof)
    switch(opt) {
      case 'c': scan_ulong(optarg,&limit); break;
      case 'X': flagallownorules = 1; break;
      case 'x': fnrules = optarg; break;
      case 'B': banner = optarg; break;
      case 'v': verbosity = 2; break;
      case 'q': verbosity = 0; break;
      case 'Q': verbosity = 1; break;
      case 'P': flagparanoid = 0; break;
      case 'p': flagparanoid = 1; break;
      case 'O': flagkillopts = 1; break;
      case 'o': flagkillopts = 0; break;
      case 'H': flagremotehost = 0; break;
      case 'h': flagremotehost = 1; break;
      case 'R': flagremoteinfo = 0; break;
      case 'r': flagremoteinfo = 1; break;
      case 't': scan_ulong(optarg,&timeout); break;
      case 'U': x = env_get("UID"); 
                if (x) scan_ulong(x,&uid);
	        	x = env_get("GID"); 
                if (x) scan_ulong(x,&gid); break;
      case 'u': scan_ulong(optarg,&uid); break;
      case 'g': scan_ulong(optarg,&gid); break;
      case '1': fd = 6; break;
      case 'l': localhost = optarg; break;
      case 'f': foreground = 1; break;
      case 'C': // Ignore some parameters.
      case 'n':
      case 'L':
      case '8':
      case '0': break;
      default: usage();
    }
  argc -= optind;
  argv += optind;

  if (!verbosity)
    buffer_2->fd = -1;
 
  hostname = *argv++;
  if (!hostname) usage();
  if (str_equal(hostname,"")) hostname = "0.0.0.0";
  if (str_equal(hostname,"0")) hostname = "0.0.0.0";

  x = *argv++;
  if (!x) usage();
  if (!x[scan_ulong(x,&u)])
    localport = u;
  else {
    se = getservbyname(x,"udp");
    if (!se)
      strerr_die3x(111,FATAL,"unable to figure out port number for ",x);
    localport = ntohs(se->s_port);
  }

  if (!*argv) usage();
 
  sig_block(sig_child);
  sig_catch(sig_child,sigchld);
  sig_catch(sig_term,sigterm);
  sig_ignore(sig_pipe);
 
  if (!stralloc_copys(&tmp,hostname))
    strerr_die2x(111,FATAL,"out of memory");
  if (dns_ip4_qualify(&addresses,&fqdn,&tmp) == -1)
    strerr_die4sys(111,FATAL,"temporarily unable to figure out IP address for ",hostname,": ");
  if (addresses.len < 4)
    strerr_die3x(111,FATAL,"no IP address for ",hostname);
  byte_copy(localip,4,addresses.s);

  s = socket_udp();
  if (s == -1)
    strerr_die2sys(111,FATAL,"unable to create socket: ");
  if (socket_bind4_reuse(s,localip,localport) == -1)
    strerr_die2sys(111,FATAL,"unable to bind: ");
  if (socket_local4(s,localip,&localport) == -1)
    strerr_die2sys(111,FATAL,"unable to get local address: ");
  ndelay_off(s);

  localportstr[fmt_ulong(localportstr,localport)] = 0;
 
  if (!foreground) {
    close(0);
    close(1);
  }
  printstatus();
 
  for (;;) {
    while (numchildren >= limit) sig_pause();

    sig_unblock(sig_child);
    char buf[1];
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    t = recvfrom(s,buf,sizeof(buf),MSG_PEEK,(struct sockaddr *)&sa,&sl);
    sig_block(sig_child);

    int ss = socket_udp();
    if (ss == -1)
      strerr_die2sys(111,FATAL,"unable to create socket: ");
    if (socket_bind4_reuse(ss,localip,localport) == -1)
      strerr_die2sys(111,FATAL,"unable to bind: ");
    if (socket_local4(ss,localip,&localport) == -1)
      strerr_die2sys(111,FATAL,"unable to get local address: ");
    ndelay_off(ss);
    if (t != -1) {
        ++numchildren; printstatus();
        if (foreground) {
          return exec_cmd(ss, s, t, buf, sizeof(buf), &sa, sl, fd, argv);
        }
        switch(fork()) {
          case 0:
            exec_cmd(ss, s, t, buf, sizeof(buf), &sa, sl, fd, argv);
          case -1:
            strerr_warn2(DROP,"unable to fork: ",&strerr_sys);
            --numchildren; printstatus();
        }
    }
    close(s);
    s = ss;
  }
}
