#include "auto_home.h"

void hier()
{
  h(auto_home,-1,-1,02755);
  d(auto_home,"bin",-1,-1,02755);

  c(auto_home,"bin","udplisten",-1,-1,0755);
  c(auto_home,"bin","udprules",-1,-1,0755);
  c(auto_home,"bin","udprulescheck",-1,-1,0755);
  c(auto_home,"bin","recordio",-1,-1,0755);
  c(auto_home,"bin","udpconnect",-1,-1,0755);
  c(auto_home,"bin","udpcat",-1,-1,0755);
}
