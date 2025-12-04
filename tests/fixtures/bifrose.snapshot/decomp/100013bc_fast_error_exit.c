
/* Library Function - Single Match
    _fast_error_exit
   
   Library: Visual Studio 2008 Release */

void __cdecl fast_error_exit(int param_1)

{
  if (DAT_1000df14 != 2) {
    __FF_MSGBANNER();
  }
  __NMSG_WRITE(param_1);
  ___crtExitProcess(0xff);
  return;
}

