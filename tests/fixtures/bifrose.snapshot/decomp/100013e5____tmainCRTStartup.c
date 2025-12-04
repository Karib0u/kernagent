
/* WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4 */
/* WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3 */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    ___tmainCRTStartup
   
   Library: Visual Studio 2008 Release */

int ___tmainCRTStartup(void)

{
  int iVar1;
  bool bVar2;
  
  if ((((IMAGE_DOS_HEADER_10000000.e_magic == (char  [2])0x5a4d) &&
       (*(int *)(IMAGE_DOS_HEADER_10000000.e_lfanew + 0x10000000) == 0x4550)) &&
      (*(short *)((int)IMAGE_DOS_HEADER_10000000.e_res_4_ + (IMAGE_DOS_HEADER_10000000.e_lfanew - 4)
                 ) == 0x10b)) &&
     (0xe < *(uint *)(IMAGE_DOS_HEADER_10000000.e_program +
                     IMAGE_DOS_HEADER_10000000.e_lfanew + 0x34))) {
    bVar2 = *(int *)(&UNK_100000e8 + IMAGE_DOS_HEADER_10000000.e_lfanew) != 0;
  }
  else {
    bVar2 = false;
  }
  iVar1 = __heap_init();
  if (iVar1 == 0) {
    fast_error_exit(0x1c);
  }
  iVar1 = __mtinit();
  if (iVar1 == 0) {
    fast_error_exit(0x10);
  }
  __RTC_Initialize();
  iVar1 = __ioinit();
  if (iVar1 < 0) {
    __amsg_exit(0x1b);
  }
  DAT_1000fac4 = GetCommandLineA();
  DAT_1000df0c = ___crtGetEnvironmentStringsA();
  iVar1 = __setargv();
  if (iVar1 < 0) {
    __amsg_exit(8);
  }
  iVar1 = __setenvp();
  if (iVar1 < 0) {
    __amsg_exit(9);
  }
  iVar1 = __cinit(1);
  if (iVar1 != 0) {
    __amsg_exit(iVar1);
  }
  _DAT_1000e260 = DAT_1000e25c;
  iVar1 = FUN_10001020();
  if (!bVar2) {
                    /* WARNING: Subroutine does not return */
    _exit(iVar1);
  }
  __cexit();
  return iVar1;
}

