
/* Library Function - Single Match
    __cinit
   
   Library: Visual Studio 2008 Release */

int __cdecl __cinit(int param_1)

{
  BOOL BVar1;
  int iVar2;
  
  if (DAT_1000eab0 != (code *)0x0) {
    BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_1000eab0);
    if (BVar1 != 0) {
      (*DAT_1000eab0)(param_1);
    }
  }
  __initp_misc_cfltcvt_tab();
  iVar2 = __initterm_e((undefined4 *)&DAT_1000a12c,(undefined4 *)&DAT_1000a148);
  if (iVar2 == 0) {
    _atexit((_func_4879 *)&LAB_100037cd);
    __initterm((undefined4 *)&DAT_1000a128);
    if (DAT_1000eab4 != (code *)0x0) {
      BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_1000eab4);
      if (BVar1 != 0) {
        (*DAT_1000eab4)(0,2,0);
      }
    }
    iVar2 = 0;
  }
  return iVar2;
}

