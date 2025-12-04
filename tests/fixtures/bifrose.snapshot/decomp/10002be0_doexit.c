
/* WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4 */
/* WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3 */
/* WARNING: Removing unreachable block (ram,0x10002cfd) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    _doexit
   
   Library: Visual Studio 2008 Release */

void __cdecl doexit(int param_1,int param_2,int param_3)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  code *pcVar4;
  int *piVar5;
  int *piVar6;
  int *local_2c;
  int *local_24;
  int *local_20;
  
  __lock(8);
  if (DAT_1000e27c != 1) {
    _DAT_1000e278 = 1;
    DAT_1000e274 = (undefined1)param_3;
    if (param_2 == 0) {
      piVar1 = (int *)__decode_pointer(DAT_1000eaa8);
      if (piVar1 != (int *)0x0) {
        piVar2 = (int *)__decode_pointer(DAT_1000eaa4);
        local_2c = piVar1;
        local_24 = piVar2;
        local_20 = piVar1;
        while (piVar2 = piVar2 + -1, piVar1 <= piVar2) {
          iVar3 = __encoded_null();
          if (*piVar2 != iVar3) {
            if (piVar2 < piVar1) break;
            pcVar4 = (code *)__decode_pointer(*piVar2);
            iVar3 = __encoded_null();
            *piVar2 = iVar3;
            (*pcVar4)();
            piVar5 = (int *)__decode_pointer(DAT_1000eaa8);
            piVar6 = (int *)__decode_pointer(DAT_1000eaa4);
            if ((local_20 != piVar5) || (piVar1 = local_2c, local_24 != piVar6)) {
              piVar2 = piVar6;
              piVar1 = piVar5;
              local_2c = piVar5;
              local_24 = piVar6;
              local_20 = piVar5;
            }
          }
        }
      }
      __initterm((undefined4 *)&DAT_1000a158);
    }
    __initterm((undefined4 *)&DAT_1000a160);
  }
  FUN_10002cf7();
  if (param_3 == 0) {
    DAT_1000e27c = 1;
    FUN_1000429f(8);
    ___crtExitProcess(param_1);
    return;
  }
  return;
}

