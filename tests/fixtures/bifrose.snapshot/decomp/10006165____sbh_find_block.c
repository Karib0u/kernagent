
/* Library Function - Single Match
    ___sbh_find_block
   
   Library: Visual Studio 2008 Release */

uint __cdecl ___sbh_find_block(int param_1)

{
  uint uVar1;
  
  uVar1 = DAT_1000e978;
  while( true ) {
    if (DAT_1000e974 * 0x14 + DAT_1000e978 <= uVar1) {
      return 0;
    }
    if ((uint)(param_1 - *(int *)(uVar1 + 0xc)) < 0x100000) break;
    uVar1 = uVar1 + 0x14;
  }
  return uVar1;
}

