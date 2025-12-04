
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    __setargv
   
   Library: Visual Studio 2008 Release */

int __cdecl __setargv(void)

{
  uint _Size;
  uint uVar1;
  undefined4 *puVar2;
  uint local_10;
  uint local_c;
  char *local_8;
  
  if (DAT_1000eaac == 0) {
    ___initmbctable();
  }
  DAT_1000e69c = 0;
  GetModuleFileNameA((HMODULE)0x0,&DAT_1000e598,0x104);
  _DAT_1000e26c = &DAT_1000e598;
  if ((DAT_1000fac4 == (char *)0x0) || (local_8 = DAT_1000fac4, *DAT_1000fac4 == '\0')) {
    local_8 = &DAT_1000e598;
  }
  parse_cmdline((undefined4 *)0x0,(byte *)0x0,(int *)&local_c);
  uVar1 = local_c;
  if ((local_c < 0x3fffffff) && (local_10 != 0xffffffff)) {
    _Size = local_c * 4 + local_10;
    if ((local_10 <= _Size) &&
       (puVar2 = (undefined4 *)__malloc_crt(_Size), puVar2 != (undefined4 *)0x0)) {
      parse_cmdline(puVar2,(byte *)(puVar2 + uVar1),(int *)&local_c);
      DAT_1000e250 = local_c - 1;
      DAT_1000e254 = puVar2;
      return 0;
    }
  }
  return -1;
}

