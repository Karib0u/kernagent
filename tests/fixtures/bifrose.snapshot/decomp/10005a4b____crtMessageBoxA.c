
/* Library Function - Single Match
    ___crtMessageBoxA
   
   Library: Visual Studio 2008 Release */

int __cdecl ___crtMessageBoxA(LPCSTR _LpText,LPCSTR _LpCaption,UINT _UType)

{
  int iVar1;
  HMODULE hModule;
  FARPROC pFVar2;
  code *pcVar3;
  code *pcVar4;
  int iVar5;
  undefined1 local_18 [8];
  byte local_10;
  undefined1 local_c [4];
  int local_8;
  
  iVar1 = __encoded_null();
  local_8 = 0;
  if (DAT_1000e880 == 0) {
    hModule = LoadLibraryA("USER32.DLL");
    if (hModule == (HMODULE)0x0) {
      return 0;
    }
    pFVar2 = GetProcAddress(hModule,"MessageBoxA");
    if (pFVar2 == (FARPROC)0x0) {
      return 0;
    }
    DAT_1000e880 = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,"GetActiveWindow");
    DAT_1000e884 = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,"GetLastActivePopup");
    DAT_1000e888 = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,"GetUserObjectInformationA");
    DAT_1000e890 = __encode_pointer((int)pFVar2);
    if (DAT_1000e890 != 0) {
      pFVar2 = GetProcAddress(hModule,"GetProcessWindowStation");
      DAT_1000e88c = __encode_pointer((int)pFVar2);
    }
  }
  if ((DAT_1000e88c != iVar1) && (DAT_1000e890 != iVar1)) {
    pcVar3 = (code *)__decode_pointer(DAT_1000e88c);
    pcVar4 = (code *)__decode_pointer(DAT_1000e890);
    if (((pcVar3 != (code *)0x0) && (pcVar4 != (code *)0x0)) &&
       (((iVar5 = (*pcVar3)(), iVar5 == 0 ||
         (iVar5 = (*pcVar4)(iVar5,1,local_18,0xc,local_c), iVar5 == 0)) || ((local_10 & 1) == 0))))
    {
      _UType = _UType | 0x200000;
      goto LAB_10005b8d;
    }
  }
  if ((((DAT_1000e884 != iVar1) &&
       (pcVar3 = (code *)__decode_pointer(DAT_1000e884), pcVar3 != (code *)0x0)) &&
      (local_8 = (*pcVar3)(), local_8 != 0)) &&
     ((DAT_1000e888 != iVar1 &&
      (pcVar3 = (code *)__decode_pointer(DAT_1000e888), pcVar3 != (code *)0x0)))) {
    local_8 = (*pcVar3)(local_8);
  }
LAB_10005b8d:
  pcVar3 = (code *)__decode_pointer(DAT_1000e880);
  if (pcVar3 == (code *)0x0) {
    return 0;
  }
  iVar1 = (*pcVar3)(local_8,_LpText,_LpCaption,_UType);
  return iVar1;
}

