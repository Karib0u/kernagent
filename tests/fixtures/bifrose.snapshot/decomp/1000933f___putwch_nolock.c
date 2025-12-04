
/* Library Function - Single Match
    __putwch_nolock
   
   Library: Visual Studio 2008 Release */

wint_t __cdecl __putwch_nolock(wchar_t _WCh)

{
  wint_t wVar1;
  BOOL BVar2;
  DWORD DVar3;
  UINT CodePage;
  wchar_t *lpWideCharStr;
  int cchWideChar;
  CHAR *lpMultiByteStr;
  int cbMultiByte;
  LPCSTR lpDefaultChar;
  LPBOOL lpUsedDefaultChar;
  DWORD local_14;
  CHAR local_10 [8];
  uint local_8;
  
  local_8 = DAT_1000d004 ^ (uint)&stack0xfffffffc;
  if (DAT_1000ddc0 != 0) {
    if (DAT_1000de84 == (HANDLE)0xfffffffe) {
      ___initconout();
    }
    if (DAT_1000de84 == (HANDLE)0xffffffff) goto LAB_100093eb;
    BVar2 = WriteConsoleW(DAT_1000de84,&_WCh,1,&local_14,(LPVOID)0x0);
    if (BVar2 != 0) {
      DAT_1000ddc0 = 1;
      goto LAB_100093eb;
    }
    if ((DAT_1000ddc0 != 2) || (DVar3 = GetLastError(), DVar3 != 0x78)) goto LAB_100093eb;
    DAT_1000ddc0 = 0;
  }
  lpUsedDefaultChar = (LPBOOL)0x0;
  lpDefaultChar = (LPCSTR)0x0;
  cbMultiByte = 5;
  lpMultiByteStr = local_10;
  cchWideChar = 1;
  lpWideCharStr = &_WCh;
  DVar3 = 0;
  CodePage = GetConsoleOutputCP();
  DVar3 = WideCharToMultiByte(CodePage,DVar3,lpWideCharStr,cchWideChar,lpMultiByteStr,cbMultiByte,
                              lpDefaultChar,lpUsedDefaultChar);
  if (DAT_1000de84 != (HANDLE)0xffffffff) {
    WriteConsoleA(DAT_1000de84,local_10,DVar3,&local_14,(LPVOID)0x0);
  }
LAB_100093eb:
  wVar1 = __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return wVar1;
}

