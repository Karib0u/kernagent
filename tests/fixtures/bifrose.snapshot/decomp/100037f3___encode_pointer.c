
/* Library Function - Single Match
    __encode_pointer
   
   Library: Visual Studio 2008 Release */

int __cdecl __encode_pointer(int param_1)

{
  LPVOID pvVar1;
  code *pcVar2;
  int iVar3;
  HMODULE hModule;
  FARPROC pFVar4;
  
  pvVar1 = TlsGetValue(DAT_1000d51c);
  if ((pvVar1 != (LPVOID)0x0) && (DAT_1000d518 != -1)) {
    iVar3 = DAT_1000d518;
    pcVar2 = (code *)TlsGetValue(DAT_1000d51c);
    iVar3 = (*pcVar2)(iVar3);
    if (iVar3 != 0) {
      pFVar4 = *(FARPROC *)(iVar3 + 0x1f8);
      goto LAB_10003853;
    }
  }
  hModule = GetModuleHandleW(L"KERNEL32.DLL");
  if ((hModule == (HMODULE)0x0) &&
     (hModule = (HMODULE)__crt_waiting_on_module_handle(L"KERNEL32.DLL"), hModule == (HMODULE)0x0))
  {
    return param_1;
  }
  pFVar4 = GetProcAddress(hModule,"EncodePointer");
LAB_10003853:
  if (pFVar4 != (FARPROC)0x0) {
    param_1 = (*pFVar4)(param_1);
  }
  return param_1;
}

