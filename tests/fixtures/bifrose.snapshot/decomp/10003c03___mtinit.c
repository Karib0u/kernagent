
/* Library Function - Single Match
    __mtinit
   
   Library: Visual Studio 2008 Release */

int __cdecl __mtinit(void)

{
  HMODULE hModule;
  BOOL BVar1;
  int iVar2;
  code *pcVar3;
  _ptiddata _Ptd;
  DWORD DVar4;
  undefined1 *puVar5;
  _ptiddata p_Var6;
  
  hModule = GetModuleHandleW(L"KERNEL32.DLL");
  if (hModule == (HMODULE)0x0) {
    hModule = (HMODULE)__crt_waiting_on_module_handle(L"KERNEL32.DLL");
  }
  if (hModule != (HMODULE)0x0) {
    DAT_1000e6a4 = GetProcAddress(hModule,"FlsAlloc");
    DAT_1000e6a8 = GetProcAddress(hModule,"FlsGetValue");
    DAT_1000e6ac = GetProcAddress(hModule,"FlsSetValue");
    DAT_1000e6b0 = GetProcAddress(hModule,"FlsFree");
    if ((((DAT_1000e6a4 == (FARPROC)0x0) || (DAT_1000e6a8 == (FARPROC)0x0)) ||
        (DAT_1000e6ac == (FARPROC)0x0)) || (DAT_1000e6b0 == (FARPROC)0x0)) {
      DAT_1000e6a8 = TlsGetValue_exref;
      DAT_1000e6a4 = (FARPROC)&LAB_100038e0;
      DAT_1000e6ac = TlsSetValue_exref;
      DAT_1000e6b0 = TlsFree_exref;
    }
    DAT_1000d51c = TlsAlloc();
    if (DAT_1000d51c == 0xffffffff) {
      return 0;
    }
    BVar1 = TlsSetValue(DAT_1000d51c,DAT_1000e6a8);
    if (BVar1 == 0) {
      return 0;
    }
    __init_pointers();
    DAT_1000e6a4 = (FARPROC)__encode_pointer((int)DAT_1000e6a4);
    DAT_1000e6a8 = (FARPROC)__encode_pointer((int)DAT_1000e6a8);
    DAT_1000e6ac = (FARPROC)__encode_pointer((int)DAT_1000e6ac);
    DAT_1000e6b0 = (FARPROC)__encode_pointer((int)DAT_1000e6b0);
    iVar2 = __mtinitlocks();
    if (iVar2 != 0) {
      puVar5 = &LAB_10003ad4;
      pcVar3 = (code *)__decode_pointer((int)DAT_1000e6a4);
      DAT_1000d518 = (*pcVar3)(puVar5);
      if ((DAT_1000d518 != -1) && (_Ptd = (_ptiddata)__calloc_crt(1,0x214), _Ptd != (_ptiddata)0x0))
      {
        iVar2 = DAT_1000d518;
        p_Var6 = _Ptd;
        pcVar3 = (code *)__decode_pointer((int)DAT_1000e6ac);
        iVar2 = (*pcVar3)(iVar2,p_Var6);
        if (iVar2 != 0) {
          __initptd(_Ptd,(pthreadlocinfo)0x0);
          DVar4 = GetCurrentThreadId();
          _Ptd->_thandle = 0xffffffff;
          _Ptd->_tid = DVar4;
          return 1;
        }
      }
    }
  }
  __mtterm();
  return 0;
}

