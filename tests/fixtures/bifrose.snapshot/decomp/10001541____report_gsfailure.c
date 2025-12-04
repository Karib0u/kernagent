
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    ___report_gsfailure
   
   Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release */

void __cdecl ___report_gsfailure(void)

{
  undefined4 in_EAX;
  HANDLE hProcess;
  undefined4 in_ECX;
  undefined4 in_EDX;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined2 in_CS;
  undefined2 in_SS;
  undefined2 in_DS;
  undefined2 in_FS;
  undefined2 in_GS;
  byte in_AF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined4 unaff_retaddr;
  UINT uExitCode;
  undefined4 local_32c;
  undefined4 local_328;
  
  _DAT_1000e030 =
       (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4((int)&stack0xfffffffc,0x328) * 0x800 |
       (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)&local_32c < 0) * 0x80 |
       (uint)(&stack0x00000000 == (undefined1 *)0x32c) * 0x40 | (uint)(in_AF & 1) * 0x10 |
       (uint)((POPCOUNT((uint)&local_32c & 0xff) & 1U) == 0) * 4 |
       (uint)(&stack0xfffffffc < (undefined1 *)0x328) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  _DAT_1000e034 = &stack0x00000004;
  _DAT_1000df70 = 0x10001;
  _DAT_1000df18 = 0xc0000409;
  _DAT_1000df1c = 1;
  local_32c = DAT_1000d004;
  local_328 = DAT_1000d008;
  _DAT_1000df24 = unaff_retaddr;
  _DAT_1000dffc = in_GS;
  _DAT_1000e000 = in_FS;
  _DAT_1000e004 = in_ES;
  _DAT_1000e008 = in_DS;
  _DAT_1000e00c = unaff_EDI;
  _DAT_1000e010 = unaff_ESI;
  _DAT_1000e014 = unaff_EBX;
  _DAT_1000e018 = in_EDX;
  _DAT_1000e01c = in_ECX;
  _DAT_1000e020 = in_EAX;
  _DAT_1000e024 = unaff_EBP;
  DAT_1000e028 = unaff_retaddr;
  _DAT_1000e02c = in_CS;
  _DAT_1000e038 = in_SS;
  DAT_1000df68 = IsDebuggerPresent();
  FUN_10003e56();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&PTR_DAT_1000a18c);
  if (DAT_1000df68 == 0) {
    FUN_10003e56();
  }
  uExitCode = 0xc0000409;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}

