
/* Library Function - Single Match
    __mtterm
   
   Library: Visual Studio 2008 Release */

void __cdecl __mtterm(void)

{
  code *pcVar1;
  int iVar2;
  
  if (DAT_1000d518 != -1) {
    iVar2 = DAT_1000d518;
    pcVar1 = (code *)__decode_pointer(DAT_1000e6b0);
    (*pcVar1)(iVar2);
    DAT_1000d518 = -1;
  }
  if (DAT_1000d51c != 0xffffffff) {
    TlsFree(DAT_1000d51c);
    DAT_1000d51c = 0xffffffff;
  }
  __mtdeletelocks();
  return;
}

