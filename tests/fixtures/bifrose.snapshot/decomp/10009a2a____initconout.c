
/* Library Function - Single Match
    ___initconout
   
   Library: Visual Studio 2008 Release */

void __cdecl ___initconout(void)

{
  DAT_1000de84 = CreateFileA("CONOUT$",0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  return;
}

