
/* Library Function - Single Match
    __unlock_fhandle
   
   Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release */

void __cdecl __unlock_fhandle(int _Filehandle)

{
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)
             ((&DAT_1000e9a0)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  return;
}

