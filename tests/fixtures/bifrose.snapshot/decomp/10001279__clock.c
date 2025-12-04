
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    _clock
   
   Library: Visual Studio 2003 Release */

clock_t __cdecl _clock(void)

{
  longlong lVar1;
  undefined8 uVar2;
  _FILETIME local_c;
  
  GetSystemTimeAsFileTime(&local_c);
  lVar1 = __allmul(local_c.dwHighDateTime,0,0,1);
  lVar1 = (lVar1 - CONCAT44(_DAT_1000df04,_DAT_1000df00)) + (ulonglong)local_c.dwLowDateTime;
  uVar2 = __aulldiv((uint)lVar1,(uint)((ulonglong)lVar1 >> 0x20),10000,0);
  return (clock_t)uVar2;
}

