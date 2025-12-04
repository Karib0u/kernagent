
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    ___inittime
   
   Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release */

undefined4 ___inittime(void)

{
  longlong lVar1;
  _FILETIME local_c;
  
  GetSystemTimeAsFileTime(&local_c);
  lVar1 = __allmul(local_c.dwHighDateTime,0,0,1);
  _DAT_1000df00 = lVar1 + (ulonglong)local_c.dwLowDateTime;
  return 0;
}

