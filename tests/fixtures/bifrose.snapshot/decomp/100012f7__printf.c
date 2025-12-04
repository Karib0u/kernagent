
/* WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4 */
/* WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3 */
/* Library Function - Single Match
    _printf
   
   Library: Visual Studio 2008 Release */

int __cdecl _printf(char *_Format,...)

{
  int *piVar1;
  int iVar2;
  undefined **ppuVar3;
  int _Flag;
  _locale_t _Locale;
  va_list _ArgList;
  
  if (_Format == (char *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    iVar2 = -1;
  }
  else {
    ppuVar3 = FUN_100016f4();
    __lock_file2(1,ppuVar3 + 8);
    ppuVar3 = FUN_100016f4();
    _Flag = __stbuf((FILE *)(ppuVar3 + 8));
    _ArgList = &stack0x00000008;
    _Locale = (_locale_t)0x0;
    ppuVar3 = FUN_100016f4();
    iVar2 = __output_l((FILE *)(ppuVar3 + 8),_Format,_Locale,_ArgList);
    ppuVar3 = FUN_100016f4();
    __ftbuf(_Flag,(FILE *)(ppuVar3 + 8));
    FUN_10001393();
  }
  return iVar2;
}

