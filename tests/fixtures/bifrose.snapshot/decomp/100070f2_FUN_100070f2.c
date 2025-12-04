
/* WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4 */
/* WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3 */

int __cdecl FUN_100070f2(FILE *param_1)

{
  int *piVar1;
  int local_20;
  
  local_20 = -1;
  if (param_1 == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    local_20 = -1;
  }
  else if ((param_1->_flag & 0x40) == 0) {
    __lock_file(param_1);
    local_20 = __fclose_nolock(param_1);
    FUN_10007166();
  }
  else {
    param_1->_flag = 0;
  }
  return local_20;
}

