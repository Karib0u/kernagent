
/* WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4 */
/* WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3 */

int FUN_10003fcb(void)

{
  FILE *pFVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int local_20;
  
  local_20 = 0;
  __lock(1);
  for (iVar4 = 3; iVar4 < DAT_1000fac0; iVar4 = iVar4 + 1) {
    iVar3 = iVar4 * 4;
    if (*(int *)(DAT_1000eabc + iVar3) != 0) {
      pFVar1 = *(FILE **)(DAT_1000eabc + iVar3);
      if ((pFVar1->_flag & 0x83) != 0) {
        iVar2 = FUN_100070f2(pFVar1);
        if (iVar2 != -1) {
          local_20 = local_20 + 1;
        }
      }
      if (0x13 < iVar4) {
        DeleteCriticalSection((LPCRITICAL_SECTION)(*(int *)(iVar3 + DAT_1000eabc) + 0x20));
        _free(*(void **)(iVar3 + DAT_1000eabc));
        *(undefined4 *)(iVar3 + DAT_1000eabc) = 0;
      }
    }
  }
  FUN_10004061();
  return local_20;
}

