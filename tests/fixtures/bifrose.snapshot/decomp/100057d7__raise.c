
/* WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4 */
/* WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3 */
/* Library Function - Single Match
    _raise
   
   Library: Visual Studio 2008 Release */

int __cdecl _raise(int _SigNum)

{
  uint uVar1;
  int *piVar2;
  code *pcVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  _ptiddata p_Var7;
  int local_34;
  void *local_30;
  int local_28;
  int local_20;
  
  p_Var7 = (_ptiddata)0x0;
  local_20 = 0;
  if (_SigNum < 0xc) {
    if (_SigNum != 0xb) {
      if (_SigNum == 2) {
        puVar6 = &DAT_1000e854;
        iVar4 = DAT_1000e854;
        goto LAB_1000588c;
      }
      if (_SigNum != 4) {
        if (_SigNum == 6) goto LAB_1000586a;
        if (_SigNum != 8) goto LAB_1000584e;
      }
    }
    p_Var7 = __getptd_noexit();
    if (p_Var7 == (_ptiddata)0x0) {
      return -1;
    }
    uVar1 = siglookup((uint)p_Var7->_pxcptacttab);
    puVar6 = (undefined4 *)(uVar1 + 8);
    pcVar3 = (code *)*puVar6;
  }
  else {
    if (_SigNum == 0xf) {
      puVar6 = &DAT_1000e860;
      iVar4 = DAT_1000e860;
    }
    else if (_SigNum == 0x15) {
      puVar6 = &DAT_1000e858;
      iVar4 = DAT_1000e858;
    }
    else {
      if (_SigNum != 0x16) {
LAB_1000584e:
        piVar2 = __errno();
        *piVar2 = 0x16;
        __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        return -1;
      }
LAB_1000586a:
      puVar6 = &DAT_1000e85c;
      iVar4 = DAT_1000e85c;
    }
LAB_1000588c:
    local_20 = 1;
    pcVar3 = (code *)__decode_pointer(iVar4);
  }
  iVar4 = 0;
  if (pcVar3 == (code *)0x1) {
    return 0;
  }
  if (pcVar3 == (code *)0x0) {
    iVar4 = __exit(3);
  }
  if (local_20 != iVar4) {
    __lock(iVar4);
  }
  if (((_SigNum == 8) || (_SigNum == 0xb)) || (_SigNum == 4)) {
    local_30 = p_Var7->_tpxcptinfoptrs;
    p_Var7->_tpxcptinfoptrs = (void *)0x0;
    if (_SigNum == 8) {
      local_34 = p_Var7->_tfpecode;
      p_Var7->_tfpecode = 0x8c;
      goto LAB_100058f0;
    }
  }
  else {
LAB_100058f0:
    if (_SigNum == 8) {
      for (local_28 = DAT_1000d4c8; local_28 < DAT_1000d4cc + DAT_1000d4c8; local_28 = local_28 + 1)
      {
        *(undefined4 *)(local_28 * 0xc + 8 + (int)p_Var7->_pxcptacttab) = 0;
      }
      goto LAB_1000592a;
    }
  }
  uVar5 = __encoded_null();
  *puVar6 = uVar5;
LAB_1000592a:
  FUN_1000594b();
  if (_SigNum == 8) {
    (*pcVar3)(8,p_Var7->_tfpecode);
  }
  else {
    (*pcVar3)(_SigNum);
    if ((_SigNum != 0xb) && (_SigNum != 4)) {
      return 0;
    }
  }
  p_Var7->_tpxcptinfoptrs = local_30;
  if (_SigNum == 8) {
    p_Var7->_tfpecode = local_34;
  }
  return 0;
}

