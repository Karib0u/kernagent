
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* Library Function - Single Match
    __stbuf
   
   Library: Visual Studio 2008 Release */

int __cdecl __stbuf(FILE *_File)

{
  int *piVar1;
  char *pcVar2;
  int iVar3;
  undefined **ppuVar4;
  void *pvVar5;
  
  iVar3 = __fileno(_File);
  iVar3 = __isatty(iVar3);
  if (iVar3 == 0) {
    return 0;
  }
  ppuVar4 = FUN_100016f4();
  if (_File == (FILE *)(ppuVar4 + 8)) {
    iVar3 = 0;
  }
  else {
    ppuVar4 = FUN_100016f4();
    if (_File != (FILE *)(ppuVar4 + 0x10)) {
      return 0;
    }
    iVar3 = 1;
  }
  _DAT_1000e23c = _DAT_1000e23c + 1;
  if ((_File->_flag & 0x10cU) != 0) {
    return 0;
  }
  piVar1 = &DAT_1000e240 + iVar3;
  if (*piVar1 == 0) {
    pvVar5 = __malloc_crt(0x1000);
    *piVar1 = (int)pvVar5;
    if (pvVar5 == (void *)0x0) {
      _File->_base = (char *)&_File->_charbuf;
      _File->_ptr = (char *)&_File->_charbuf;
      _File->_bufsiz = 2;
      _File->_cnt = 2;
      goto LAB_10001932;
    }
  }
  pcVar2 = (char *)*piVar1;
  _File->_base = pcVar2;
  _File->_ptr = pcVar2;
  _File->_bufsiz = 0x1000;
  _File->_cnt = 0x1000;
LAB_10001932:
  _File->_flag = _File->_flag | 0x1102;
  return 1;
}

