
/* Library Function - Single Match
    ___initmbctable
   
   Library: Visual Studio 2008 Release */

undefined4 ___initmbctable(void)

{
  if (DAT_1000eaac == 0) {
    __setmbcp(-3);
    DAT_1000eaac = 1;
  }
  return 0;
}

