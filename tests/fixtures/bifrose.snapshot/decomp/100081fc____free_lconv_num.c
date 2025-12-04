
/* Library Function - Single Match
    ___free_lconv_num
   
   Library: Visual Studio 2008 Release */

void __cdecl ___free_lconv_num(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    if ((undefined *)*param_1 != PTR_DAT_1000dd58) {
      _free((undefined *)*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_1000dd5c) {
      _free((undefined *)param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_1000dd60) {
      _free((undefined *)param_1[2]);
    }
  }
  return;
}

