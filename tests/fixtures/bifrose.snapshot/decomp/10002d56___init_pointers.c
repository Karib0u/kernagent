
/* Library Function - Single Match
    __init_pointers
   
   Library: Visual Studio 2008 Release */

void __cdecl __init_pointers(void)

{
  undefined4 uVar1;
  
  uVar1 = __encoded_null();
  FUN_10005a14(uVar1);
  FUN_100059a5(uVar1);
  FUN_1000263e(uVar1);
  FUN_10005996(uVar1);
  FUN_10005987(uVar1);
  __initp_misc_winsig(uVar1);
  FUN_10002f88();
  __initp_eh_hooks();
  PTR___exit_1000d408 = (undefined *)__encode_pointer(0x10002d22);
  return;
}

