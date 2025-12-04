
/* Library Function - Single Match
    ___set_flsgetvalue
   
   Library: Visual Studio 2008 Release */

LPVOID ___set_flsgetvalue(void)

{
  LPVOID lpTlsValue;
  
  lpTlsValue = TlsGetValue(DAT_1000d51c);
  if (lpTlsValue == (LPVOID)0x0) {
    lpTlsValue = (LPVOID)__decode_pointer(DAT_1000e6a8);
    TlsSetValue(DAT_1000d51c,lpTlsValue);
  }
  return lpTlsValue;
}

