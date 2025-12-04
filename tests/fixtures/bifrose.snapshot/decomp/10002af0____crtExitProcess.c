
/* Library Function - Single Match
    ___crtExitProcess
   
   Library: Visual Studio 2008 Release */

void __cdecl ___crtExitProcess(int param_1)

{
  ___crtCorExitProcess(param_1);
                    /* WARNING: Subroutine does not return */
  ExitProcess(param_1);
}

