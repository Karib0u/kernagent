
/* Library Function - Single Match
    __lock_file
   
   Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release */

void __cdecl __lock_file(FILE *_File)

{
  if ((_File < &PTR_DAT_1000d010) || ((FILE *)&DAT_1000d270 < _File)) {
    EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  }
  else {
    __lock(((int)&_File[-0x800681]._file >> 5) + 0x10);
    _File->_flag = _File->_flag | 0x8000;
  }
  return;
}

