
/* WARNING: Type propagation algorithm not settling */
/* Library Function - Single Match
    __output_l
   
   Library: Visual Studio 2008 Release */

int __cdecl __output_l(FILE *_File,char *_Format,_locale_t _Locale,va_list _ArgList)

{
  byte bVar1;
  wchar_t _WCh;
  short *psVar2;
  int *piVar3;
  uint uVar4;
  int iVar5;
  code *pcVar6;
  errno_t eVar7;
  int iVar8;
  undefined *puVar9;
  int extraout_ECX;
  uint uVar10;
  byte *pbVar11;
  size_t sVar12;
  wchar_t *pwVar13;
  bool bVar14;
  undefined8 uVar15;
  undefined4 *puVar16;
  wchar_t *pwVar17;
  undefined4 uVar18;
  localeinfo_struct *plVar19;
  undefined4 local_27c;
  undefined4 local_278;
  undefined4 local_274;
  int local_270;
  int local_26c [2];
  size_t local_264;
  localeinfo_struct local_260;
  int local_258;
  char local_254;
  FILE *local_250;
  int local_24c;
  wchar_t *local_248;
  int local_244;
  byte *local_240;
  int local_23c;
  int local_238;
  int local_234;
  undefined1 local_230;
  char local_22f;
  int local_22c;
  wchar_t *local_228;
  size_t local_224;
  wchar_t *local_220;
  int local_21c;
  byte local_215;
  uint local_214;
  wchar_t local_210 [255];
  undefined2 local_11;
  uint local_8;
  
  local_8 = DAT_1000d004 ^ (uint)&stack0xfffffffc;
  local_250 = _File;
  local_228 = (wchar_t *)_ArgList;
  local_24c = 0;
  local_214 = 0;
  local_238 = 0;
  local_21c = 0;
  local_234 = 0;
  local_244 = 0;
  local_23c = 0;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_260,_Locale);
  if (_File != (FILE *)0x0) {
    if ((_File->_flag & 0x40) == 0) {
      uVar4 = __fileno(_File);
      if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
        puVar9 = &DAT_1000d4d8;
      }
      else {
        puVar9 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_1000e9a0)[(int)uVar4 >> 5]);
      }
      if ((puVar9[0x24] & 0x7f) == 0) {
        if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
          puVar9 = &DAT_1000d4d8;
        }
        else {
          puVar9 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_1000e9a0)[(int)uVar4 >> 5]);
        }
        if ((puVar9[0x24] & 0x80) == 0) goto LAB_10001baa;
      }
    }
    else {
LAB_10001baa:
      if (_Format != (char *)0x0) {
        local_215 = *_Format;
        local_22c = 0;
        local_224 = 0;
        local_248 = (wchar_t *)0x0;
        iVar8 = 0;
        while ((local_215 != 0 &&
               (pbVar11 = (byte *)_Format + 1, local_240 = pbVar11, -1 < local_22c))) {
          if ((byte)(local_215 - 0x20) < 0x59) {
            uVar4 = (int)*(char *)((int)&PTR_DAT_1000a190 + (int)(char)local_215) & 0xf;
          }
          else {
            uVar4 = 0;
          }
          local_270 = (int)(char)(&DAT_1000a1b0)[uVar4 * 8 + iVar8] >> 4;
          switch(local_270) {
          case 0:
switchD_10001c23_caseD_0:
            local_23c = 0;
            iVar8 = __isleadbyte_l((uint)local_215,&local_260);
            if (iVar8 != 0) {
              write_char();
              local_240 = (byte *)_Format + 2;
              if (*pbVar11 == 0) goto LAB_10001b11;
            }
            write_char();
            break;
          case 1:
            local_21c = -1;
            local_274 = 0;
            local_244 = 0;
            local_238 = 0;
            local_234 = 0;
            local_214 = 0;
            local_23c = 0;
            break;
          case 2:
            if (local_215 == 0x20) {
              local_214 = local_214 | 2;
            }
            else if (local_215 == 0x23) {
              local_214 = local_214 | 0x80;
            }
            else if (local_215 == 0x2b) {
              local_214 = local_214 | 1;
            }
            else if (local_215 == 0x2d) {
              local_214 = local_214 | 4;
            }
            else if (local_215 == 0x30) {
              local_214 = local_214 | 8;
            }
            break;
          case 3:
            if (local_215 == 0x2a) {
              local_228 = (wchar_t *)((int)_ArgList + 4);
              local_238 = *(int *)_ArgList;
              if (local_238 < 0) {
                local_214 = local_214 | 4;
                local_238 = -local_238;
              }
            }
            else {
              local_238 = local_238 * 10 + -0x30 + (int)(char)local_215;
            }
            break;
          case 4:
            local_21c = 0;
            break;
          case 5:
            if (local_215 == 0x2a) {
              local_228 = (wchar_t *)((int)_ArgList + 4);
              local_21c = *(int *)_ArgList;
              if (local_21c < 0) {
                local_21c = -1;
              }
            }
            else {
              local_21c = local_21c * 10 + -0x30 + (int)(char)local_215;
            }
            break;
          case 6:
            if (local_215 == 0x49) {
              bVar1 = *pbVar11;
              if ((bVar1 == 0x36) && (((byte *)_Format)[2] == 0x34)) {
                local_214 = local_214 | 0x8000;
                local_240 = (byte *)_Format + 3;
              }
              else if ((bVar1 == 0x33) && (((byte *)_Format)[2] == 0x32)) {
                local_214 = local_214 & 0xffff7fff;
                local_240 = (byte *)_Format + 3;
              }
              else if (((((bVar1 != 100) && (bVar1 != 0x69)) && (bVar1 != 0x6f)) &&
                       ((bVar1 != 0x75 && (bVar1 != 0x78)))) && (bVar1 != 0x58)) {
                local_270 = 0;
                goto switchD_10001c23_caseD_0;
              }
            }
            else if (local_215 == 0x68) {
              local_214 = local_214 | 0x20;
            }
            else if (local_215 == 0x6c) {
              if (*pbVar11 == 0x6c) {
                local_214 = local_214 | 0x1000;
                local_240 = (byte *)_Format + 2;
              }
              else {
                local_214 = local_214 | 0x10;
              }
            }
            else if (local_215 == 0x77) {
              local_214 = local_214 | 0x800;
            }
            break;
          case 7:
            if ((char)local_215 < 'e') {
              if (local_215 == 100) {
LAB_1000210e:
                local_214 = local_214 | 0x40;
LAB_10002115:
                local_224 = 10;
LAB_1000211f:
                if (((local_214 & 0x8000) == 0) && ((local_214 & 0x1000) == 0)) {
                  local_228 = (wchar_t *)((int)_ArgList + 4);
                  if ((local_214 & 0x20) == 0) {
                    uVar4 = *(uint *)_ArgList;
                    if ((local_214 & 0x40) == 0) {
                      uVar10 = 0;
                    }
                    else {
                      uVar10 = (int)uVar4 >> 0x1f;
                    }
                  }
                  else {
                    if ((local_214 & 0x40) == 0) {
                      uVar4 = (uint)(ushort)*(wchar_t *)_ArgList;
                    }
                    else {
                      uVar4 = (uint)*(wchar_t *)_ArgList;
                    }
                    uVar10 = (int)uVar4 >> 0x1f;
                  }
                }
                else {
                  uVar4 = *(uint *)_ArgList;
                  uVar10 = *(uint *)((int)_ArgList + 4);
                  local_228 = (wchar_t *)((int)_ArgList + 8);
                }
                if ((((local_214 & 0x40) != 0) && ((int)uVar10 < 1)) && ((int)uVar10 < 0)) {
                  bVar14 = uVar4 != 0;
                  uVar4 = -uVar4;
                  uVar10 = -(uVar10 + bVar14);
                  local_214 = local_214 | 0x100;
                }
                uVar15 = CONCAT44(uVar10,uVar4);
                if ((local_214 & 0x9000) == 0) {
                  uVar10 = 0;
                }
                if (local_21c < 0) {
                  local_21c = 1;
                }
                else {
                  local_214 = local_214 & 0xfffffff7;
                  if (0x200 < local_21c) {
                    local_21c = 0x200;
                  }
                }
                if (uVar4 == 0 && uVar10 == 0) {
                  local_234 = 0;
                }
                pwVar13 = &local_11;
                while( true ) {
                  uVar4 = uVar10;
                  iVar8 = local_21c + -1;
                  if ((local_21c < 1) && ((uint)uVar15 == 0 && uVar4 == 0)) break;
                  local_21c = iVar8;
                  uVar15 = __aulldvrm((uint)uVar15,uVar4,local_224,(int)local_224 >> 0x1f);
                  iVar8 = extraout_ECX + 0x30;
                  if (0x39 < iVar8) {
                    iVar8 = iVar8 + local_24c;
                  }
                  *(char *)pwVar13 = (char)iVar8;
                  pwVar13 = (wchar_t *)((int)pwVar13 + -1);
                  uVar10 = (uint)((ulonglong)uVar15 >> 0x20);
                  local_264 = uVar4;
                }
                local_224 = (int)&local_11 + -(int)pwVar13;
                local_220 = (wchar_t *)((int)pwVar13 + 1);
                local_21c = iVar8;
                if (((local_214 & 0x200) != 0) && ((local_224 == 0 || (*(char *)local_220 != '0'))))
                {
                  *(char *)pwVar13 = '0';
                  local_224 = (int)&local_11 + -(int)pwVar13 + 1;
                  local_220 = pwVar13;
                }
              }
              else if ((char)local_215 < 'T') {
                if (local_215 == 0x53) {
                  if ((local_214 & 0x830) == 0) {
                    local_214 = local_214 | 0x800;
                  }
                  goto LAB_10001f3a;
                }
                if (local_215 == 0x41) {
LAB_10001eb9:
                  local_215 = local_215 + 0x20;
                  local_274 = 1;
LAB_10001ecc:
                  local_214 = local_214 | 0x40;
                  local_264 = 0x200;
                  pwVar13 = local_210;
                  sVar12 = local_264;
                  pwVar17 = local_210;
                  if (local_21c < 0) {
                    local_21c = 6;
                  }
                  else if (local_21c == 0) {
                    if (local_215 == 0x67) {
                      local_21c = 1;
                    }
                  }
                  else {
                    if (0x200 < local_21c) {
                      local_21c = 0x200;
                    }
                    if (0xa3 < local_21c) {
                      sVar12 = local_21c + 0x15d;
                      local_220 = local_210;
                      local_248 = (wchar_t *)__malloc_crt(sVar12);
                      pwVar13 = local_248;
                      pwVar17 = local_248;
                      if (local_248 == (wchar_t *)0x0) {
                        local_21c = 0xa3;
                        pwVar13 = local_210;
                        sVar12 = local_264;
                        pwVar17 = local_220;
                      }
                    }
                  }
                  local_220 = pwVar17;
                  local_264 = sVar12;
                  local_27c = *(undefined4 *)_ArgList;
                  local_228 = (wchar_t *)((int)_ArgList + 8);
                  local_278 = *(undefined4 *)((int)_ArgList + 4);
                  plVar19 = &local_260;
                  iVar5 = (int)(char)local_215;
                  puVar16 = &local_27c;
                  pwVar17 = pwVar13;
                  sVar12 = local_264;
                  iVar8 = local_21c;
                  uVar18 = local_274;
                  pcVar6 = (code *)__decode_pointer((int)PTR_LAB_1000dc78);
                  (*pcVar6)(puVar16,pwVar17,sVar12,iVar5,iVar8,uVar18,plVar19);
                  uVar4 = local_214 & 0x80;
                  if ((uVar4 != 0) && (local_21c == 0)) {
                    plVar19 = &local_260;
                    pwVar17 = pwVar13;
                    pcVar6 = (code *)__decode_pointer((int)PTR_LAB_1000dc84);
                    (*pcVar6)(pwVar17,plVar19);
                  }
                  if ((local_215 == 0x67) && (uVar4 == 0)) {
                    plVar19 = &local_260;
                    pwVar17 = pwVar13;
                    pcVar6 = (code *)__decode_pointer((int)PTR_LAB_1000dc80);
                    (*pcVar6)(pwVar17,plVar19);
                  }
                  if ((char)*pwVar13 == '-') {
                    local_214 = local_214 | 0x100;
                    local_220 = (wchar_t *)((int)pwVar13 + 1);
                    pwVar13 = local_220;
                  }
LAB_1000206c:
                  local_224 = _strlen((char *)pwVar13);
                }
                else if (local_215 == 0x43) {
                  if ((local_214 & 0x830) == 0) {
                    local_214 = local_214 | 0x800;
                  }
LAB_10001fad:
                  local_228 = (wchar_t *)((int)_ArgList + 4);
                  if ((local_214 & 0x810) == 0) {
                    local_210[0]._0_1_ = (char)*(wchar_t *)_ArgList;
                    local_224 = 1;
                  }
                  else {
                    eVar7 = _wctomb_s((int *)&local_224,(char *)local_210,0x200,*(wchar_t *)_ArgList
                                     );
                    if (eVar7 != 0) {
                      local_244 = 1;
                    }
                  }
                  local_220 = local_210;
                }
                else if ((local_215 == 0x45) || (local_215 == 0x47)) goto LAB_10001eb9;
              }
              else {
                if (local_215 == 0x58) goto LAB_10002273;
                if (local_215 == 0x5a) {
                  psVar2 = *(short **)_ArgList;
                  local_228 = (wchar_t *)((int)_ArgList + 4);
                  pwVar13 = (wchar_t *)PTR_s__null__1000d290;
                  local_220 = (wchar_t *)PTR_s__null__1000d290;
                  if ((psVar2 == (short *)0x0) ||
                     (pwVar17 = *(wchar_t **)(psVar2 + 2), pwVar17 == (wchar_t *)0x0))
                  goto LAB_1000206c;
                  local_224 = (size_t)*psVar2;
                  local_220 = pwVar17;
                  if ((local_214 & 0x800) == 0) {
                    local_23c = 0;
                  }
                  else {
                    local_224 = (int)local_224 / 2;
                    local_23c = 1;
                  }
                }
                else {
                  if (local_215 == 0x61) goto LAB_10001ecc;
                  if (local_215 == 99) goto LAB_10001fad;
                }
              }
LAB_1000244b:
              if (local_244 == 0) {
                if ((local_214 & 0x40) != 0) {
                  if ((local_214 & 0x100) == 0) {
                    if ((local_214 & 1) == 0) {
                      if ((local_214 & 2) == 0) goto LAB_10002494;
                      local_230 = 0x20;
                    }
                    else {
                      local_230 = 0x2b;
                    }
                  }
                  else {
                    local_230 = 0x2d;
                  }
                  local_234 = 1;
                }
LAB_10002494:
                iVar8 = (local_238 - local_224) - local_234;
                if ((local_214 & 0xc) == 0) {
                  write_multi_char(0x20,iVar8);
                }
                write_string(local_234);
                if (((local_214 & 8) != 0) && ((local_214 & 4) == 0)) {
                  write_multi_char(0x30,iVar8);
                }
                if ((local_23c == 0) || ((int)local_224 < 1)) {
                  write_string(local_224);
                }
                else {
                  local_264 = local_224;
                  pwVar13 = local_220;
                  do {
                    _WCh = *pwVar13;
                    local_264 = local_264 - 1;
                    pwVar13 = pwVar13 + 1;
                    eVar7 = _wctomb_s(local_26c,(char *)((int)&local_11 + 1),6,_WCh);
                    if ((eVar7 != 0) || (local_26c[0] == 0)) {
                      local_22c = -1;
                      break;
                    }
                    write_string(local_26c[0]);
                  } while (local_264 != 0);
                }
                if ((-1 < local_22c) && ((local_214 & 4) != 0)) {
                  write_multi_char(0x20,iVar8);
                }
              }
            }
            else {
              if ('p' < (char)local_215) {
                if (local_215 == 0x73) {
LAB_10001f3a:
                  iVar8 = local_21c;
                  if (local_21c == -1) {
                    iVar8 = 0x7fffffff;
                  }
                  local_228 = (wchar_t *)((int)_ArgList + 4);
                  local_220 = *(wchar_t **)_ArgList;
                  if ((local_214 & 0x810) == 0) {
                    pwVar13 = local_220;
                    if (local_220 == (wchar_t *)0x0) {
                      pwVar13 = (wchar_t *)PTR_s__null__1000d290;
                      local_220 = (wchar_t *)PTR_s__null__1000d290;
                    }
                    for (; (iVar8 != 0 && (iVar8 = iVar8 + -1, (char)*pwVar13 != '\0'));
                        pwVar13 = (wchar_t *)((int)pwVar13 + 1)) {
                    }
                    local_224 = (int)pwVar13 - (int)local_220;
                  }
                  else {
                    if (local_220 == (wchar_t *)0x0) {
                      local_220 = (wchar_t *)PTR_u__null__1000d294;
                    }
                    local_23c = 1;
                    for (pwVar13 = local_220;
                        (iVar8 != 0 && (iVar8 = iVar8 + -1, *pwVar13 != L'\0'));
                        pwVar13 = pwVar13 + 1) {
                    }
                    local_224 = (int)pwVar13 - (int)local_220 >> 1;
                  }
                  goto LAB_1000244b;
                }
                if (local_215 == 0x75) goto LAB_10002115;
                if (local_215 != 0x78) goto LAB_1000244b;
                local_24c = 0x27;
LAB_1000229f:
                local_224 = 0x10;
                if ((local_214 & 0x80) != 0) {
                  local_22f = (char)local_24c + 'Q';
                  local_230 = 0x30;
                  local_234 = 2;
                }
                goto LAB_1000211f;
              }
              if (local_215 == 0x70) {
                local_21c = 8;
LAB_10002273:
                local_24c = 7;
                goto LAB_1000229f;
              }
              if ((char)local_215 < 'e') goto LAB_1000244b;
              if ((char)local_215 < 'h') goto LAB_10001ecc;
              if (local_215 == 0x69) goto LAB_1000210e;
              if (local_215 != 0x6e) {
                if (local_215 != 0x6f) goto LAB_1000244b;
                local_224 = 8;
                if ((local_214 & 0x80) != 0) {
                  local_214 = local_214 | 0x200;
                }
                goto LAB_1000211f;
              }
              piVar3 = *(int **)_ArgList;
              local_228 = (wchar_t *)((int)_ArgList + 4);
              iVar8 = __get_printf_count_output();
              if (iVar8 == 0) goto LAB_10001b11;
              if ((local_214 & 0x20) == 0) {
                *piVar3 = local_22c;
              }
              else {
                *(undefined2 *)piVar3 = (undefined2)local_22c;
              }
              local_244 = 1;
            }
            if (local_248 != (wchar_t *)0x0) {
              _free(local_248);
              local_248 = (wchar_t *)0x0;
            }
          }
          local_215 = *local_240;
          iVar8 = local_270;
          _Format = (char *)local_240;
          _ArgList = (va_list)local_228;
        }
        if (local_254 != '\0') {
          *(uint *)(local_258 + 0x70) = *(uint *)(local_258 + 0x70) & 0xfffffffd;
        }
        goto LAB_1000260e;
      }
    }
  }
LAB_10001b11:
  piVar3 = __errno();
  *piVar3 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  if (local_254 != '\0') {
    *(uint *)(local_258 + 0x70) = *(uint *)(local_258 + 0x70) & 0xfffffffd;
  }
LAB_1000260e:
  iVar8 = __security_check_cookie(local_8 ^ (uint)&stack0xfffffffc);
  return iVar8;
}

