int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  LPCWSTR *v4; // ecx
  unsigned int v5; // edi
  int v6; // eax
  HANDLE hProcess; // ecx
  const WCHAR *v8; // eax
  HANDLE FileW; // esi
  LPCWSTR *v10; // eax
  DWORD v11; // edi
  __int128 v12; // xmm0
  unsigned int v13; // esi
  unsigned int v14; // ecx
  int v15; // eax
  int v16; // eax
  unsigned int v17; // ecx
  const WCHAR *CommandLineW; // eax
  LPWSTR *v19; // eax
  int v20; // esi
  const unsigned __int16 *v21; // edx
  _DWORD *v22; // eax
  _DWORD *v23; // edx
  unsigned int v24; // ecx
  unsigned int v25; // edi
  __int128 *v26; // esi
  int v27; // ecx
  HANDLE v28; // ecx
  int v29; // eax
  struct _PROCESS_INFORMATION *p_ProcessInformation; // edx
  struct _PROCESS_INFORMATION v31; // xmm1
  __int64 v32; // xmm0_8
  int v33; // eax
  int v34; // edi
  __int128 *v35; // esi
  char *v36; // ecx
  char *v37; // eax
  int v38; // ecx
  int v39; // ecx
  __int128 *v40; // eax
  WCHAR *v41; // eax
  LPCWSTR *v42; // ecx
  WCHAR *v43; // esi
  const WCHAR *v44; // eax
  const WCHAR *v45; // eax
  const WCHAR *v46; // eax
  int v47; // ecx
  LPCWSTR v48; // ecx
  LPCWSTR v49; // ecx
  char v51; // [esp-18h] [ebp-358h]
  char v52; // [esp-18h] [ebp-358h]
  int v53; // [esp+8h] [ebp-338h]
  char *v54; // [esp+8h] [ebp-338h]
  int v55[4]; // [esp+Ch] [ebp-334h] BYREF
  int v56; // [esp+1Ch] [ebp-324h]
  unsigned int v57; // [esp+20h] [ebp-320h]
  DWORD v58; // [esp+24h] [ebp-31Ch]
  int v59; // [esp+28h] [ebp-318h]
  int v60; // [esp+38h] [ebp-308h]
  unsigned int v61; // [esp+3Ch] [ebp-304h]
  struct _PROCESS_INFORMATION ProcessInformation; // [esp+40h] [ebp-300h] BYREF
  __int64 v63; // [esp+50h] [ebp-2F0h]
  DWORD ExitCode; // [esp+68h] [ebp-2D8h] BYREF
  DWORD NumberOfBytesWritten; // [esp+6Ch] [ebp-2D4h] BYREF
  __int128 v66; // [esp+70h] [ebp-2D0h] BYREF
  DWORD v67; // [esp+80h] [ebp-2C0h]
  unsigned int v68; // [esp+84h] [ebp-2BCh]
  int pNumArgs; // [esp+9Ch] [ebp-2A4h] BYREF
  LPCWSTR lpFileName[4]; // [esp+A0h] [ebp-2A0h] BYREF
  __int64 v71; // [esp+B0h] [ebp-290h]
  LPCWSTR lpPathName[4]; // [esp+C8h] [ebp-278h] BYREF
  unsigned int v73; // [esp+D8h] [ebp-268h]
  unsigned int v74; // [esp+DCh] [ebp-264h]
  struct _STARTUPINFOW StartupInfo; // [esp+E0h] [ebp-260h] BYREF
  WCHAR Filename[266]; // [esp+128h] [ebp-218h] BYREF

  sub_401030();
  v63 = 0x700000000i64;
  LOWORD(ProcessInformation.hProcess) = 0;
  sub_4022C0(v73 + 1);
  v4 = lpPathName;
  if ( v74 >= 8 )
    v4 = (LPCWSTR *)lpPathName[0];
  v5 = v73;
  NumberOfBytesWritten = v63;
  if ( v73 > HIDWORD(v63) - (int)v63 )
  {
    LOBYTE(NumberOfBytesWritten) = 0;
    sub_402130(v73, NumberOfBytesWritten, v4, v73);
  }
  else
  {
    LODWORD(v63) = v63 + v73;
    sub_405110(&ProcessInformation, v4, 2 * v73);
    *((_WORD *)&ProcessInformation.hProcess + v5 + NumberOfBytesWritten) = 0;
  }
  sub_402360(L"\\");
  v6 = sub_402360(&off_413C88);
  *(_OWORD *)lpFileName = *(_OWORD *)v6;
  v71 = *(_QWORD *)(v6 + 16);
  *(_DWORD *)(v6 + 16) = 0;
  *(_DWORD *)(v6 + 20) = 7;
  *(_WORD *)v6 = 0;
  if ( HIDWORD(v63) >= 8 )
  {
    hProcess = ProcessInformation.hProcess;
    if ( (unsigned int)(2 * HIDWORD(v63) + 2) >= 0x1000 )
    {
      hProcess = (HANDLE)*((_DWORD *)ProcessInformation.hProcess - 1);
      if ( (unsigned int)(ProcessInformation.hProcess - hProcess - 4) > 0x1F )
LABEL_94:
        sub_405F00();
    }
    sub_4027ED(hProcess);
  }
  v8 = (const WCHAR *)lpFileName;
  if ( HIDWORD(v71) >= 8 )
    v8 = lpFileName[0];
  FileW = CreateFileW(v8, 0x40000000u, 4u, 0, 2u, 0x80u, 0);
  if ( FileW == (HANDLE)-1 )
  {
    sub_401E60(&off_413BC8);
    sub_401000(v51);
  }
  WriteFile(FileW, &unk_413D50, (DWORD)aDTextAndTheBra, &NumberOfBytesWritten, 0);
  CloseHandle(FileW);
  if ( (char *)NumberOfBytesWritten != aDTextAndTheBra )
  {
    sub_401E60(&off_413BF0);
    sub_401000(v51);
  }
  v10 = lpFileName;
  v11 = v71;
  if ( HIDWORD(v71) >= 8 )
    v10 = (LPCWSTR *)lpFileName[0];
  v67 = 0;
  v68 = 0;
  NumberOfBytesWritten = (DWORD)v10;
  if ( (unsigned int)v71 < 8 )
  {
    v12 = *(_OWORD *)v10;
    v68 = 7;
    v66 = v12;
    goto LABEL_31;
  }
  v13 = v71 | 7;
  if ( ((unsigned int)v71 | 7) > 0x7FFFFFFE )
    v13 = 2147483646;
  v14 = 2 * (v13 + 1);
  if ( v13 + 1 > 0x7FFFFFFF )
  {
    v14 = -1;
LABEL_23:
    v15 = v14 + 35;
    if ( v14 + 35 <= v14 )
      v15 = -1;
    v16 = sub_4027FB(v15);
    if ( !v16 )
      goto LABEL_101;
    v17 = (v16 + 35) & 0xFFFFFFE0;
    *(_DWORD *)(v17 - 4) = v16;
    goto LABEL_30;
  }
  if ( v14 >= 0x1000 )
    goto LABEL_23;
  if ( v14 )
    v17 = sub_4027FB(2 * (v13 + 1));
  else
    v17 = 0;
LABEL_30:
  LODWORD(v66) = v17;
  sub_4057D0(v17, NumberOfBytesWritten, 2 * v11 + 2);
  v68 = v13;
LABEL_31:
  v67 = v11;
  CommandLineW = GetCommandLineW();
  v19 = CommandLineToArgvW(CommandLineW, &pNumArgs);
  ExitCode = (DWORD)v19;
  if ( !v19 )
  {
    sub_401E60(&off_413CAC);
    sub_401000(v51);
  }
  v20 = 1;
  NumberOfBytesWritten = 1;
  if ( pNumArgs > 1 )
  {
    while ( 1 )
    {
      v21 = v19[v20];
      LOWORD(ProcessInformation.hProcess) = 0;
      v63 = 0x700000000i64;
      sub_401EB0(v21, wcslen(v21));
      v22 = (_DWORD *)sub_402010(&ProcessInformation);
      v23 = v22;
      if ( v22[5] >= 8u )
        v23 = (_DWORD *)*v22;
      v24 = v22[4];
      v58 = v67;
      if ( v24 > v68 - v67 )
      {
        LOBYTE(v53) = 0;
        sub_402130(v24, v53, v23, v24);
      }
      else
      {
        v25 = v24 + v67;
        v26 = &v66;
        if ( v68 >= 8 )
          v26 = (__int128 *)v66;
        v67 += v24;
        sub_405110((char *)v26 + 2 * v58, v23, 2 * v24);
        *((_WORD *)v26 + v25) = 0;
        v20 = NumberOfBytesWritten;
      }
      if ( v57 >= 8 )
      {
        v27 = v55[0];
        if ( 2 * v57 + 2 >= 0x1000 )
        {
          v27 = *(_DWORD *)(v55[0] - 4);
          if ( (unsigned int)(v55[0] - v27 - 4) > 0x1F )
            goto LABEL_94;
        }
        sub_4027ED(v27);
      }
      v56 = 0;
      v57 = 7;
      LOWORD(v55[0]) = 0;
      if ( HIDWORD(v63) >= 8 )
      {
        v28 = ProcessInformation.hProcess;
        if ( (unsigned int)(2 * HIDWORD(v63) + 2) >= 0x1000 )
        {
          v28 = (HANDLE)*((_DWORD *)ProcessInformation.hProcess - 1);
          if ( (unsigned int)(ProcessInformation.hProcess - v28 - 4) > 0x1F )
            goto LABEL_94;
        }
        sub_4027ED(v28);
      }
      NumberOfBytesWritten = ++v20;
      if ( v20 >= pNumArgs )
        break;
      v19 = (LPWSTR *)ExitCode;
    }
  }
  if ( !GetModuleFileNameW(0, Filename, 0x104u) )
  {
    sub_401E60(&off_413CEC);
    sub_401000(v51);
  }
  v56 = 0;
  v57 = 7;
  LOWORD(v55[0]) = 0;
  sub_401EB0(Filename, wcslen(Filename));
  sub_402010(v55);
  v29 = sub_402360(L"\"");
  p_ProcessInformation = &ProcessInformation;
  v31 = *(struct _PROCESS_INFORMATION *)v29;
  v32 = *(_QWORD *)(v29 + 16);
  *(_DWORD *)(v29 + 16) = 0;
  *(_DWORD *)(v29 + 20) = 7;
  *(_WORD *)v29 = 0;
  v33 = _mm_cvtsi128_si32((__m128i)v31);
  v63 = v32;
  if ( HIDWORD(v32) >= 8 )
    p_ProcessInformation = (struct _PROCESS_INFORMATION *)v33;
  v54 = (char *)v33;
  ProcessInformation = v31;
  ExitCode = v67;
  if ( (unsigned int)v32 > v68 - v67 )
  {
    LOBYTE(ExitCode) = 0;
    sub_402130(v32, ExitCode, p_ProcessInformation, v32);
    v36 = (char *)ProcessInformation.hProcess;
  }
  else
  {
    v34 = v32 + v67;
    v67 += v32;
    v35 = &v66;
    if ( v68 >= 8 )
      v35 = (__int128 *)v66;
    sub_405110((char *)v35 + 2 * ExitCode, p_ProcessInformation, 2 * v32);
    v36 = v54;
    *((_WORD *)v35 + v34) = 0;
  }
  if ( HIDWORD(v63) >= 8 )
  {
    v37 = v36;
    if ( (unsigned int)(2 * HIDWORD(v63) + 2) >= 0x1000 )
    {
      v36 = (char *)*((_DWORD *)v36 - 1);
      if ( (unsigned int)(v37 - v36 - 4) > 0x1F )
        goto LABEL_99;
    }
    sub_4027ED(v36);
  }
  if ( v61 >= 8 )
  {
    v38 = v59;
    if ( 2 * v61 + 2 >= 0x1000 )
    {
      v38 = *(_DWORD *)(v59 - 4);
      if ( (unsigned int)(v59 - v38 - 4) > 0x1F )
        goto LABEL_99;
    }
    sub_4027ED(v38);
  }
  v60 = 0;
  v61 = 7;
  LOWORD(v59) = 0;
  if ( v57 < 8 )
    goto LABEL_70;
  v39 = v55[0];
  if ( 2 * v57 + 2 >= 0x1000 )
  {
    v39 = *(_DWORD *)(v55[0] - 4);
    if ( (unsigned int)(v55[0] - v39 - 4) > 0x1F )
LABEL_99:
      sub_405F00();
  }
  sub_4027ED(v39);
LABEL_70:
  v40 = &v66;
  StartupInfo.cb = 68;
  if ( v68 >= 8 )
    v40 = (__int128 *)v66;
  ProcessInformation = 0i64;
  memset(&StartupInfo.lpReserved, 0, 64);
  v41 = (WCHAR *)sub_406222(v40);
  v42 = lpPathName;
  v43 = v41;
  if ( v74 >= 8 )
    v42 = (LPCWSTR *)lpPathName[0];
  v44 = (const WCHAR *)sub_406222(v42);
  if ( !CreateProcessW(0, v43, 0, 0, 0, 0x420u, 0, v44, &StartupInfo, &ProcessInformation) )
  {
    sub_401E60(&off_413C28);
    sub_401000(v52);
  }
  WaitForSingleObject(ProcessInformation.hProcess, 0xFFFFFFFF);
  if ( !GetExitCodeProcess(ProcessInformation.hProcess, &ExitCode) )
  {
    sub_401E60(&off_413C58);
    sub_401000(v52);
  }
  v45 = (const WCHAR *)lpFileName;
  if ( HIDWORD(v71) >= 8 )
    v45 = lpFileName[0];
  DeleteFileW(v45);
  v46 = (const WCHAR *)lpPathName;
  if ( v74 >= 8 )
    v46 = lpPathName[0];
  RemoveDirectoryW(v46);
  if ( v68 >= 8 )
  {
    v47 = v66;
    if ( 2 * v68 + 2 >= 0x1000 )
    {
      v47 = *(_DWORD *)(v66 - 4);
      if ( (unsigned int)(v66 - v47 - 4) > 0x1F )
        goto LABEL_101;
    }
    sub_4027ED(v47);
  }
  v67 = 0;
  v68 = 7;
  LOWORD(v66) = 0;
  if ( HIDWORD(v71) >= 8 )
  {
    v48 = lpFileName[0];
    if ( (unsigned int)(2 * HIDWORD(v71) + 2) >= 0x1000 )
    {
      v48 = (LPCWSTR)*((_DWORD *)lpFileName[0] - 1);
      if ( (unsigned int)((char *)lpFileName[0] - (char *)v48 - 4) > 0x1F )
        goto LABEL_101;
    }
    sub_4027ED(v48);
  }
  v71 = 0x700000000i64;
  LOWORD(lpFileName[0]) = 0;
  if ( v74 >= 8 )
  {
    v49 = lpPathName[0];
    if ( 2 * v74 + 2 < 0x1000
      || (v49 = (LPCWSTR)*((_DWORD *)lpPathName[0] - 1), (unsigned int)((char *)lpPathName[0] - (char *)v49 - 4) <= 0x1F) )
    {
      sub_4027ED(v49);
      return ExitCode;
    }
LABEL_101:
    sub_405F00();
  }
  return ExitCode;
}
