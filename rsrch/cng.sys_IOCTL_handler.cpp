__int64 __fastcall CngDeviceControl(unsigned int *a1, SIZE_T a2, _OWORD *a3, signed int *a4)
{
  unsigned int v4; // ebx
  unsigned int *v5; // rdi
  void *v6; // rsi
  unsigned int v7; // er12
  __int64 result; // rax
  signed int v9; // eax
  __int128 v10; // ST00_16
  __int128 v11; // ST10_16
  __int128 v12; // ST20_16
  __int128 v13; // ST30_16
  __int128 v14; // ST40_16
  __int128 v15; // ST50_16
  __int128 v16; // ST60_16
  __int128 v17; // ST70_16
  __int128 v18; // ST00_16
  __int128 v19; // ST10_16
  __int128 v20; // ST20_16
  __int128 v21; // ST30_16
  __int128 v22; // ST40_16
  unsigned int v23; // eax
  signed __int64 v24; // r9
  void **v25; // r9
  unsigned int v26; // er15
  signed __int64 v27; // r9
  unsigned int v28; // eax
  signed int v29; // ecx
  __int64 v30; // rdx
  signed __int64 v31; // rcx
  void *retaddr; // [rsp+D0h] [rbp+77h]
  char v33; // [rsp+D8h] [rbp+7Fh]

  v4 = 0;
  v5 = (unsigned int *)a4;
  v6 = a3;
  v7 = -1073741637;
  if ( (unsigned int)retaddr > 0x390040 )
  {
    switch ( (_DWORD)retaddr )
    {
      case 0x390044:
        v25 = (void **)&off_1C008F510;
        return CryptIoctlReturnKernelmodePointer(a3, v5, v33, v25);
      case 0x390048:
        v25 = &off_1C008F558;
        return CryptIoctlReturnKernelmodePointer(a3, v5, v33, v25);
      case 0x390064:
        v25 = (void **)&unk_1C008F568;
        return CryptIoctlReturnKernelmodePointer(a3, v5, v33, v25);
      case 0x390073:
        if ( a4 && *a4 || a1 || (_DWORD)a2 )
        {
          v24 = 1273i64;
          goto LABEL_28;
        }
        if ( g_fSelftest )
        {
          v30 = 0i64;
          v31 = 1i64;
          goto LABEL_82;
        }
        break;
      case 0x390074:
        if ( a4 && *a4 || !a1 || (_DWORD)a2 != 4 )
        {
          v24 = 1291i64;
          goto LABEL_28;
        }
        if ( g_fSelftest )
        {
          v30 = *a1;
          v31 = 0i64;
LABEL_82:
          SeAuditFipsCryptoSelftests(v31, v30);
          return v4;
        }
        break;
      case 0x39007A:
      case 0x39007E:
        goto LABEL_48;
      case 0x390084:
        if ( a4 && *a4 == 8 && a3 )
        {
          *(_QWORD *)a3 = g_selftestDuration;
          return 0i64;
        }
        v24 = 1304i64;
LABEL_28:
        DebugTraceError(
          3221225485i64,
          "Status",
          "onecore\\ds\\security\\cryptoapi\\ncrypt\\crypt\\kernel\\cng.cxx",
          v24);
        return 3221225485i64;
      case 0x390400:
        return ConfigIoHandler_Safeguarded(a1, a2);
      default:
LABEL_39:
        if ( WPP_GLOBAL_Control != &WPP_GLOBAL_Control && *((_DWORD *)WPP_GLOBAL_Control + 11) & 1 )
          WPP_SF_D(*((_QWORD *)WPP_GLOBAL_Control + 3), 12i64, a3, (unsigned int)retaddr);
        goto LABEL_64;
    }
    return (unsigned int)-1073741244;
  }
  if ( (_DWORD)retaddr == 3735616 )
  {
    v25 = (void **)off_1C008F580;
    return CryptIoctlReturnKernelmodePointer(a3, v5, v33, v25);
  }
  if ( (_DWORD)retaddr == 3735556 || (_DWORD)retaddr == 3735560 )
  {
    if ( a3 && a4 )
    {
      v23 = *a4;
      if ( (unsigned int)a2 < *a4 )
      {
        memset((char *)a3 + (unsigned int)a2, 0, v23 - (unsigned int)a2);
        v23 = *v5;
      }
      if ( (unsigned int)SystemPrng(v6, v23) )
        return 0i64;
      DebugTraceError(
        3221225473i64,
        "Status",
        "onecore\\ds\\security\\cryptoapi\\ncrypt\\crypt\\kernel\\cng.cxx",
        1082i64);
      return 3221225473i64;
    }
    v24 = 1066i64;
    goto LABEL_28;
  }
  if ( (_DWORD)retaddr != 3735566
    && (_DWORD)retaddr != 3735570
    && (_DWORD)retaddr != 3735574
    && (_DWORD)retaddr != 3735578
    && (_DWORD)retaddr != 3735582
    && (_DWORD)retaddr != 3735586 )
  {
    if ( (_DWORD)retaddr == 3735588 )
    {
      if ( v33 )
      {
        DebugTraceError(
          3221225506i64,
          "Status",
          "onecore\\ds\\security\\cryptoapi\\ncrypt\\crypt\\kernel\\cng.cxx",
          1166i64);
        return 3221225506i64;
      }
      v9 = 128;
      if ( (unsigned int)*a4 >= 0x80 )
      {
        *(_QWORD *)&v10 = FipsDesKey;
        *((_QWORD *)&v10 + 1) = FipsDes;
        *(_QWORD *)&v11 = Fips3Des3Key;
        *((_QWORD *)&v11 + 1) = Fips3Des;
        *(_QWORD *)&v12 = FipsSHAInit;
        *((_QWORD *)&v12 + 1) = FipsHmacSHAUpdate;
        *(_QWORD *)&v13 = FipsSHAFinal;
        *a3 = v10;
        *((_QWORD *)&v13 + 1) = &FipsCBC;
        a3[1] = v11;
        *(_QWORD *)&v14 = &FIPSGenRandom;
        *((_QWORD *)&v14 + 1) = FipsBlockCBC;
        a3[2] = v12;
        *(_QWORD *)&v15 = &FipsHmacSHAInit;
        a3[3] = v13;
        *((_QWORD *)&v15 + 1) = FipsHmacSHAUpdate;
        *(_QWORD *)&v16 = &FipsHmacSHAFinal;
        a3[4] = v14;
        *((_QWORD *)&v16 + 1) = &HmacMD5Init;
        a3[5] = v15;
        *(_QWORD *)&v17 = HmacMD5Update;
        *((_QWORD *)&v17 + 1) = &HmacMD5Final;
        a3[6] = v16;
        a3[7] = v17;
LABEL_18:
        *a4 = v9;
        return 0i64;
      }
      v9 = 80;
      if ( (unsigned int)*a4 >= 0x50 )
      {
        *(_QWORD *)&v18 = FipsDesKey;
        *((_QWORD *)&v18 + 1) = FipsDes;
        *(_QWORD *)&v19 = Fips3Des3Key;
        *((_QWORD *)&v19 + 1) = Fips3Des;
        *(_QWORD *)&v20 = FipsSHAInit;
        *a3 = v18;
        *((_QWORD *)&v20 + 1) = FipsHmacSHAUpdate;
        *(_QWORD *)&v21 = FipsSHAFinal;
        a3[1] = v19;
        *((_QWORD *)&v21 + 1) = &FipsCBC;
        a3[2] = v20;
        *(_QWORD *)&v22 = &FIPSGenRandom;
        *((_QWORD *)&v22 + 1) = FipsBlockCBC;
        a3[3] = v21;
        a3[4] = v22;
        goto LABEL_18;
      }
      v7 = -1073741789;
      goto LABEL_64;
    }
    goto LABEL_39;
  }
LABEL_48:
  v26 = 1;
  if ( !a3 || !a4 )
  {
    v24 = 1102i64;
    goto LABEL_28;
  }
  if ( (unsigned int)a2 < *a4 )
    memset((char *)a3 + (unsigned int)a2, 0, (unsigned int)(*a4 - a2));
  v27 = 0i64;
  if ( !(((_DWORD)retaddr - 3735574) & 0xFFFFFFFB) )
    v27 = 1i64;
  if ( !(((_DWORD)retaddr - 3735582) & 0xFFFFFFFB) )
    v27 = 2i64;
  v28 = (_DWORD)retaddr - 3735570;
  if ( !(((_DWORD)retaddr - 3735674) & 0xFFFFFFFB) )
    v27 = 4i64;
  if ( v28 <= 0x10 && (v29 = 65793, _bittest(&v29, v28)) || (_DWORD)retaddr == 3735678 )
    v26 = 0;
  result = CngEncryptMemoryEx(v6, *v5, v26, v27);
  v7 = result;
  if ( (signed int)result < 0 )
  {
    DebugTraceError(
      (unsigned int)result,
      "Status",
      "onecore\\ds\\security\\cryptoapi\\ncrypt\\crypt\\kernel\\cng.cxx",
      1151i64);
LABEL_64:
    if ( v5 )
      *v5 = 0;
    result = v7;
  }
  return result;
}