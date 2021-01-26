void __usercall KiDispatchException(ULONG_PTR *Dst@<rcx>, __m128i *a2@<rdx>, __int64 a3@<r8>, char a4@<r9b>, __int64 a5@<r13>, char a6)
{
  char v6; // r15
  __m128i *v7; // r14
  ULONG_PTR *ExceptionCode; // rbx
  _KPROCESS *v9; // rax
  int v10; // er12
  unsigned __int64 v11; // rax
  void *v12; // rsp
  __int64 v13; // rdx
  __int64 v14; // r15
  bool v15; // al
  _KPROCESS *v16; // rdx
  unsigned __int64 v17; // rdx
  _BYTE *v18; // r12
  SIZE_T v19; // rcx
  _QWORD *v20; // rcx
  __int64 v21; // rbx
  int v22; // er12
  __int64 v23; // rdx
  ULONG_PTR BugCheckParameter3; // [rsp+30h] [rbp+0h]
  unsigned int v25; // [rsp+38h] [rbp+8h]
  __m128i *v26; // [rsp+40h] [rbp+10h]
  unsigned __int64 v27; // [rsp+48h] [rbp+18h]
  unsigned __int64 v28; // [rsp+50h] [rbp+20h]
  __int64 v29; // [rsp+58h] [rbp+28h]
  __int64 v30; // [rsp+60h] [rbp+30h]
  ULONG_PTR *v31; // [rsp+68h] [rbp+38h]
  unsigned __int64 v32; // [rsp+70h] [rbp+40h]
  _BYTE *v33; // [rsp+78h] [rbp+48h]
  _QWORD *v34; // [rsp+80h] [rbp+50h]
  __int64 v35; // [rsp+88h] [rbp+58h]
  ULONG_PTR *v36; // [rsp+98h] [rbp+68h]
  __int64 v37; // [rsp+A0h] [rbp+70h]
  int v38; // [rsp+B0h] [rbp+80h]
  char Dsta; // [rsp+B4h] [rbp+84h]
  __int64 v40; // [rsp+C8h] [rbp+98h]
  __int64 v41; // [rsp+128h] [rbp+F8h]
  __int128 v42; // [rsp+150h] [rbp+120h]
  __int64 v43; // [rsp+160h] [rbp+130h]

  v6 = a4;
  LOBYTE(BugCheckParameter3) = a4;
  v7 = (__m128i *)a3;
  v26 = a2;
  ExceptionCode = Dst;
  v31 = Dst;
  v37 = a3;
  memset(&Dsta, 0, 0x94ui64);
  v42 = 0ui64;
  v43 = 0i64;
  BYTE1(BugCheckParameter3) = 0;
  v9 = KeGetCurrentThread()->ApcState.Process;
  v27 = (unsigned __int64)v9;
  __incgsdword(0x5D30u);
  if ( a6 && v9[2].ActiveProcessors.Bitmap[13] )
  {
    v22 = *(_DWORD *)ExceptionCode;
    switch ( *(_DWORD *)ExceptionCode )
    {
      case 0x10000002:
        *(_DWORD *)ExceptionCode = 0xC000001D;
        break;
      case 0x10000003:
        *(_DWORD *)ExceptionCode = 0xC0000094;
        break;
      case 0x10000004:
        *(_DWORD *)ExceptionCode = 0xC0000005;
        break;
    }
    if ( KeGetEffectiveIrql() < 2u
      && (v6
       || (*(_DWORD *)ExceptionCode == 0x80000001 || (unsigned int)(*(_DWORD *)ExceptionCode + 0x3FFFFFFB) <= 1)
       && ExceptionCode[5] <= 0x7FFFFFFF0000i64)
      && (unsigned __int8)xmmword_140438A20(ExceptionCode, v26, v7, 0i64, v6) )
    {
      return;
    }
    *(_DWORD *)ExceptionCode = v22;
  }
  v10 = 1048607;
  HIDWORD(BugCheckParameter3) = 1048607;
  if ( v6 )
  {
    if ( KeFeatureBits & 0x800000 )
      v10 = 1048671;
    HIDWORD(BugCheckParameter3) = v10;
  }
  RtlGetExtendedContextLength(v10);
  v11 = v25 + 0xFi64;
  if ( v11 <= v25 )
    v11 = 0xFFFFFFFFFFFFFF0i64;
  v12 = alloca(v11);
  v36 = &BugCheckParameter3;
  if ( v6 )
    memset(&BugCheckParameter3, 0, v25);
  RtlInitializeExtendedContext((__int64)&BugCheckParameter3, v10);
  KeContextFromKframes(v7, v26, (__int64)&BugCheckParameter3);
  if ( *(_DWORD *)ExceptionCode == 0x80000003 ) // BREAKPOINT
  {
    --v41;
    if ( KiDynamicTraceMask & 2 )
    {
      if ( KiTpHandleTrap((__int64)ExceptionCode, (__int64)&BugCheckParameter3, v6, a6) )
        goto LABEL_14;
    }
  }
  if ( KiPreprocessFault(ExceptionCode, (ULONG_PTR)&BugCheckParameter3, v6) )
    goto LABEL_14;
  if ( !v6 )
  {
    if ( (!a6
       || !KdTrap((__int64)v7, v13, (__int64)ExceptionCode, (__int64)&BugCheckParameter3, 0, 0)
       && !RtlDispatchException((__int64)ExceptionCode, (__int64)&BugCheckParameter3))
      && !KdTrap((__int64)v7, v13, (__int64)ExceptionCode, (__int64)&BugCheckParameter3, 0, 1) )
    {
      KeBugCheckEx(0x1Eu, *(signed int *)ExceptionCode, ExceptionCode[2], ExceptionCode[4], ExceptionCode[5]);
    }
    goto LABEL_14;
  }
  v14 = v40;
  v30 = v40;
  if ( !(*(_DWORD *)(v27 + 0x6FC) & 1) )
  {
    if ( KeGetCurrentThread()->ApcState.Process[1].ActiveProcessors.Bitmap[6]
      && *(_DWORD *)ExceptionCode == 0x80000002
      && v7[23].m128i_i32[2] & 0x40000 )
    {
      _disable();
      v7[23].m128i_i32[2] &= 0xFFFBFFFF;
LABEL_69:
      _enable();
      return;
    }
    if ( ((unsigned __int16)v31 & 0xFFF8) == 32 )
    {
      if ( *(_DWORD *)ExceptionCode == 0x80000003 )
      {
        *(_DWORD *)ExceptionCode = 1073741855;
      }
      else if ( *(_DWORD *)ExceptionCode == 0x80000004 )
      {
        *(_DWORD *)ExceptionCode = 0x4000001E;
      }
      v14 = (unsigned int)v14 & 0xFFFFFFF0;
      v30 = v14;
    }
  }
  if ( a6 )
  {
    v15 = KdIsThisAKdTrap((__int64)ExceptionCode);
    BYTE1(BugCheckParameter3) = v15;
    v16 = KeGetCurrentThread()->ApcState.Process;
    if ( (!v16[1].ActiveProcessors.Bitmap[5] && !KdIgnoreUmExceptions || v15)
      && KdTrap((__int64)v7, (__int64)v16, (__int64)ExceptionCode, (__int64)&BugCheckParameter3, BugCheckParameter3, 0) )
    {
      v6 = BugCheckParameter3;
LABEL_14:
      KeContextToKframes(v7, v26, (__m128i *)&BugCheckParameter3, v30, v6);
      if ( !BYTE1(BugCheckParameter3) )
        return;
      _disable();
      KiSetupForInstrumentationReturn((__int64)v7);
      goto LABEL_69;
    }
    if ( !DbgkForwardException((__int64)ExceptionCode, 1, 0, a5) )
    {
      _disable();
      v7[23].m128i_i32[2] &= 0xFFFFFEFF;
      _enable();
      v38 = 0xC0000005;
      v17 = v14;
      v28 = v14;
      if ( (v10 & 0x100040) == 0x100040 )
      {
        v17 = (v14 - *(unsigned int *)(v29 + 20)) & 0xFFFFFFFFFFFFFFC0ui64;
        v28 = (v14 - *(unsigned int *)(v29 + 20)) & 0xFFFFFFFFFFFFFFC0ui64;
      }
      v27 = (v17 - 40) & 0xFFFFFFFFFFFFFFF0ui64;
      v32 = (v17 - 40) & 0xFFFFFFFFFFFFFFF0ui64;
      v34 = (_QWORD *)(v27 - 160);
      v35 = v27 - 192;
      v18 = (_BYTE *)(v27 - 1424);
      v33 = (_BYTE *)(v27 - 1424);
      LODWORD(v42) = -1232;
      v19 = v14 - (v27 - 1424);
      DWORD1(v42) = v14 - (v27 - 1424);
      *((_QWORD *)&v42 + 1) = 5295694674736i64;
      LODWORD(v43) = v17 - (v27 - 192);
      HIDWORD(v43) = v14 - v17;
      if ( v14 - (v27 - 1424) - 1 > 0xFFE )
      {
        ProbeForWrite(v18, v19, 0x10u);
        v20 = (_QWORD *)v27;
      }
      else
      {
        if ( (unsigned __int64)v18 >= 0x7FFFFFFF0000i64 )
          v18 = (_BYTE *)0x7FFFFFFF0000i64;
        *v18 = *v18;
        v18[v19 - 1] = v18[v19 - 1];
        v20 = (_QWORD *)v32;
        v18 = v33;
      }
      v20[3] = v14;
      *v20 = v41;
      KeCopyExceptionRecord(v34, (__int64)ExceptionCode);
      v21 = v35;
      RtlpCopyExtendedContext(1, v35, (__int64)&v42, SHIDWORD(BugCheckParameter3), v29, 0i64);
      *(_OWORD *)v21 = v42;
      *(_QWORD *)(v21 + 16) = v43;
      _disable();
      v7[24].m128i_i64[0] = (__int64)v18;
      v7[23].m128i_i16[0] = 51;
      v7[22].m128i_i64[1] = KeUserExceptionDispatcher;
      KiSetupForInstrumentationReturn((__int64)v7);
      _enable();
    }
  }
  else if ( !DbgkForwardException((__int64)ExceptionCode, 1, 1, a5)
         && !DbgkForwardException((__int64)ExceptionCode, 0, 1, a5) )
  {
    v23 = *(unsigned int *)ExceptionCode;
    ZwTerminateProcess();
  }
}


/*
nt!KeUserExceptionDispatcher:
fffff804`43d5d908 002f            add     byte ptr [rdi],ch
fffff804`43d5d90a d3ea            shr     edx,cl
fffff804`43d5d90c fd              std
fffff804`43d5d90d 7f00            jg      nt!KeUserExceptionDispatcher+0x7 (fffff804`43d5d90f)
fffff804`43d5d90f 00913bd3eafd    add     byte ptr [rcx-2152CC5h],dl
fffff804`43d5d915 7f00            jg      nt!KeExecuteUmsThread+0x7 (fffff804`43d5d917)
fffff804`43d5d917 00b63ed3eafd    add     byte ptr [rsi-2152CC2h],dh
fffff804`43d5d91d 7f00            jg      nt!KeUmsExecuteYieldThreadEnd+0x7 (fffff804`43d5d91f)
0: kd> u nt!KeUserExceptionDispatcher
nt!KeUserExceptionDispatcher:
fffff804`43d5d908 002f            add     byte ptr [rdi],ch
fffff804`43d5d90a d3ea            shr     edx,cl
fffff804`43d5d90c fd              std
fffff804`43d5d90d 7f00            jg      nt!KeUserExceptionDispatcher+0x7 (fffff804`43d5d90f)
fffff804`43d5d90f 00913bd3eafd    add     byte ptr [rcx-2152CC5h],dl
fffff804`43d5d915 7f00            jg      nt!KeExecuteUmsThread+0x7 (fffff804`43d5d917)
fffff804`43d5d917 00b63ed3eafd    add     byte ptr [rsi-2152CC2h],dh
fffff804`43d5d91d 7f00            jg      nt!KeUmsExecuteYieldThreadEnd+0x7 (fffff804`43d5d91f)
0: kd> uf KeUserExceptionDispatcher
Flow analysis was incomplete, some code may be missing
nt!KeUserExceptionDispatcher:
fffff804`43d5d908 002f            add     byte ptr [rdi],ch
fffff804`43d5d90a d3ea            shr     edx,cl
fffff804`43d5d90c fd              std
fffff804`43d5d90d 7f00            jg      nt!KeUserExceptionDispatcher+0x7 (fffff804`43d5d90f)  Branch

nt!KeUserExceptionDispatcher+0x7:
fffff804`43d5d90f 00913bd3eafd    add     byte ptr [rcx-2152CC5h],dl
fffff804`43d5d915 7f00            jg      nt!KeExecuteUmsThread+0x7 (fffff804`43d5d917)  Branch

nt!KeExecuteUmsThread+0x7:
fffff804`43d5d917 00b63ed3eafd    add     byte ptr [rsi-2152CC2h],dh
fffff804`43d5d91d 7f00            jg      nt!KeUmsExecuteYieldThreadEnd+0x7 (fffff804`43d5d91f)  Branch

nt!KeUmsExecuteYieldThreadEnd+0x7:
fffff804`43d5d91f 0001            add     byte ptr [rcx],al
fffff804`43d5d921 0000            add     byte ptr [rax],al
fffff804`43d5d923 0000            add     byte ptr [rax],al
fffff804`43d5d925 0000            add     byte ptr [rax],al
fffff804`43d5d927 00c0            add     al,al
fffff804`43d5d929 6bd4c8          imul    edx,esp,0FFFFFFC8h
fffff804`43d5d92c 8389ffff000000  or      dword ptr [rcx+0FFFFh],0
fffff804`43d5d933 0000            add     byte ptr [rax],al
fffff804`43d5d935 0000            add     byte ptr [rax],al
fffff804`43d5d937 00e0            add     al,ah
fffff804`43d5d939 7ad4            jp      nt!KeUserExceptionDispatcher+0x7 (fffff804`43d5d90f)  Branch

nt!TmTransactionManagerObjectType+0x3:
fffff804`43d5d93b c88389ff        enter   8983h,0FFh
fffff804`43d5d93f ff606a          jmp     qword ptr [rax+6Ah]

*/