 /*
 
 nt!KiDispatchException+0x156b75 // the call to ZwTerminateProcess

^ that case only happens if the exception is fatal. we won't see a crash if for example: 0XC0000005'S are handled in userland by the application


fatal exceptions seem to be pushed to:
ntdll!KiUserExceptionDispatch

// use !wow64exts.sw in KD to make 64 bit kernel work in 32 bit KD context
will need to check as far as terminateprocess goes
 */
 
 VOID
 NTAPI
 KiDispatchException(IN PEXCEPTION_RECORD ExceptionRecord,
                     IN PKEXCEPTION_FRAME ExceptionFrame,
                     IN PKTRAP_FRAME TrapFrame,
                     IN KPROCESSOR_MODE PreviousMode,
                     IN BOOLEAN FirstChance)
 {
     CONTEXT Context;
 
     /* Increase number of Exception Dispatches */
     KeGetCurrentPrcb()->KeExceptionDispatchCount++;
 
     /* Zero out the context to avoid leaking kernel stack memor to user mode */
     RtlZeroMemory(&Context, sizeof(Context));
 
     /* Set the context flags */
     Context.ContextFlags = CONTEXT_ALL;
 
     /* Get the Context from the trap and exception frame */
     KeTrapFrameToContext(TrapFrame, ExceptionFrame, &Context);
 
     /* Look at our exception code */
     switch (ExceptionRecord->ExceptionCode)
     {
         /* Breakpoint */
         case STATUS_BREAKPOINT:
 
             /* Decrement RIP by one */
             Context.Rip--;
             break;
 
         /* Internal exception */
         case KI_EXCEPTION_ACCESS_VIOLATION:
 
             /* Set correct code */
             ExceptionRecord->ExceptionCode = STATUS_ACCESS_VIOLATION;
             if (PreviousMode == UserMode)
             {
                 /* FIXME: Handle no execute */
             }
             break;
     }
 
     /* Handle kernel-mode first, it's simpler */
     if (PreviousMode == KernelMode)
     {
         /* Check if this is a first-chance exception */
         if (FirstChance)
         {
             /* Break into the debugger for the first time */
             if (KiDebugRoutine(TrapFrame,
                                ExceptionFrame,
                                ExceptionRecord,
                                &Context,
                                PreviousMode,
                                FALSE))
             {
                 /* Exception was handled */
                 goto Handled;
             }
 
             /* If the Debugger couldn't handle it, dispatch the exception */
             if (RtlDispatchException(ExceptionRecord, &Context)) goto Handled;
         }
 
         /* This is a second-chance exception, only for the debugger */
         if (KiDebugRoutine(TrapFrame,
                            ExceptionFrame,
                            ExceptionRecord,
                            &Context,
                            PreviousMode,
                            TRUE))
         {
             /* Exception was handled */
             goto Handled;
         }
 
         /* Third strike; you're out */
         KeBugCheckEx(KMODE_EXCEPTION_NOT_HANDLED,
                      ExceptionRecord->ExceptionCode,
                      (ULONG_PTR)ExceptionRecord->ExceptionAddress,
                      (ULONG_PTR)TrapFrame,
                      0);
     }
     else
     {
         /* User mode exception, was it first-chance? */
         if (FirstChance)
         {
             /*
              * Break into the kernel debugger unless a user mode debugger
              * is present or user mode exceptions are ignored, except if this
              * is a debug service which we must always pass to KD
              */
             if ((!(PsGetCurrentProcess()->DebugPort) &&
                  !(KdIgnoreUmExceptions)) ||
                  (KdIsThisAKdTrap(ExceptionRecord, &Context, PreviousMode)))
             {
                 /* Make sure the debugger can access debug directories */
                 KiPrepareUserDebugData();
 
                 /* Call the kernel debugger */
                 if (KiDebugRoutine(TrapFrame,
                                    ExceptionFrame,
                                    ExceptionRecord,
                                    &Context,
                                    PreviousMode,
                                    FALSE))
                 {
                     /* Exception was handled */
                     goto Handled;
                 }
             }
 
             /* Forward exception to user mode debugger */
             if (DbgkForwardException(ExceptionRecord, TRUE, FALSE)) return;
             
             /* Forward exception to user mode (does not return) */
             KiDispatchExceptionToUser(TrapFrame, &Context, ExceptionRecord);
             NT_ASSERT(FALSE);
         }
 
         /* Try second chance */
         if (DbgkForwardException(ExceptionRecord, TRUE, TRUE))
         {
             /* Handled, get out */
             return;
         }
         else if (DbgkForwardException(ExceptionRecord, FALSE, TRUE))
         {
             /* Handled, get out */
             return;
         }
 
         /* 3rd strike, kill the process */
         DPRINT1("Kill %.16s, ExceptionCode: %lx, ExceptionAddress: %lx, BaseAddress: %lx\n",
                 PsGetCurrentProcess()->ImageFileName,
                 ExceptionRecord->ExceptionCode,
                 ExceptionRecord->ExceptionAddress,
                 PsGetCurrentProcess()->SectionBaseAddress);
 
         ZwTerminateProcess(NtCurrentProcess(), ExceptionRecord->ExceptionCode);
         KeBugCheckEx(KMODE_EXCEPTION_NOT_HANDLED,
                      ExceptionRecord->ExceptionCode,
                      (ULONG_PTR)ExceptionRecord->ExceptionAddress,
                      (ULONG_PTR)TrapFrame,
                      0);
     }
 
 Handled:
     /* Convert the context back into Trap/Exception Frames */
     KeContextToTrapFrame(&Context,
                          ExceptionFrame,
                          TrapFrame,
                          Context.ContextFlags,
                          PreviousMode);
     return;
 }