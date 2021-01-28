# To snapshot

## Get QEMU

```
sudo apt build-dep qemu
git clone https://github.com/qemu/QEMU
```

## Apply diffs to QEMU to expand snapshot state to include everything we need

```
diff --git a/target/i386/arch_dump.c b/target/i386/arch_dump.c
index 004141fc04..7a407b2d48 100644
--- a/target/i386/arch_dump.c
+++ b/target/i386/arch_dump.c
@@ -264,6 +264,21 @@ struct QEMUCPUState {
      * by checking 'size' field.
      */
     uint64_t kernel_gs_base;
+    uint64_t cr8;
+    uint64_t cstar;
+    uint64_t lstar;
+    uint64_t fmask;
+    uint64_t star;
+    uint64_t sysenter_cs;
+    uint64_t sysenter_esp;
+    uint64_t sysenter_eip;
+    uint64_t efer;
+    uint64_t dr[8];
+    uint64_t tsc;
+    uint64_t tsc_adjust;
+    uint64_t tsc_deadline;
+    uint64_t tsc_aux;
+    X86LegacyXSaveArea xsave;
 };
 
 typedef struct QEMUCPUState QEMUCPUState;
@@ -322,8 +337,50 @@ static void qemu_get_cpustate(QEMUCPUState *s, CPUX86State *env)
     s->cr[3] = env->cr[3];
     s->cr[4] = env->cr[4];
 
+
 #ifdef TARGET_X86_64
     s->kernel_gs_base = env->kernelgsbase;
+    s->cr8 = cpu_get_apic_tpr(env_archcpu(env)->apic_state);
+    s->cstar = env->cstar;
+    s->lstar = env->lstar;
+    s->fmask = env->fmask;
+    s->star = env->star;
+    s->sysenter_cs = env->sysenter_cs;
+    s->sysenter_esp = env->sysenter_esp;
+    s->sysenter_eip = env->sysenter_eip;
+    s->efer = env->efer;
+    memcpy(s->dr, env->dr, sizeof(s->dr));
+
+    s->tsc          = env->tsc;
+    s->tsc_adjust   = env->tsc_adjust;
+    s->tsc_deadline = env->tsc_deadline;
+    s->tsc_aux      = env->tsc_aux;
+
+    int fpus, fptag, i;
+
+    fpus = (env->fpus & ~0x3800) | (env->fpstt & 0x7) << 11;
+    fptag = 0;
+    for (i = 0; i < 8; i++) {
+        fptag |= (env->fptags[i] << i);
+    }
+
+    s->xsave.fcw = env->fpuc;
+    s->xsave.fsw = fpus;
+    s->xsave.ftw = fptag ^ 0xff;
+    s->xsave.reserved = 0;
+    s->xsave.fpop = 0;
+    s->xsave.fpip = 0;
+    s->xsave.fpdp = 0;
+    s->xsave.mxcsr = env->mxcsr;
+    s->xsave.mxcsr_mask = 0x0000ffff;
+
+    for(i = 0; i < 8; i++) {
+        s->xsave.fpregs[i] = env->fpregs[i];
+    }
+
+    for(i = 0; i < 16; i++) {
+        memcpy(s->xsave.xmm_regs[i], &env->xmm_regs[i], 16);
+    }
 #endif
 }
```

## Build QEMU

```
mkdir build
cd build
../QEMU/configure --target-list=x86_64-softmmu
make -j32
```

## Run QEMU with a target

```
build/x86_64-softmmu/qemu-system-x86_64 -hda ./DISK.qcow2 -m 4G -cpu core2duo
```

I personally often use, since I have some network devices I can TAP, and I use
KVM for the virt speedup during snapshotting.

```
~/qemu_build/x86_64-softmmu/qemu-system-x86_64 -hda ./DISK.qcow2 -enable-kvm -m 4G -cpu core2duo -smp 1 -vga std -netdev tap,ifname=virbr1-nic,id=mynet -device driver=e1000,netdev=mynet
```

## Take a snapshot

Arrange the guest with GDB to be at the right location. Once you found the right place, go into the QEMU monitor and type `dump-guest-memory <filename>`. This file is directly what is consumed by chocolate milk!


# Notes on Page Heap snapshotting

On windows running inside qemu, Page heap work in a weird ass way. The usual way to snapshot a process with page heap would be:

1. Enable page heap for the process
2. Reboot
3. take the perfect snapshot from qemu on FIRST TRY,

 as the qemu or windows allocator with page heap has a big problem. Mainly when the process exits, the pages unmapped/free'd.
 as we know, free'd pages on page heap are not permitted to be used by anyone else to detect it. Windows due to aslr of course 
 maps the process in the same place for the sake of completeness. The problem is that, page heap is preventing that memory from being used 
 (yeah, kernel should have cleaned that up, but it didnt). Winbag can see the addresses as before, as they have been somehow aliased/used nested mapping
 to just interpret them as such in windbg.

 That means that, when accessing the eip address of that process executed 2nd time in a row from QEMU gdbserver, will result in an error, while reading
 it from windbg will be just fine.

 summing it up: the USERMODE APP snapshot, has to be taken during the first time the process was executed since qemu boot up.


 ## todo

 # Notes on Special pools/kernel page heap 

 ...