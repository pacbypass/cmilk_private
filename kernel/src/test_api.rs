use crate::core_locals::LockInterrupts;
use crate::fuzz_session::{BasicRegisterState, FuzzSession, Worker};
use crate::vtx::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::any::Any;
use falktp::CoverageRecord;
use page_table::VirtAddr;

/*
!reload /user
x nt!ntwritefile; 
x nt!ntreadfile; 
x nt!ntcreatefile; 
x ntdll!KiUserExceptionDispatch; 
x nt!NtQueryInformationFile; 
x nt!NtQueryAttributesFile; 
.dump  /o /f C:\snaps\foxit_converttopdf.dmp


32.2: kd:x86> x nt!ntwritefile; 
fffff800`2ae6e400          nt!NtWriteFile (void)
32.2: kd:x86> x nt!ntreadfile; 
fffff800`2aec9ac0          nt!NtReadFile (void)
32.2: kd:x86> x nt!ntcreatefile; 
fffff800`2ae96000          nt!NtCreateFile (NtCreateFile)
32.2: kd:x86> x ntdll!KiUserExceptionDispatch; 
00007ffb`ba9b2f00          ntdll!KiUserExceptionDispatch (KiUserExceptionDispatch)
32.2: kd:x86> x nt!NtQueryInformationFile; 
fffff800`2ae7de60          nt!NtQueryInformationFile (void)
32.2: kd:x86> x nt!NtQueryAttributesFile; 
fffff800`2ae96c80          nt!NtQueryAttributesFile (NtQueryAttributesFile)




*/
use lockcell::LockCell;

const STATUS_INVALID_HANDLE: u32 = 0xC0000008;

//const SIZE: usize = 20000;
pub fn fuzz() {
    //if core!().id != 0 { cpu::halt(); }

    static SESSION: LockCell<Option<Arc<FuzzSession>>, LockInterrupts> = LockCell::new(None);

    // Create the master snapshot, and fork from it for all cores
    let session = {
        let mut session = SESSION.lock();
        if session.is_none() {
            // for _ in 0..26 {
            //     print!("\n");
            // }
            print!("LETS FUZZ! 192.168.2.175:1911\n");
            *session = Some(Arc::new(
                FuzzSession::from_falkdump("192.168.2.175:1911", "foxit.falkdump", |_worker| {})
                    .timeout(1_000_000_000)
                    .inject(inject)
                    .bp_handler(bphandler),
            ));
        }
        session.as_ref().unwrap().clone()
    };

    let mut worker = FuzzSession::worker(session);

    // Set that this is a Windows guest
    worker.enlighten(Some(Box::new(
        crate::fuzz_session::windows::Enlightenment::default(),
    )));
    //let seed = worker.rng.rand();
    //print!("{}\n", seed);
    //worker.mutator.max_input_size(128).seed(seed as u64);
    //let mut first_run = 1;
    loop {
        let _vmexit = worker.fuzz_case(&mut ());
        //first_run = 0;
        //print!("vmexit {:#x?}\n", _vmexit);
    }
}
//type BpHandler<'a> = fn(&mut Worker<'a>) -> bool;

/*



*/

//mutate testcase, get's called on each fuzz case
fn inject(_worker: &mut Worker, _context: &mut dyn Any) {
    //print!("{:x}", _worker.reg(Register::Rip));

    //let mut input = worker.mutate().unwrap();
    let mut input: [u8; 1] = [0xcc];
    
    //_worker.write_virt_from(VirtAddr(BreakPoint::NtCreateFile as u64), &input);
   // _worker.write_virt_from(VirtAddr(BreakPoint::Crash as u64), &input);
    //_worker.write_virt_from(VirtAddr(BreakPoint::NtWriteFile as u64), &input);
    _worker.write_virt_from(VirtAddr(BreakPoint::X86usercreatefile as u64), &input);
    _worker.write_virt_from(VirtAddr(BreakPoint::X86usercreatefiletwo as u64), &input);

    _worker.write_virt_from(VirtAddr(BreakPoint::X86userwritefile as u64), &input);
    _worker.write_virt_from(VirtAddr(BreakPoint::X86userwritefiletwo as u64), &input);
    //_worker.write_virt_from(VirtAddr(BreakPoint::NtReadFile as u64), &input); 


    // inject the input into the target program
    
    /*
    let mut input: [u8; 60] = [0; 60];
    // inject the input into the target program
    worker.read_virt_into(VirtAddr(rbx), &mut input);
    print!("{:x?}", input);*/

    // save the input back
    //worker.fuzz_input = Some(input);
}

// Addresses of handled functions

#[repr(u64)]
enum BreakPoint {
    // Addy to CreateFile
    NtCreateFile = 0xfffff8002ae96000,

    // ReadFile addy
    NtReadFile = 0xfffff8002aec9ac0,

    // NtWriteFile
    NtWriteFile = 0xfffff8002ae6e400,

    // End of test case, followed by an immediate exit.
    Crash = 0x00007ffbba9b2f00,

    X86usercreatefile = 0x756e3bb0,
    X86usercreatefiletwo = 0x76652460,

    X86userwritefile = 0x756e4020,
    X86userwritefiletwo = 0x766519a0,

    //X86readfile = 0x756e3bb0,
    //X86writefile = 0x756e3bb0,
    
    //SPROBUJ PUSCIC TYLKO Z READFILE I CREATEFILE i zobaczymy

    //sprawdz czy ntreadfile czyta caly plik tak non stop, czy czyta od danego momentu do ktoregos, czy ma jakis index albo cos

    // NtQueryInformationFile PROB NEEDED LUL
    //NtQueryAttributesFile <- may be needed, nvm maybe not
}

fn bphandler(
    _worker: &mut Worker,
    _lpf: &(CoverageRecord, VmExit, BasicRegisterState, u8),
) -> bool {
    //print!("bp handler hit");

    let rip: BreakPoint = unsafe { core::mem::transmute(_worker.reg(Register::Rip)) };

    let rsp = _worker.reg(Register::Rsp);
    let return_address = _worker
        .read_virt::<u32>(VirtAddr(rsp))
        .expect("fugffff\n");
    match rip {
        BreakPoint::X86usercreatefiletwo =>{
            _worker.mod_reg(Register::Rsp, |x| {
                x+0x20
            });
            _worker.set_reg(Register::Rip, return_address as u64);
            _worker.set_reg(Register::Rax, 0x696);
            return true;
        }
        BreakPoint::X86usercreatefile =>{
            /*
            0:000> du poi(esp+4)
            00ed7a4c  "e:\smb\hello.jpg"
 */

 /* 
            let mut file_name_bytes: [u8; 128] = [0; 128];
            _worker.read_virt_into(VirtAddr(fname_address), &mut file_name_bytes);
            let (front, slice, back) = unsafe { file_name_bytes.align_to::<u16>() };
            let fname: alloc::string::String = if front.is_empty() && back.is_empty() {
                alloc::string::String::from_utf16(slice).ok()
            } else {
                None
            };*/

            //print!("{}", fname);
            _worker.mod_reg(Register::Rsp, |x| {
                x+0x20
            });
            _worker.set_reg(Register::Rip, return_address as u64);
            _worker.set_reg(Register::Rax, 0x696);
            return true;
        }
        BreakPoint::X86userwritefile =>{
            let addy_to_lpNumberOfBytesWritten = _worker.reg(Register::Rsp)+0x10; 
            let write_back_addy = _worker
                .read_virt::<u32>(VirtAddr(addy_to_lpNumberOfBytesWritten))
                .expect("fugffff\n");

            let len_addr = _worker.reg(Register::Rsp)+0xc; 
            let len = _worker
                .read_virt::<u32>(VirtAddr(len_addr))
                .expect("fugffff\n");

            _worker.write_virt::<u32>(VirtAddr(write_back_addy as u64), len);
            _worker.mod_reg(Register::Rsp, |x| {
                x+0x20
            });
            _worker.set_reg(Register::Rip, return_address as u64);
            _worker.set_reg(Register::Rax, 0x696);
            return true;
        }
        BreakPoint::X86userwritefiletwo =>{
            let addy_to_lpNumberOfBytesWritten = _worker.reg(Register::Rsp)+0x10; 
            let write_back_addy = _worker
                .read_virt::<u32>(VirtAddr(addy_to_lpNumberOfBytesWritten))
                .expect("fugffff\n");

            let len_addr = _worker.reg(Register::Rsp)+0xc; 
            let len = _worker
                .read_virt::<u32>(VirtAddr(len_addr))
                .expect("fugffff\n");

            _worker.write_virt::<u32>(VirtAddr(write_back_addy as u64), len);
            _worker.mod_reg(Register::Rsp, |x| {
                x+0x20
            });
            _worker.set_reg(Register::Rip, return_address as u64);
            _worker.set_reg(Register::Rax, 0x696);
            return true;
        }
        // BreakPoint::NtReadFile => {
        //     /*
        //     3: kd> r
        //     rax=fffff8024d8d5ac0 rbx=ffff980659fbb080 rcx=0000000000000e7c
        //     rdx=0000000000000000 rsi=000000f22b27eb68 rdi=ffffa90e18162be8
        //     rip=fffff8024d8d5ac0 rsp=ffffa90e18162bc8 rbp=ffffa90e18162cc0
        //     r8=0000000000000000  r9=0000000000000000 r10=fffff8024d8d5ac0
        //     r11=fffff8024d3e55b8 r12=0000028d2ef2fca0 r13=0000000000000000
        //     r14=0000000000000000 r15=0000000000001000
        //     iopl=0         nv up ei pl zr na po nc
        //     cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
        //     nt!NtReadFile:
        //     fffff802`4d8d5ac0 4c894c2420      mov     qword ptr [rsp+20h],r9 ss:0018:ffffa90e`18162be8=0000000000000008
        //     3: kd> dd poi(rsp+30)
        //     0000028d`2ef2fca0  00000000 00000000 00000000 00000000
        //     0000028d`2ef2fcb0  00000000 00000000 00000000 00000000
        //     0000028d`2ef2fcc0  00000000 00000000 00000000 00000000
        //     0000028d`2ef2fcd0  00000000 00000000 00000000 00000000
        //     0000028d`2ef2fce0  00000000 00000000 00000000 00000000
        //     0000028d`2ef2fcf0  00000000 00000000 00000000 00000000
        //     0000028d`2ef2fd00  00000000 00000000 00000000 00000000
        //     0000028d`2ef2fd10  00000000 00000000 00000000 00000000

        //     */

        //     /*
        //     NTSTATUS NtReadFile(
        //         _In_     HANDLE           FileHandle,
        //         _In_opt_ HANDLE           Event,
        //         _In_opt_ PIO_APC_ROUTINE  ApcRoutine,
        //         _In_opt_ PVOID            ApcContext,
        //         _Out_    PIO_STATUS_BLOCK IoStatusBlock,
        //         _Out_    PVOID            Buffer,
        //         _In_     ULONG            Length,
        //         _In_opt_ PLARGE_INTEGER   ByteOffset,
        //         _In_opt_ PULONG           Key
        //     );
            
        //     */



        //     // add support for file size-related operations ETC.
        //     // we need to support "PLARGE_INTEGER   ByteOffset" <- kinda done
        //     // add support for checking handles with our global handle database...
        //     // or just compare it with the global 0x6969 handle

        //     let mut start_offset = 0;

        //     let buffer_addr = VirtAddr(_worker.reg(Register::Rsp) + 0x30);
        //     let length_addr = VirtAddr(_worker.reg(Register::Rsp) + 0x34);

        //     // Location in memory of the pointer
        //     let byte_offset_addr = VirtAddr(_worker.reg(Register::Rsp) + 0x38);

        //     // Read pointer from memory
        //     let byte_offset_ptr = _worker
        //         .read_virt::<u64>(byte_offset_addr)
        //         .expect("fugffff\n");

        //     // Check if it's a nullptr
        //     if byte_offset_ptr != 0 {
        //         print!("reading byte offset from {:x}", byte_offset_ptr);
        //         start_offset = _worker
        //             .read_virt::<u64>(VirtAddr(byte_offset_ptr))
        //             .expect("fugffff\n");
        //     }

        //     let addy_buf = _worker.read_virt::<u64>(buffer_addr).expect("fugffff\n");
        //     let length = _worker.read_virt::<u64>(length_addr).expect("fugffff\n");

        //     // improve performance of this, try doing this without
        //     let slice = _worker.fuzz_input.take().unwrap();

        //     // make sure that casting to usize doesnt fuck it up
        //     let input = &slice[start_offset as usize..length as usize];

        //     // write back the file to our nig nog
        //     _worker.write_virt_from(VirtAddr(addy_buf), input);
        //     _worker.set_reg(Register::Rax, 0);

        //     _worker.fuzz_input = Some(slice);

        //     _worker.set_reg(Register::Rip, return_address);

        //     return true;
        // }

        // BreakPoint::NtCreateFile => {
        //     /*
        //     1: kd> r
        //     rax=fffff8024d8a2000 rbx=ffff98065260c080 rcx=000000e2fe9fc570
        //     rdx=0000000080100080 rsi=000000e2fe9fc518 rdi=ffffa90e18853be8
        //     rip=fffff8024d8a2000 rsp=ffffa90e18853bc8 rbp=ffffa90e18853cc0
        //     r8=000000e2fe9fc5c8  r9=000000e2fe9fc588 r10=fffff8024d8a2000
        //     r11=fffff8024d3e55a8 r12=0000000000000000 r13=0000000080100080
        //     r14=0000000000000000 r15=0000000000000000
        //     iopl=0         nv up ei pl zr na po nc
        //     cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
        //     nt!NtCreateFile:
        //     fffff802`4d8a2000 4881ec88000000  sub     rsp,88h
        //     1: kd> du poi(poi(r8+10)+8)
        //     000001ec`1605b7c0  "\??\C:\Windows\Prefetch\SVCHOST."
        //     000001ec`1605b800  "EXE-EE1C9ACA.pf"

        //     */
        //     /*
        //     __kernel_entry NTSTATUS NtCreateFile(
        //         PHANDLE            FileHandle,
        //         ACCESS_MASK        DesiredAccess,
        //         POBJECT_ATTRIBUTES ObjectAttributes,
        //         PIO_STATUS_BLOCK   IoStatusBlock, // CHECK IF WE NEED TO WRITE THIS BACK 
        //         PLARGE_INTEGER     AllocationSize,
        //         ULONG              FileAttributes,
        //         ULONG              ShareAccess,
        //         ULONG              CreateDisposition,
        //         ULONG              CreateOptions,
        //         PVOID              EaBuffer,
        //         ULONG              EaLength
        //     );
            
            
        //     */
        //     // the utf-16 bytes we read to detect the filename
        //     let mut file_name_bytes: [u8; 128] = [0; 128];

        //     // ObjectAttributes+10h -> PTR to utf-16 string
        //     let object_attributes = VirtAddr(_worker.reg(Register::R8) + 0x10);

        //     // base of the utf-16 thingy
        //     let addy = _worker.read_virt::<u64>(object_attributes).expect("fug\n") + 8;

        //     // Raw addy of the utf 16 string
        //     let fname_address = _worker.read_virt::<u64>(VirtAddr(addy)).expect("nig");

        //     // raw utf-16 bytes
        //     _worker.read_virt_into(VirtAddr(fname_address), &mut file_name_bytes);

        //     // Convert the array from u8 to u16 and convert it to a rust string
        //     let (front, slice, back) = unsafe { file_name_bytes.align_to::<u16>() };
        //     let fname: alloc::string::String = if front.is_empty() && back.is_empty() {
        //         alloc::string::String::from_utf16(slice).ok()
        //     } else {
        //         None
        //     }
        //     .expect("niggacheese lol");

        //     print!("fname {}\n", fname);

        //     // not sure if its supposed to be u32 or u64, to be tested

        //     // Create handle
        //     let handle: i32 = if fname == "nigger" { 0x6969 } else { -1 };

        //     // write back our fake handle
            
        //     let addr = VirtAddr(_worker.reg(Register::Rcx));
        //     _worker.write_virt::<i32>(addr, handle);

        //     _worker.set_reg(Register::Rip, return_address);
        //     return true;
        // }
        // BreakPoint::NtWriteFile =>{

        //     /*
        //     __kernel_entry NTSYSCALLAPI NTSTATUS NtWriteFile(
        //         HANDLE           FileHandle,
        //         HANDLE           Event,
        //         PIO_APC_ROUTINE  ApcRoutine,
        //         PVOID            ApcContext,
        //         PIO_STATUS_BLOCK IoStatusBlock, // OUT
        //         PVOID            Buffer,
        //         ULONG            Length,
        //         PLARGE_INTEGER   ByteOffset,
        //         PULONG           Key
        //         );
        //     */

        //     // Check if IOSB needs to get checked or not

        //     // STATUS_SUCCESS
        //     _worker.set_reg(Register::Rax, 0);

        //     // jmp back to ret address
        //     _worker.set_reg(Register::Rip, return_address);

        //     return true;
        // }
        BreakPoint::Crash => {
            print!("crashed\n");
            return false;
        }
        _ => {
            panic!("bad ptr addy: {}\n", _worker.reg(Register::Rip))
        }
    }
}
