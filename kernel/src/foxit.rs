use crate::core_locals::LockInterrupts;
use crate::fuzz_session::{BasicRegisterState, FuzzSession, Worker, Rng, ContextStructure};
use crate::vtx::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use basic_mutator::Mutator;
use core::any::Any;
use falktp::CoverageRecord;
use page_table::VirtAddr;
use alloc::vec::Vec;
/*
!reload /user
x nt!ntwritefile;
x nt!ntreadfile;
x nt!ntcreatefile;
x ntdll!KiUserExceptionDispatch;
x nt!NtQueryInformationFile;
x nt!NtQueryAttributesFile;
.dump  /o /f E:\snaps\foxit_converttopdf.dmp


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

const testslice: [u8; 524288] = [0; 524288];

use lockcell::LockCell;

//const SIZE: usize = 20000;
pub fn fuzz() {
    
    //if core!().id != 0 { cpu::halt(); }

    static SESSION: LockCell<Option<Arc<FuzzSession>>, LockInterrupts> = LockCell::new(None);

    // Create the master snapshot, and fork from it for all cores
    let session = {
        let mut session = SESSION.lock();
        if session.is_none() {
            print!("LETS FUZZ! 192.168.2.175:1911\n");
            *session = Some(Arc::new(
                FuzzSession::from_falkdump(
                    "192.168.2.175:1911",
                    "mapped_foxit.falkdump",
                    |_worker| {},
                )
                .timeout(25_000_000)
                .inject(inject)
                .corpus()
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

    // if core!().id != 0 {
    //     cpu::halt();
    // }

    let mut ctr: u64 = 1;
    let id:u64 = core!().id as u64 +1;
    let tsc = 132612309538763543;
    let inplen = worker.len_of_inputs();
    let mut context: ContextStructure = ContextStructure {
        mutator: Mutator::new().max_input_size(512 * 1024).seed(cpu::rdtsc()+(core!().id*32) as u64),
        base_rdtsc: tsc,
        rdtsc: tsc,
        debug: false,
        first_exec: true,
        dry_run: true,
        cur_input: (inplen/4)* core!().id as usize,
        len_of_inputs: worker.len_of_inputs(),
        input_offset: 0,
        input_size: 0,
    };
    if !context.dry_run{
        context.cur_input=context.len_of_inputs+1;
    }
    print!("!CORE:{} will stop at {} \n", core!().id, (inplen/4)* (core!().id as usize+1));
    loop {
        // print!("== NEW RUN ==\n");
        let _vmexit = worker.fuzz_case(&mut context);
        context.input_offset = 0;
        context.input_size = 0;
        if context.dry_run{
            context.first_exec = true;
        }
        else{
            context.first_exec = false;
        }
        ctr+=1;

        
        if context.cur_input >=  (inplen/4)* (core!().id as usize+1){
            if context.dry_run == true{
                print!("!CORE:{} Dry run finished!\n", core!().id);
            }
            context.dry_run = false;
            context.first_exec = false;
            
        }
        else{
            print!("!CORE:{} dry run {} / {} completed with {:?}\n",core!().id ,context.cur_input, context.len_of_inputs, _vmexit);
            context.cur_input+=1;
        }
        // print!("vmexit {:#x?}\n", _vmexit);
        // if _vmexit != VmExit::Exception(Exception::Breakpoint){
        //     print!("vmexit {:#x?}\n", _vmexit);
        // }
        // if _vmexit == (VmExit::EptViolation{
        //     addr: page_table::PhysAddr(0xfee00300),
        //     read: true,
        //     write:false,
        //     exec:false,
        // } ){
        //     print!("tracing\n");
        //     context.debug = true;
        //     print!("traced with {:?}\n", worker.fuzz_case(&mut context));
        //     context.debug = false;
        // }

        context.rdtsc = context.base_rdtsc;
    }
}

//mutate testcase, get's called on each fuzz case
fn inject(_worker: &mut Worker, _context: &mut ContextStructure) {
    // print!("mutating\n");
    // let mut mutator = Mutator::new()
    //     .max_input_size(5 * 1024 * 1024)
    //     .seed(cpu::rdtsc());
    // let fuzz_input = _worker.mutate(&mut mutator);

    //print!("{:x}", _worker.reg(Register::Rip));

    //let mut input = worker.mutate().unwrap();
    let input: [u8; 1] = [0xcc];
    
    
    //_worker.write_virt_from(VirtAddr(BreakPoint::NtCreateFile as u64), &input);
    _worker.write_virt_from(VirtAddr(BreakPoint::Crash as u64), &input);
    //_worker.write_virt_from(VirtAddr(BreakPoint::NtWriteFile as u64), &input);
    _worker.write_virt_from(VirtAddr(BreakPoint::X86usercreatefile as u64), &input);
    //_worker.write_virt_from(VirtAddr(BreakPoint::X86usercreatefiletwo as u64), &input);
    _worker.write_virt_from(VirtAddr(BreakPoint::X86userreadfile as u64), &input);
    //_worker.write_virt_from(VirtAddr(BreakPoint::X86userreadfiletwo as u64), &input);
    _worker.write_virt_from(VirtAddr(BreakPoint::X86userwritefile as u64), &input);
    //_worker.write_virt_from(VirtAddr(BreakPoint::X86userwritefiletwo as u64), &input);
    //_worker.write_virt_from(VirtAddr(BreakPoint::X86userclosehandletwo as u64), &input);
    _worker.write_virt_from(VirtAddr(BreakPoint::X86userclosehandle as u64), &input);
    _worker.write_virt_from(VirtAddr(BreakPoint::X86usergetfilesizeex as u64), &input);
    //_worker.write_virt_from(VirtAddr(BreakPoint::X86usergetfilesizeextwo as u64), &input);
    _worker.write_virt_from(VirtAddr(BreakPoint::End as u64), &input);
    //_worker.write_virt_from(VirtAddr(BreakPoint::Debug as u64), &input);
    _worker.write_virt_from(
        VirtAddr(BreakPoint::X86usersetfilesizepointerex as u64),
        &input,
    );
    _worker.write_virt_from(VirtAddr(BreakPoint::GetSystemTimePreciseAsFileTime as u64), &input);
    //_worker.write_virt_from(VirtAddr(BreakPoint::X86usersetfilesizepointerextwo as u64), &input);
    //_worker.write_virt_from(VirtAddr(BreakPoint::X86userdeletefiletwo as u64), &input);
    _worker.write_virt_from(VirtAddr(BreakPoint::X86userdeletefile as u64), &input); // X86userFlushFileBufferstwo

    //_worker.write_virt_from(VirtAddr(BreakPoint::X86userFlushFileBufferstwo as u64), &input);

    _worker.write_virt_from(VirtAddr(BreakPoint::X86userFlushFileBuffers as u64), &input);

    // _worker.write_virt_from(VirtAddr(BreakPoint::LoadLibraryEx as u64), &input);
    //_worker.write_virt_from(VirtAddr(BreakPoint::NtReadFile as u64), &input);
    // _worker.write_virt_from(VirtAddr(BreakPoint::NtReadFile as u64), &input);
    // _worker.write_virt_from(VirtAddr(BreakPoint::NtWriteFile as u64), &input);
    // inject the input into the target program

    /*
    let mut input: [u8; 60] = [0; 60];
    // inject the input into the target program
    worker.read_virt_into(VirtAddr(rbx), &mut input);
    print!("{:x?}", input);*/

    if !_context.debug && !_context.dry_run{
        _worker.mutate(
            &mut _context.mutator,
        );
        _context.input_size = _context.mutator.input.len();
        _worker.fuzz_input = Some(_context.mutator.input.clone());
    }

    if _context.dry_run{
        let nipo:Vec<u8> = _worker.get_input_at_idx(_context.cur_input).unwrap().to_vec();
        _worker.fuzz_input = Some(nipo);
    }

    


    // let input: Vec<u8> = vec![
    //     0xff, 0x4f, 0xff, 0x51, 0x0, 0x29, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0xfc, 0x0, 0x0,
    //     0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0x0, 0x0, 0x0, 0x0, 0x93, 0x0, 0x0, 0x0,
    //     0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x0,
    //     0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0x51, 0x0, 0x29, 0x0, 0x0, 0x0, 0x4a, 0x0, 0x0, 0x0,
    //     0x0, 0xfc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0,
    //     0x93, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0,
    //     0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    // ];
    // // save the input back
    // _worker.fuzz_input = Some(input.to_vec());
}

// Addresses of handled functions

fn readstack(_worker: &mut Worker, rsp: u64){
    let mut tmp = rsp;
    print!("======== STACK ========\n");
    for x in 0..8{
        print!("{:#x}: {:#x}\n", tmp, _worker.read_virt::<u32>(VirtAddr(tmp)).expect("cant read stack wtf....\n"));
        tmp+=4;
    }
    print!("======== STACK END ========\n");

    // crate::time::sleep(10_000_000);

}   

#[repr(u64)]
#[derive(Debug)]
enum BreakPoint {
    // Addy to CreateFile
    //NtCreateFile = 0xfffff8002ae96000,

    // ReadFile addy
    //NtReadFile = 0xfffff8002aec9ac0,

    // NtWriteFile
    //NtWriteFile = 0xfffff8002ae6e400,

    // End of test case, followed by an immediate exit.

    // nt!KeBugCheckEx
    //Crash = 0xfffff807`68a6d073,

    // ntdll!KiUserExceptionDispatch
    //Crash = 0x7ffd648b3540,

    // // nt!KiPageFault+0x3de
    Crash = 0xfffff80768a6d094,

    LoadLibraryEx = 0x772b1c30 ,
    GetSystemTimePreciseAsFileTime = 0x772be330,
    X86usercreatefile = 0x75c63bb0,
    //X86usercreatefiletwo = 0x756e3bb0,
    X86userwritefile = 0x75c64020,
    //X86userwritefiletwo = 0x756e4020,
    X86userreadfile = 0x75c63f30,
    //X86userreadfiletwo = 0x756e3f30,
    X86userclosehandle = 0x75c63950,
    //X86userclosehandletwo = 0x756e3950,
    X86usergetfilesizeex = 0x772c20a0,
    //X86usergetfilesizeextwo = 0x756e3de0,
    X86usersetfilesizepointerex = 0x75c63fd0,
    //X86usersetfilesizepointerextwo = 0x756e3fd0 ,
    X86userdeletefile = 0x75c63be0,
    //X86userdeletefiletwo = 0x756e3be0 ,
    X86userFlushFileBuffers = 0x75c63d10,
    //X86userFlushFileBufferstwo = 0x756e3d10 ,
    End = 0x00cc6fba,
}
 

fn bphandler(
    _worker: &mut Worker,
    _lpp: &Option<(CoverageRecord, VmExit, BasicRegisterState, u8)>,
    _session: &FuzzSession,
    context: &mut ContextStructure,
) -> bool {
    let rip: BreakPoint = unsafe { core::mem::transmute(_worker.reg(Register::Rip)) };
    if rip as u64 == BreakPoint::Crash as u64 {
        let _lpf = _lpp.as_ref().unwrap();
        // print!("crashed {}\n", _lpf.2);
        _worker.report_crash(_session, &_lpf.0, &_lpf.1, &_lpf.2, _lpf.3);
        return false;
    }
    let rip: BreakPoint = unsafe { core::mem::transmute(_worker.reg(Register::Rip)) };
    //print!("bp handler hit {:?}\n", rip);

    let rsp = _worker.reg(Register::Rsp);
    let return_address = _worker
        .read_virt::<u32>(VirtAddr(rsp))
        .expect("Couldn't read the x86 return address.\n");
    match rip {
        BreakPoint::X86userFlushFileBuffers => {
            return false;
        }
        // BreakPoint::LoadLibraryEx => {
        //     return false;
        //     //print!("loadlibrary\n");
        //     // the utf-16 bytes we read to detect the filename
        //     let mut file_name_bytes: [u8; 16] = [0; 16];

        //     // base of the utf-16 thingy
        //     let addy = _worker.read_virt::<u32>(VirtAddr(rsp+4)).expect("fug\n");

        //     // Raw addy of the utf 16 string
        //     let fname_address = _worker.read_virt::<u64>(VirtAddr(addy as u64)).expect("ss");

        //     // raw utf-16 bytes
        //     _worker.read_virt_into(VirtAddr(fname_address), &mut file_name_bytes);
        //     // print!("{:#x?}\n", file_name_bytes);
        //     // Convert the array from u8 to u16 and convert it to a rust string
        //     let (front, slice, back) = unsafe { file_name_bytes.align_to::<u16>() };
        //     if front.is_empty() && back.is_empty() {
                
        //         print!("{}\n", alloc::string::String::from_utf16(slice).ok().unwrap());
        //     } else {
        //         print!("failed reading lol\n");
        //     };
            
        //     return false;
        // }
        
        BreakPoint::X86userdeletefile => {
            _worker.mod_reg(Register::Rsp, |x| x + 0x8);
            _worker.set_reg(Register::Rip, return_address as u64);
            _worker.set_reg(Register::Rax, 1);
            return true;
        }
        // make this work with seek n shit
        BreakPoint::X86usersetfilesizepointerex => {
            // print!("current state before setfilepointer {}\n", context.input_offset);
            let addr_to_requested_offset = rsp+8;
            let requested_offset = _worker
                .read_virt::<i32>(VirtAddr(addr_to_requested_offset)).expect("base setfilepointer failed");

            let addr = rsp + 16;
            let base_large_integer = _worker
                .read_virt::<u32>(VirtAddr(addr)).expect("base setfilepointer failed");
                
                //print!("adding {} {}\n", requested_offset, context.input_offset);
            let dwmovemethod_addy = rsp + 20;
            let dwmovemethod = _worker
                .read_virt::<u32>(VirtAddr(dwmovemethod_addy)).expect("base setfilepointer failed");
            match dwmovemethod{
                0 => {context.input_offset=requested_offset as usize;}
                1 => {context.input_offset+=requested_offset as usize;}
                2 => {context.input_offset=context.input_size+requested_offset as usize;}
                _ => {unimplemented!("bad dwmovemethod\n");}
            }
            // print!("adding {} {} movemethod {}\n", requested_offset, context.input_offset, dwmovemethod);
            _worker.write_virt::<u64>(VirtAddr(base_large_integer as u64), context.input_offset as u64);

            _worker.mod_reg(Register::Rsp, |x| x + 0x18);
            _worker.set_reg(Register::Rip, return_address as u64);
            _worker.set_reg(Register::Rax, 1);
            // print!("current state after setfilepointer {}\n", context.input_offset);
            return true;
        }
        BreakPoint::X86usercreatefile => {
            _worker.mod_reg(Register::Rsp, |x| x + 0x20);
            _worker.set_reg(Register::Rip, return_address as u64);
            _worker.set_reg(Register::Rax, 0x696);
            return true;
        }
        BreakPoint::GetSystemTimePreciseAsFileTime =>{
            let addr = rsp+0x4;
            let base_large_integer = _worker
                .read_virt::<u32>(VirtAddr(addr));
            context.rdtsc+=5000000;
            if base_large_integer !=None{
                _worker.write_virt::<u64>(VirtAddr(base_large_integer.unwrap() as u64), context.rdtsc );
                _worker.mod_reg(Register::Rsp, |x| x + 0x8);
            }
            return true;
        }
        BreakPoint::X86usergetfilesizeex => {
            let addr = rsp + 0x8;
            let base_large_integer = _worker
                .read_virt::<u32>(VirtAddr(addr))
                .expect("Couldn't get the virtaddr of the large integer.\n");

            let size = _worker.fuzz_input.as_ref().unwrap().len();

            // file size
            _worker.write_virt::<u64>(VirtAddr(base_large_integer as u64), size as u64);

            // inject the input into the target program
            _worker.mod_reg(Register::Rsp, |x| x + 0xc);
            _worker.set_reg(Register::Rip, return_address as u64);
            _worker.set_reg(Register::Rax, 1);
            return true;
        }
        BreakPoint::X86userclosehandle => {
            _worker.mod_reg(Register::Rsp, |x| x + 0x8);
            _worker.set_reg(Register::Rip, return_address as u64);
            _worker.set_reg(Register::Rax, 1);
            return true;
        }
        BreakPoint::X86userwritefile => {
            return false;
            // // Ignore, but write back the len, as if we wrote to a file
            // // print!("X86userwritefile\n");
            // let addy_to_lp_number_of_bytes_written = rsp + 16;
            // let write_back_addy = _worker
            //     .read_virt::<u32>(VirtAddr(addy_to_lp_number_of_bytes_written))
            //     .expect("Couldn't get the addy ptr to bytes_written\n");

            // let len_addr = rsp + 0xc;
            // let len = _worker
            //     .read_virt::<u32>(VirtAddr(len_addr))
            //     .expect("couldn't get the\n");

            // // write back len to bytes_written
            // _worker.write_virt::<u32>(VirtAddr(write_back_addy as u64), len);
            // _worker.mod_reg(Register::Rsp, |x| x + 0x18);
            // _worker.set_reg(Register::Rip, return_address as u64);
            // _worker.set_reg(Register::Rax, 1);
            // return true;
        }
        BreakPoint::X86userreadfile => {
            // print!("current state before readfile {}\n", context.input_offset);
            let addy_to_lp_number_of_bytes_written = rsp + 16;
            let write_back_addy = _worker
                .read_virt::<u32>(VirtAddr(addy_to_lp_number_of_bytes_written))
                .expect("couldn't get bytes_read ptr\n");

            let len_addr = rsp + 12;
            let len = _worker
                .read_virt::<u32>(VirtAddr(len_addr))
                .expect("couldn't get read length\n");
            
            // print!("len: {}\n", len);

            // DETERMINE WHETHER TO WRITE TO BUF OR BUF_ADDR
            let buf_addr = rsp + 0x8;
            let buf = _worker
                .read_virt::<u32>(VirtAddr(buf_addr))
                .expect("couldn't get buf addy\n");
            // print!("buf_addr {:#x}\n", buf);
            //print!("buf_buf {:#x}\n", )
            // Write back the fuzz_input into the guest memory.
            let input = _worker.fuzz_input.take().unwrap();

            let slice = if input.len()>=len as usize{
                &input[context.input_offset..context.input_offset+len as usize]
            }
            else{
                &testslice[0..len as usize]
            };
            //print!("slice {}")
            let tx = _worker
                .write_virt_from(VirtAddr(buf as u64), slice);
            if tx ==None{
                print!("I JUST FAILED TO WRITE INTO IT {} {}\n", len, slice.len());
            }

            // let mut inputt: [u8; 16] = [0; 16];
            // // inject the input into the target program
            // _worker.read_virt_into(VirtAddr(buf as u64), &mut inputt);
            // print!("{:#x?}", inputt);

            _worker
                .write_virt::<u32>(VirtAddr(write_back_addy as u64), len)
                .expect("error len writing\n");
            _worker.mod_reg(Register::Rsp, |x| x + 24);

            _worker.set_reg(Register::Rip, return_address as u64);
            _worker.set_reg(Register::Rax, 0x1);
            _worker.fuzz_input = Some(input);
            context.input_offset +=len as usize;
            // print!("current state after readfile {}\n", context.input_offset);
            return true;
        }
        // BreakPoint::Crash => {
        //     let _lpf = _lpp.as_ref().unwrap();
        //     // print!("crashed {}\n", _lpf.2);
        //     _worker.report_crash(_session, &_lpf.0, &_lpf.1, &_lpf.2, _lpf.3);
        //     return false;
        // }
        BreakPoint::End => {
            //print!("case finished\n");
            return false;
        }
        _ => {
            print!("unexpected! {:#x} \n", _worker.reg(Register::Rip));
            return false;
        } // _ => {
          //     panic!("bad ptr addy: {:x}\n", _worker.reg(Register::Rip))
          // }
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
          //     let fname_address = _worker.read_virt::<u64>(VirtAddr(addy)).expect("ss");

          //     // raw utf-16 bytes
          //     _worker.read_virt_into(VirtAddr(fname_address), &mut file_name_bytes);

          //     // Convert the array from u8 to u16 and convert it to a rust string
          //     let (front, slice, back) = unsafe { file_name_bytes.align_to::<u16>() };
          //     let fname: alloc::string::String = if front.is_empty() && back.is_empty() {
          //         alloc::string::String::from_utf16(slice).ok()
          //     } else {
          //         None
          //     }
          //     .expect(" lol");

          //     print!("fname {}\n", fname);

          //     // not sure if its supposed to be u32 or u64, to be tested

          //     // Create handle
          //     let handle: i32 = if fname == "" { 0x6969 } else { -1 };

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
    }
}
