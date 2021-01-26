use crate::core_locals::LockInterrupts;
use crate::fuzz_session::{BasicRegisterState, FuzzSession, Worker};
use crate::vtx::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::any::Any;
use falktp::CoverageRecord;
use page_table::VirtAddr;

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
                FuzzSession::from_falkdump("192.168.2.175:1911", "32bit.falkdump", |_worker| {})
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

//mutate testcase, get's called on each fuzz case
fn inject(_worker: &mut Worker, _context: &mut dyn Any) {

    //injection point
    //let rbx = worker.reg(Register::Rbx);

    //get and reset the imput
    /*let mut input = worker.fuzz_input.take().unwrap();
    input.clear();

    // use an input from the corpus, we're
    // assuming that corpus is not empty
    let inp = worker.rand_input();
    input.extend_from_slice(inp.unwrap());

    // Corrupt the input
    if input.len() > 0 {
        let il = input.len();
        for _ in 0.. worker.rng.rand() % 64 {
            input[worker.rng.rand() % il] = worker.rng.rand() as u8;
        }
    }
    */

    //let mut input = worker.mutate().unwrap();
    //let mut input: [u8; 1] = [0xcc];
    // inject the input into the target program
    //worker.write_virt_from(VirtAddr(rbx), &input);
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
    CreateFile = 0x0,

    // ReadFile addy
    ReadFile = 0xe,

    // End of test case, followed by an immediate exit.
    CaseEnd = 0x34,
    //SPROBUJ PUSCIC TYLKO Z READFILE I CREATEFILE i zobaczymy

    //sprawdz czy ntreadfile czyta caly plik tak non stop, czy czyta od danego momentu do ktoregos, czy ma jakis index albo cos

    // NtQueryInformationFile PROB NEEDED LUL
    //NtQueryAttributesFile <- may be needed, nvm maybe not
}

fn bphandler(
    _worker: &mut Worker,
    _lpf: &(CoverageRecord, VmExit, BasicRegisterState, u8),
) -> bool {
    print!("bp handler hit");

    let rip: BreakPoint = unsafe { core::mem::transmute(_worker.reg(Register::Rip)) };
    match rip {
        BreakPoint::ReadFile => {
            /*
            3: kd> r
            rax=fffff8024d8d5ac0 rbx=ffff980659fbb080 rcx=0000000000000e7c
            rdx=0000000000000000 rsi=000000f22b27eb68 rdi=ffffa90e18162be8
            rip=fffff8024d8d5ac0 rsp=ffffa90e18162bc8 rbp=ffffa90e18162cc0
            r8=0000000000000000  r9=0000000000000000 r10=fffff8024d8d5ac0
            r11=fffff8024d3e55b8 r12=0000028d2ef2fca0 r13=0000000000000000
            r14=0000000000000000 r15=0000000000001000
            iopl=0         nv up ei pl zr na po nc
            cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
            nt!NtReadFile:
            fffff802`4d8d5ac0 4c894c2420      mov     qword ptr [rsp+20h],r9 ss:0018:ffffa90e`18162be8=0000000000000008
            3: kd> dd poi(rsp+30)
            0000028d`2ef2fca0  00000000 00000000 00000000 00000000
            0000028d`2ef2fcb0  00000000 00000000 00000000 00000000
            0000028d`2ef2fcc0  00000000 00000000 00000000 00000000
            0000028d`2ef2fcd0  00000000 00000000 00000000 00000000
            0000028d`2ef2fce0  00000000 00000000 00000000 00000000
            0000028d`2ef2fcf0  00000000 00000000 00000000 00000000
            0000028d`2ef2fd00  00000000 00000000 00000000 00000000
            0000028d`2ef2fd10  00000000 00000000 00000000 00000000

            */

            // add support for file size-related operations ETC.
            // we need to support "PLARGE_INTEGER   ByteOffset" <- kinda done
            // add support for checking handles with our global handle database...
            // or just compare it with the global 0x6969 handle

            let mut start_offset = 0;

            let buffer_addr = VirtAddr(_worker.reg(Register::Rsp) + 0x30);
            let length_addr = VirtAddr(_worker.reg(Register::Rsp) + 0x34);

            // Location in memory of the pointer
            let byte_offset_addr = VirtAddr(_worker.reg(Register::Rsp) + 0x38);

            // Read pointer from memory
            let byte_offset_ptr = _worker
                .read_virt::<u64>(byte_offset_addr)
                .expect("fugffff\n");

            // Check if it's a nullptr
            if byte_offset_ptr != 0 {
                print!("reading byte offset from {:x}", byte_offset_ptr);
                start_offset = _worker
                    .read_virt::<u64>(VirtAddr(byte_offset_ptr))
                    .expect("fugffff\n");
            }

            let addy_buf = _worker.read_virt::<u64>(buffer_addr).expect("fugffff\n");
            let length = _worker.read_virt::<u64>(length_addr).expect("fugffff\n");

            // improve performance of this, try doing this without
            let slice = _worker.fuzz_input.take().unwrap();

            // make sure that casting to usize doesnt fuck it up
            let input = &slice[start_offset as usize..length as usize];

            // write back the file to our nig nog
            _worker.write_virt_from(VirtAddr(addy_buf), input);
            _worker.set_reg(Register::Rax, 0);

            _worker.fuzz_input = Some(slice);

            return true;
        }

        BreakPoint::CreateFile => {
            /*
            1: kd> r
            rax=fffff8024d8a2000 rbx=ffff98065260c080 rcx=000000e2fe9fc570
            rdx=0000000080100080 rsi=000000e2fe9fc518 rdi=ffffa90e18853be8
            rip=fffff8024d8a2000 rsp=ffffa90e18853bc8 rbp=ffffa90e18853cc0
            r8=000000e2fe9fc5c8  r9=000000e2fe9fc588 r10=fffff8024d8a2000
            r11=fffff8024d3e55a8 r12=0000000000000000 r13=0000000080100080
            r14=0000000000000000 r15=0000000000000000
            iopl=0         nv up ei pl zr na po nc
            cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
            nt!NtCreateFile:
            fffff802`4d8a2000 4881ec88000000  sub     rsp,88h
            1: kd> du poi(poi(r8+10)+8)
            000001ec`1605b7c0  "\??\C:\Windows\Prefetch\SVCHOST."
            000001ec`1605b800  "EXE-EE1C9ACA.pf"

            */

            // the utf-16 bytes we read to detect the filename
            let mut file_name_bytes: [u8; 128] = [0; 128];

            // ObjectAttributes+10h -> PTR to utf-16 string
            let object_attributes = VirtAddr(_worker.reg(Register::R8) + 0x10);

            // base of the utf-16 thingy
            let addy = _worker.read_virt::<u64>(object_attributes).expect("fug\n") + 8;

            // Raw addy of the utf 16 string
            let fname_address = _worker.read_virt::<u64>(VirtAddr(addy)).expect("nig");

            // raw utf-16 bytes
            _worker.read_virt_into(VirtAddr(fname_address), &mut file_name_bytes);

            // Convert the array from u8 to u16 and convert it to a rust string
            let (front, slice, back) = unsafe { file_name_bytes.align_to::<u16>() };
            let fname: alloc::string::String = if front.is_empty() && back.is_empty() {
                alloc::string::String::from_utf16(slice).ok()
            } else {
                None
            }
            .expect("niggacheese lol");

            print!("fname {}\n", fname);

            // not sure if its supposed to be u32 or u64, to be tested

            // Create handle
            let handle: i32 = if fname == "nigger" { 0x6969 } else { -1 };

            // write back our fake handle
            _worker.set_reg(Register::Rax, 0);
            let addr = VirtAddr(_worker.reg(Register::Rcx));
            _worker.write_virt::<i32>(addr, handle);

            return true;
        }
        BreakPoint::CaseEnd => {
            return false;
        }
    }
}
