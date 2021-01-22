use core::any::Any;
use alloc::sync::Arc;
use alloc::boxed::Box;

use crate::vtx::*;
use crate::core_locals::LockInterrupts;
use falktp::CoverageRecord;
use crate::fuzz_session::{Worker, FuzzSession, BasicRegisterState};

use lockcell::LockCell;

//const SIZE: usize = 20000;
pub fn fuzz() {
    //if core!().id != 0 { cpu::halt(); }

    static SESSION:
        LockCell<Option<Arc<FuzzSession>>, LockInterrupts> =
        LockCell::new(None);

    // Create the master snapshot, and fork from it for all cores
    let session = {
        let mut session = SESSION.lock();
        if session.is_none() {
            // for _ in 0..26 {
            //     print!("\n");
            // }
            print!("LETS FUZZ! 192.168.2.175:1911\n");
            *session = Some(
                Arc::new(FuzzSession::from_falkdump(
                        "192.168.2.175:1911", "32bit.falkdump", |_worker| {
                })
                .timeout(1_000_000_000)
                .inject(inject)
                .bp_handler(bphandler))
            );
        }
        session.as_ref().unwrap().clone()
    };

    let mut worker = FuzzSession::worker(session);
    
    // Set that this is a Windows guest
    worker.enlighten(Some(Box::new(
                crate::fuzz_session::windows::Enlightenment::default())));
    print!("nigger");
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

fn bphandler(_worker: &mut Worker, _lpf: &(CoverageRecord, VmExit, BasicRegisterState, u8)) -> bool{
    print!("bp handler hit");
    return true;
}

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
