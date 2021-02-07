use core::any::Any;
use alloc::sync::Arc;
use alloc::boxed::Box;
use page_table::*;

use crate::vtx::*;
use crate::core_locals::LockInterrupts;
use crate::fuzz_session::{Worker, FuzzSession};

use lockcell::LockCell;

static null_vec: &'static [u8] = &[0,0,0,0];

pub fn fuzz() {
    if core!().id != 0 { cpu::halt(); }
    //if core!().id >= 24 { cpu::halt(); }

    static SESSION:
        LockCell<Option<Arc<FuzzSession>>, LockInterrupts> =
        LockCell::new(None);

    // Create the master snapshot, and fork from it for all cores
    let session = {
        let mut session = SESSION.lock();
        if session.is_none() {
            print!("LETS FUZZ!\n");
            *session = Some(
                Arc::new(FuzzSession::from_falkdump(
                        "192.168.101.1:1911", "test.falkdump", |_worker| {
                    // Mutate the master at this point
                })
                .timeout(1_000_000)
                .inject(inject))
            );
        }
        session.as_ref().unwrap().clone()
    };

    let mut worker = FuzzSession::worker(session);
    
    // Set that this is a Windows guest
    worker.enlighten(Some(Box::new(
                crate::fuzz_session::windows::Enlightenment::default())));

    loop {
        let _vmexit = worker.fuzz_case(&mut ());
    }
}

fn inject(worker: &mut Worker, _context: &mut dyn Any) {
    let mut input = worker.fuzz_input.take().unwrap();
    worker.fuzz_input = Some(input);
}

fn vmexit_handler(worker: &mut Worker, vmexit: &VmExit){
    //createfile
    let createfile_addr: u64 = 11;

    // kernelbase!readfile
    let readfile_addr: u64 = 9;

    //getfilesize 
    let getfilesize_addr: u64 = 10;
    match vmexit {
        VmExit::Exception(Exception::Breakpoint) => {
            //kernelbase!readfile handler
            let rip = worker.reg(Register::Rip);
            if  worker.fuzz_input != None {
                match rip {
                    readfile_addr => {

                        /*
                        BOOL ReadFile(
                            HANDLE       hFile,
                            LPVOID       lpBuffer,
                            DWORD        nNumberOfBytesToRead,
                            LPDWORD      lpNumberOfBytesRead,
                            LPOVERLAPPED lpOverlapped
                        );
                        */

                        //temporary buffer
                        let mut buf = [0u8; 8];


                        let rsp = worker.reg(Register::Rsp);
                        let rdx = worker.reg(Register::Rdx);
                        
                        let r9 = worker.reg(Register::R9);

                        //where we should jump to after this read
                        worker.read_virt_into(VirtAddr(rsp), &mut buf);
                        let jmp_addr = u64::from_le_bytes(buf);

                        // handle to file
                        let handle = worker.reg(Register::Rcx);

                        // buffer address
                        worker.read_virt_into(VirtAddr(rdx), &mut buf);
                        let buf_addr = u64::from_le_bytes(buf);

                        //buffer length
                        let buf_len = worker.reg(Register::R8);

                        //bytes_read
                        worker.read_virt_into(VirtAddr(r9), &mut buf);
                        let bytes_read = u64::from_le_bytes(buf);

                        //the input that gets copied
                        let input = worker.fuzz_input.take().unwrap()[0..buf_len as usize].to_vec();

                        //write the input to the file reader
                        worker.write_virt_from(VirtAddr(buf_addr), input.as_slice());

                        //write the bytes_read value
                        let len = input.len().to_le_bytes();
                        worker.write_virt_from(VirtAddr(bytes_read), &len);

                        //jumping back into the executable
                        worker.set_reg(Register::Rip, jmp_addr);

                        //return value success
                        worker.set_reg(Register::Rax, 0x1 as u64);

                    }
                    getfilesize_addr =>{

                        /*
                        DWORD GetFileSize(
                            HANDLE  hFile,
                            LPDWORD lpFileSizeHigh
                        );
                        */

                        //filehandle
                        let handle = worker.reg(Register::Rcx);

                        let lpFileSizeHigh = worker.reg(Register::Rdx);
    
                        let input = worker.fuzz_input.take().unwrap();
    
                        let len = input.len();
                        
                        worker.set_reg(Register::Rax, len as u64);
    
                        if lpFileSizeHigh != 0{
                            worker.write_virt_from(VirtAddr(lpFileSizeHigh), null_vec);
                        }
                    }
                    createfile_addr =>{
                        unimplemented!("AAAAAAAAAAAAAAA");
                    }
                }
            }
            
        }

        _ =>
        {
            
        }
    }
}
