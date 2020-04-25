//! Network mapped memory

use core::ops::{Deref, DerefMut};
use core::alloc::Layout;
use core::convert::TryInto;
use alloc::boxed::Box;
use alloc::borrow::Cow;
use noodle::*;
use falktp::ServerMessage;
use page_table::{VirtAddr, PageType, PhysMem};
use page_table::{PAGE_NX, PAGE_WRITE, PAGE_PRESENT};
use crate::mm::{self, PhysicalMemory};
use crate::net::{NetDevice, UdpAddress, UdpBind};
use crate::interrupts::{register_fault_handler, FaultReg, PageFaultHandler};

/// Structure to handle `NetMapping` page faults
pub struct NetMapHandler {
    /// Virtual address of the base of the mapping
    vaddr: VirtAddr,

    /// A UDP port which we are bound to and able to recv from and send to
    udp: UdpBind,
    
    /// File ID of the open file on the server
    file_id: u64,

    /// Size of the file in bytes
    size: usize,

    /// Address of the server we are communicating with
    server: UdpAddress,
}

impl PageFaultHandler for NetMapHandler {
    unsafe fn page_fault(&mut self, fault_addr: VirtAddr) -> bool {
        // Compute the ending virtual address for our mapping
        let end = VirtAddr(self.vaddr.0 + (self.size as u64 - 1));

        // Check if this fault happened in our mapping range
        if fault_addr >= self.vaddr && fault_addr <= end {
            // Compute the offset into the mapping that this fault represents
            // and page align it
            let offset = ((fault_addr.0 & !0xfff) - self.vaddr.0) as usize;
            
            // Allocate the backing page for the mapping
            let page = {
                // Get access to physical memory
                let mut pmem = PhysicalMemory;

                // Allocate a page
                pmem.alloc_phys(Layout::from_size_align(4096, 4096).unwrap())
            };

            // Get a mutable slice to the physical memory backing the page
            let new_page = mm::slice_phys_mut(page, 4096);
                
            // Compute the number of bytes we expect to receive
            let to_recv = core::cmp::min(4096, self.size - offset);

            let mut retries = 0;
            'retry: loop {
                retries += 1;
                if retries > 100 {
                    panic!("Failed to download backing page");
                }

                // Request the file contents at this offset
                let mut packet = self.udp.device().allocate_packet();
                {
                    let mut pkt = packet.create_udp(&self.server);
                    ServerMessage::Read {
                        id:     self.file_id,
                        offset: offset,
                        size:   to_recv,
                    }.serialize(&mut pkt).unwrap();
                }
                self.udp.device().send(packet, true);

                // Wait for a success
                if self.udp.recv_timeout(100_000, |_, udp| {
                    let mut ptr = &udp.payload[..];
                    match ServerMessage::deserialize(&mut ptr)? {
                        ServerMessage::ReadOk  => Some(()),
                        ServerMessage::ReadErr =>
                            panic!("Could not satisfy network mapping read"),
                        _ => unreachable!(),
                    }
                }).is_none() {
                    // Retry
                    continue 'retry;
                }

                // Receive the raw payload
                let mut recv_off = 0;
                while recv_off < to_recv {
                    // Receive packets until we got everything we expected
                    if self.udp.recv_timeout(100_000, |_, udp| {
                        assert!(udp.payload.len() <= to_recv - recv_off,
                            "Whoa, larger packet than expected");

                        // Copy the payload into the page
                        new_page[recv_off..recv_off + udp.payload.len()]
                            .copy_from_slice(&udp.payload);

                        recv_off += udp.payload.len();
                        Some(())
                    }).is_none() {
                        continue 'retry;
                    }
                }

                // Received everything!
                break;
            }

            // Get access to physical memory
            let mut pmem = PhysicalMemory;

            // Get access to virtual memory
            let mut page_table = core!().boot_args.page_table.lock();
            let page_table = page_table.as_mut().unwrap();

            // Map in the memory as RW
            page_table.map_raw(&mut pmem,
                               VirtAddr(fault_addr.0 & !0xfff),
                               PageType::Page4K,
                               page.0 | PAGE_NX | PAGE_WRITE | PAGE_PRESENT)
                .expect("Failed to map in network mapped memory");

            true
        } else {
            false
        }
    }
}

/// A network backed mapping of `u8`s which will be faulted in upon access per
/// page
pub struct NetMapping<'a>(&'a mut [u8], FaultReg);

impl<'a> NetMapping<'a> {
    /// Create a network mapped view of `filename`
    /// `server` should be the `ip:port` for the server
    pub fn new(server: &str, filename: &str) -> Option<Self> {
        // Get access to a network device
        let netdev = NetDevice::get()?;

        // Bind to a random UDP port on this network device
        let udp = NetDevice::bind_udp(netdev.clone())?;

        // Resolve the target
        let server = UdpAddress::resolve(
            &netdev, udp.port(), server)
            .expect("Couldn't resolve target address");

        // Allocate a packet
        let mut packet = netdev.allocate_packet();
        {
            let mut pkt = packet.create_udp(&server);
            ServerMessage::GetFileId(Cow::Borrowed(filename))
                .serialize(&mut pkt).unwrap();
        }
        netdev.send(packet, true);

        // Wait for the response packet
        let (file_id, size) = udp.recv_timeout(5_000_000, |_, udp| {
            // Deserialize the message
            let mut ptr = &udp.payload[..];
            let msg = ServerMessage::deserialize(&mut ptr)
                .expect("Failed to deserialize File ID response");

            match msg {
                ServerMessage::FileId { id, size } => Some(Some((id, size))),
                ServerMessage::FileIdErr           => Some(None),
                _ => unreachable!(),
            }
        })??;

        // Nothing to map
        if size <= 0 { return None; }

        // Allocate virtual memory capable of holding the file
        let size_align = size.checked_add(0xfff)? & !0xfff;
        let virt_addr  = crate::mm::alloc_virt_addr_4k(size_align as u64);

        // Create a fault handler entry
        let handler = Box::new(NetMapHandler {
            vaddr:   virt_addr,
            file_id: file_id,
            udp:     udp,
            size:    size,
            server:  server,
        });

        Some(NetMapping(
            unsafe {
                core::slice::from_raw_parts_mut(virt_addr.0 as *mut u8,
                                                size.try_into().ok()?)
            },
            register_fault_handler(handler),
        ))
    }
}

impl<'a> Deref for NetMapping<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> DerefMut for NetMapping<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

