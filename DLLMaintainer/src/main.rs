use std::ffi::c_void;
use std::ptr;
use std::{env, fs};
use std::path::{Path, PathBuf};
use std::vec::Vec;
use std::time::Duration;


type Error = u32;
type FnMessageBox = extern "stdcall" fn(hWnd: *const c_void, lpText: *const u16, lpCaption: *const u16, uType: u32) -> i32;

#[repr(C)]
#[derive(Debug)]
struct ModuleInfo{
    LpBaseOfDll: u32,
    SizeOfImage: u32,
    EntryPoint:  u32,
}

#[link(name = "kernel32")]
#[no_mangle]
extern "stdcall" {
    fn GetLastError() -> Error;
    fn LoadLibraryExW(lpLibFileName: *const u16, hFile: *const c_void, dwFlags: u32) -> *const c_void;
    fn FreeLibrary(hLibModule: *const c_void) -> i32;
    fn GetProcAddress(hModule: *const c_void, lpProcName: *const u8) -> *const c_void;
    fn LoadLibraryW(lpLibFileName: *const u16) -> *const c_void;
    fn GetCurrentProcess() -> *const c_void;
}

#[link(name = "psapi")]
#[no_mangle]
extern "stdcall" {
    fn GetModuleInformation(hProcess:  *const c_void, hModule:  *const c_void, lpmoduleinfo: *mut ModuleInfo, cb:usize) -> Error;
}

fn main() {
    // unsafe {
    //     let h = LoadLibraryExW("user32.dll".to_nullterminated_u16().as_ptr(),
    //                            ptr::null(),
    //                            0x800).to_result().unwrap();
    //     print!("{:?}", h);
    //     let p = GetProcAddress(h, "MessageBoxW\0".as_ptr()).to_result().unwrap();
    //     let fn_message_box = std::mem::transmute::<_, FnMessageBox>(p);

    //     fn_message_box(ptr::null(),
    //                    "Hello, Rust!".to_nullterminated_u16().as_ptr(),
    //                    "MessageBox".to_nullterminated_u16().as_ptr(),
    //                    0);

    //     FreeLibrary(h);
    // }
    let vecc = traverse_dll(&env::current_dir().expect("bruh"));
    
    for x in vecc.iter(){
        let in_str = x.as_path().display().to_string();
        print!("checking {}\n", in_str);
        //let h = unsafe {LoadLibraryW(in_str.to_nullterminated_u16().as_ptr()) };
        let dd = unsafe{LoadLibraryExW(in_str.to_nullterminated_u16().as_ptr(),
                        ptr::null(),
                        0x0).to_result()};
        
        if dd.is_err(){
            continue;
        }
        print!("loading {}\n", in_str);
        let h = dd.unwrap();
        print!("{:?}\n", h);

        /*
        struct ModuleInfo{
            LpBaseOfDll:*const c_void,
            SizeOfImage: u32,
            EntryPoint: *const c_void,
        }
        */

        let mut base:u32 = 0;
        let mut entryp:u32 = 0;
        let mut fgd: ModuleInfo = ModuleInfo{
            LpBaseOfDll: 0,
            SizeOfImage: 0,
            EntryPoint: 0,
        };
        unsafe {GetModuleInformation(GetCurrentProcess(), h, &mut fgd as *mut ModuleInfo, core::mem::size_of::<ModuleInfo>())};

        unsafe {print!("{:#x?}\n",fgd )};

        // ModuleInfo { LpBaseOfDll: 0x57b80000, SizeOfImage: 11640832, EntryPoint: 0x57d70e63 } 0x905a4d 0x83ec8b55\
        unsafe{

            // 0x5a7e8000
            let mut x = fgd.LpBaseOfDll;
            let bruhs = x as *mut u32;
            print!("read {:#x} {:?}\n", *bruhs, bruhs);
            print!("{:#x?}\n", fgd.LpBaseOfDll+fgd.SizeOfImage);
            while x != fgd.LpBaseOfDll+fgd.SizeOfImage{
                //print!("x: {:?}\n", x);
                let bruh = x as *mut u32;
                let fags: u32 =  *bruh ;
                //print!("fags : {}\n", fags);
                x+=4;
            }
        }
        // if this does not help, maybe try to get module size 
        // and read the module out of memory byte by byte

        // https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmoduleinformation

    }
    print!("done\n");


    let tim = Duration::from_secs(10000000000000000);

    std::thread::sleep(tim);
}

fn traverse_dll(dir: &Path) -> Vec<PathBuf>{
    traverse_extension(dir, "dll")
}

fn traverse_extension(dir: &Path, extension: &str) -> Vec<PathBuf>{
    let mut ret: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir).expect("COULD NOT READ THIS DIR") {
        let entry = entry.expect("Path Entry is invalid.").path();

        if entry.is_dir(){
            ret.append(&mut traverse_extension(&entry, extension));   
        }
        else{
            if entry.extension() == None{
                continue;
            }
            if entry.extension().unwrap() == extension{
                ret.push(entry);
            }
            
        }
    }
    ret
}
fn traverse(dir: &Path) -> Vec<PathBuf>{
    let mut ret: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir).expect("COULD NOT READ THIS DIR") {
        let entry = entry.expect("Path Entry is invalid.").path();

        if entry.is_dir(){
            ret.append(&mut traverse(&entry));   
        }
        else{
            ret.push(entry);
        }
    }
    ret
}

trait ToResult: Sized {
    fn to_result(&self) -> Result<Self, Error>;
}

impl ToResult for *const c_void {
    fn to_result(&self) -> Result<*const c_void, Error> {
        if *self == ptr::null() {
            unsafe {
                Err(GetLastError())
            }
        } else {
            Ok(*self)
        }
    }
}

trait IntoNullTerminatedU16 {
    fn to_nullterminated_u16(&self) -> Vec<u16>;
}

impl IntoNullTerminatedU16 for str {
    fn to_nullterminated_u16(&self) -> Vec<u16> {
        self.encode_utf16().chain(Some(0)).collect()
    }
}