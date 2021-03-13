
fn main() {
    let minidump = std::fs::read("PoC.gif").unwrap();
    print!("vec!{:#x?};", minidump);
}
