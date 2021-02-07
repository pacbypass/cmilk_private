
fn main() {
    let minidump = std::fs::read("warning.gif").unwrap();
    print!("vec!{:#x?};", minidump);
}
