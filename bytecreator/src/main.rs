
fn main() {
    let minidump = std::fs::read("python.jpg").unwrap();
    print!("{:#x?}", minidump);
}
