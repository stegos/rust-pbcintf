extern crate rust_libpbc;

fn main() {
    println!("Hello, world!");
    let input = "hello!".as_bytes();
    let output: Vec<u8> = vec!(0; input.len());
    unsafe {
      let echo_out = rust_libpbc::echo(input.len() as u64, input.as_ptr() as *mut _, output.as_ptr()  as *mut _);
      assert_eq!(echo_out, input.len() as u64);
      assert_eq!(input.to_vec(), output);
    }
    let out_str: String = std::str::from_utf8(&output).unwrap().to_string();
    println!("Echo Output: {}", out_str);
}
