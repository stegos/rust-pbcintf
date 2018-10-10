extern crate rust_libpbc;

const INIT_TEXT : &[u8;359] = b"
type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1";

fn main() {
    let psize: [u64;4] = [0;4];
    unsafe {
      let ans = rust_libpbc::init_pairing(0 as u64,
                    INIT_TEXT.as_ptr() as *mut _,
                    INIT_TEXT.len() as u64,
                    psize.as_ptr() as *mut _);
        assert_eq!(ans, 0);
    }
    println!("Sizes = {:?}", psize);

    println!("Hello, world!");
    let input = "hello!".as_bytes();
    let output: Vec<u8> = vec![0; input.len()];
    unsafe {
        let echo_out = rust_libpbc::echo(
            input.len() as u64,
            input.as_ptr() as *mut _,
            output.as_ptr() as *mut _,
        );
        assert_eq!(echo_out, input.len() as u64);
        assert_eq!(input.to_vec(), output);
    }
    let out_str: String = std::str::from_utf8(&output).unwrap().to_string();
    println!("Echo Output: {}", out_str);
}
