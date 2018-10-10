extern crate rust_libpbc;
// extern crate rust_gmp;

use std::fmt;
use std::mem;

const PBC_CONTEXT_AR160 : u8 = 0;
const NAME_AR160 : &str = "AR160";
const INIT_TEXT_AR160 : &str = "type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1";
const G1_FR256 : &str = "ff8f256bbd48990e94d834fba52da377b4cab2d3e2a08b6828ba6631ad4d668500";
const G2_FR256 : &str = "e20543135c81c67051dc263a2bc882b838da80b05f3e1d7efa420a51f5688995e0040a12a1737c80def47c1a16a2ecc811c226c17fb61f446f3da56c420f38cc01";


const PBC_CONTEXT_FR256 : u8 = 1;
const NAME_FR256 : &str = "FR256";
const INIT_TEXT_FR256 : &str = "type f
q 115792089237314936872688561244471742058375878355761205198700409522629664518163
r 115792089237314936872688561244471742058035595988840268584488757999429535617037
b 3
beta 76600213043964638334639432839350561620586998450651561245322304548751832163977
alpha0 82889197335545133675228720470117632986673257748779594473736828145653330099944
alpha1 66367173116409392252217737940259038242793962715127129791931788032832987594232";
const G1_AR160 : &str = "797EF95B4B2DED79B0F5E3320D4C38AE2617EB9CD8C0C390B9CCC6ED8CFF4CEA4025609A9093D4C3F58F37CE43C163EADED39E8200C939912B7F4B047CC9B69300";
const G2_AR160 : &str = "A4913CAB767684B308E6F71D3994D65C2F1EB1BE4C9E96E276CD92E4D2B16A2877AA48A8A34CE5F1892CD548DE9106F3C5B0EBE7E13ACCB8C41CC0AE8D110A7F01";

struct PBCInfo {
    context      : u8,
    name         : *const str,
    text         : *const str,
    g1_size      : u16,
    g2_size      : u16,
    pairing_size : u16,
    field_size   : u16,
    g1           : *const str,
    g2           : *const str
}

fn bv_to_str(x : &[u8]) -> String {
    let mut s = String::new();
    for ix in 0 .. x.len() {
        s.push_str(&format!("{:02x}", x[ix]));
    }
    s
}

const CURVES : &[PBCInfo] = &[
    PBCInfo {
        context      : PBC_CONTEXT_AR160,
        name         : NAME_AR160,
        text         : INIT_TEXT_AR160,
        g1_size      :  65,
        g2_size      :  65,
        pairing_size : 128,
        field_size   :  20,
        g1           : G1_AR160,
        g2           : G2_AR160},

    PBCInfo {
        context      : PBC_CONTEXT_FR256,
        name         : NAME_FR256,
        text         : INIT_TEXT_FR256,
        g1_size      :  33,
        g2_size      :  65,
        pairing_size : 384,
        field_size   :  32,
        g1           : G1_FR256,
        g2           : G2_FR256},
];        

// collect a vector of 8-bit values from a hex string.
fn str_to_u8vec(s: &str, x: &mut [u8]) {
    let nx = x.len();
    let mut pos = 0;
    let mut val: u8 = 0;
    let mut cct = 0;
    for c in s.chars() {
        if pos < nx {
            match c.to_digit(16) {
                Some(d) => {
                    val += d as u8;
                    cct += 1;
                    if (cct & 1) == 0 {
                        x[pos] = val;
                        pos += 1;
                        val = 0;
                    }
                    else {
                        val <<= 4;
                    }
                },
                None => panic!("Invalid hex digit")
            }
        }
        else {
            break;
        }
    }
    for ix in pos..nx {
        x[ix] = val;
        val = 0;
    }
}

fn init_pairings() {
    let mut psize : [u64;4] = [0;4];
    let mut context = 0;
    let mut v : [u8; 65] = [0;65]; // sufficient for longest generator
    let mut ans : i64 = 0;
    for info in CURVES {
        context = info.context as u64;
        unsafe {
            println!("Init curve {}", (*info.name).to_string());
            println!("Context: {}", context);
            println!("{}", (*info.text).to_string());

            ans = rust_libpbc::init_pairing(
                context,
                info.text as *mut _,
                (*info.text).len() as u64,
                psize.as_ptr() as *mut _);
            assert_eq!(ans, 0);
            
            assert_eq!(psize[0], info.g1_size as u64);
            assert_eq!(psize[1], info.g2_size as u64);
            assert_eq!(psize[2], info.pairing_size as u64);
            assert_eq!(psize[3], info.field_size as u64);

            assert!(psize[0] <= v.len() as u64);
            assert!(psize[1] <= v.len() as u64);

            str_to_u8vec(&(*info.g1), &mut v);
                println!("G1: {}", bv_to_str(&v[0..info.g1_size as usize]));
            ans = rust_libpbc::set_g1(
                context,
                v.as_ptr() as *mut _);
            // returns nbr bytes read, should equal length of G1
            assert_eq!(ans, psize[0] as i64);

            str_to_u8vec(&(*info.g2), &mut v);
                println!("G2: {}", bv_to_str(&v[0..info.g2_size as usize]));
            ans = rust_libpbc::set_g2(
                context,
                v.as_ptr() as *mut _);
            // returns nbr bytes read, should equal length of G2
            assert_eq!(ans, psize[1] as i64);
        }
        println!("");
    }
}

fn main() {
    init_pairings();
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

// -----------------------------------------------------
/*
struct PBC(u8);

impl PBC {
    fn 
}
*/