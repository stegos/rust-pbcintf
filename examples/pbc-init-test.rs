extern crate rust_libpbc;
extern crate gmp;
extern crate sha3;

#[macro_use]
extern crate generic_array;
extern crate typenum;
use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::consts::U8;

use std::fmt;
use std::mem;
use sha3::{Digest, Sha3_256};

// -------------------------------------------------------------------

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
const ORDER_AR160 : &str = "730750818665451621361119245571504901405976559617";
const G1_FR256 : &str = "ff8f256bbd48990e94d834fba52da377b4cab2d3e2a08b6828ba6631ad4d668500";
const G2_FR256 : &str = "e20543135c81c67051dc263a2bc882b838da80b05f3e1d7efa420a51f5688995e0040a12a1737c80def47c1a16a2ecc811c226c17fb61f446f3da56c420f38cc01";
const ZR_SIZE_FR256 : usize = 32;
const G1_SIZE_FR256 : usize = 33;
const G2_SIZE_FR256 : usize = 65;
const GP_SIZE_FR256 : usize = 384;

// -------------------------------------------------------------------

const PBC_CONTEXT_FR256 : u8 = 1;
const NAME_FR256 : &str = "FR256";
const INIT_TEXT_FR256 : &str = "type f
q 115792089237314936872688561244471742058375878355761205198700409522629664518163
r 115792089237314936872688561244471742058035595988840268584488757999429535617037
b 3
beta 76600213043964638334639432839350561620586998450651561245322304548751832163977
alpha0 82889197335545133675228720470117632986673257748779594473736828145653330099944
alpha1 66367173116409392252217737940259038242793962715127129791931788032832987594232";
const ORDER_FR256 : &str = "115792089237314936872688561244471742058035595988840268584488757999429535617037";
const G1_AR160 : &str = "797EF95B4B2DED79B0F5E3320D4C38AE2617EB9CD8C0C390B9CCC6ED8CFF4CEA4025609A9093D4C3F58F37CE43C163EADED39E8200C939912B7F4B047CC9B69300";
const G2_AR160 : &str = "A4913CAB767684B308E6F71D3994D65C2F1EB1BE4C9E96E276CD92E4D2B16A2877AA48A8A34CE5F1892CD548DE9106F3C5B0EBE7E13ACCB8C41CC0AE8D110A7F01";
const ZR_SIZE_AR160 : usize = 20;
const G1_SIZE_AR160 : usize = 65;
const G2_SIZE_AR160 : usize = 65;
const GP_SIZE_AR160 : usize = 128;

// -------------------------------------------------------------------

struct PBCInfo {
    context      : u8,
    name         : *const str,
    text         : *const str,
    g1_size      : usize,
    g2_size      : usize,
    pairing_size : usize,
    field_size   : usize,
    order        : *const str,
    g1           : *const str,
    g2           : *const str
}

const CURVES : &[PBCInfo] = &[
    PBCInfo {
        context      : PBC_CONTEXT_AR160,
        name         : NAME_AR160,
        text         : INIT_TEXT_AR160,
        g1_size      : G1_SIZE_AR160,
        g2_size      : G2_SIZE_AR160,
        pairing_size : GP_SIZE_AR160,
        field_size   : ZR_SIZE_AR160,
        order        : ORDER_AR160,
        g1           : G1_AR160,
        g2           : G2_AR160},

    PBCInfo {
        context      : PBC_CONTEXT_FR256,
        name         : NAME_FR256,
        text         : INIT_TEXT_FR256,
        g1_size      : G1_SIZE_FR256,
        g2_size      : G2_SIZE_FR256,
        pairing_size : GP_SIZE_FR256,
        field_size   : ZR_SIZE_FR256,
        order        : ORDER_FR256,
        g1           : G1_FR256,
        g2           : G2_FR256},
];        

// -------------------------------------------------------------------
// collect a vector of 8-bit values from a hex string.
fn str_to_u8v(s: &str, x: &mut [u8]) {
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

fn u8v_to_str(x : &[u8]) -> String {
    // produce a hexnum string from a byte vector
    let mut s = String::new();
    for ix in 0 .. x.len() {
        s.push_str(&format!("{:02x}", x[ix]));
    }
    s
}

fn u8v_to_typed_str(pref : &str, vec : &[u8]) -> String {
    // produce a type-prefixed hexnum from a byte vector
    let mut s = String::from(pref);
    s.push_str("(");
    s.push_str(&u8v_to_str(&vec));
    s.push_str(")");
    s
}

// -------------------------------------------------------------------

fn init_pairings() {
    for info in CURVES {
        let context = info.context as u64;
        unsafe {
            println!("Init curve {}", (*info.name).to_string());
            println!("Context: {}", context);
            println!("{}", (*info.text).to_string());

            let mut psize = [0u64;4];
            let ans = rust_libpbc::init_pairing(
                context,
                info.text as *mut _,
                (*info.text).len() as u64,
                psize.as_ptr() as *mut _);
            assert_eq!(ans, 0);
            
            assert_eq!(psize[0], info.g1_size as u64);
            assert_eq!(psize[1], info.g2_size as u64);
            assert_eq!(psize[2], info.pairing_size as u64);
            assert_eq!(psize[3], info.field_size as u64);

            let mut v1 = vec![0u8; info.g1_size];
            str_to_u8v(&(*info.g1), &mut v1);
            println!("G1: {}", u8v_to_str(&v1));
            let len = rust_libpbc::set_g1(
                context,
                v1.as_ptr() as *mut _);
            // returns nbr bytes read, should equal length of G1
            assert_eq!(len, info.g1_size as i64);

            let mut v1 = vec![0u8; info.g1_size];
            let len = rust_libpbc::get_g1(
                context,
                v1.as_ptr() as *mut _,
                info.g1_size as u64);
            assert_eq!(len, info.g1_size as u64);
            println!("G1 readback: {}", u8v_to_str(&v1));
            
            let mut v2 = vec![0u8; info.g2_size];
            str_to_u8v(&(*info.g2), &mut v2);
            println!("G2: {}", u8v_to_str(&v2));
            let len = rust_libpbc::set_g2(
                context,
                v2.as_ptr() as *mut _);
            // returns nbr bytes read, should equal length of G2
            assert_eq!(len, info.g2_size as i64);

            let mut v2 = vec![0u8; info.g2_size];
            let len = rust_libpbc::get_g2(
                context,
                v2.as_ptr() as *mut _,
                info.g2_size as u64);
            assert_eq!(len, info.g2_size as u64);
            println!("G2 readback: {}", u8v_to_str(&v2));
            
        }
        println!("");
    }
}
// ------------------------------------------------------------------------

fn main() {
    init_pairings();
    println!("Hello, world!");
    let input = "hello!".as_bytes();
    let output = vec![0u8; input.len()];
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
#[derive(Copy, Clone)]
struct Zr([u8;ZR_SIZE_FR256]);

impl Zr {
    fn base_vector(&self) -> &[u8] {
        &self.0
    }

    fn from_str(s : &str) -> Zr {
        let mut v = [0u8;ZR_SIZE_FR256];
        str_to_u8v(&s, &mut v);
        Zr(v)
    }

    fn to_str(&self) -> String {
        u8v_to_typed_str("Zr", &self.base_vector())
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
struct G1([u8;G1_SIZE_FR256]);

impl G1 {
    fn base_vector(&self) -> &[u8] {
        &self.0
    }

    fn to_str(&self) -> String {
        u8v_to_typed_str("G1", &self.base_vector())
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
struct G2([u8;G2_SIZE_FR256]);

impl G2 {
    fn base_vector(&self) -> &[u8] {
        &self.0
    }


    fn to_str(&self) -> String {
        u8v_to_typed_str("G2", &self.base_vector())
    }
}

// -----------------------------------------
const HASH_SIZE : usize = 32;

#[derive(Copy, Clone)]
struct Hash([u8; HASH_SIZE]);

impl Hash {
    fn base_vector(&self) -> &[u8] {
        &self.0
    }

    fn from_vector(msg : &[u8]) -> Hash {
        hash(msg)
    }

    fn to_str(&self) -> String {
        u8v_to_typed_str("H", &self.base_vector())
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
struct SecretKey (Zr);

impl SecretKey {
    fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    fn to_str(&self) -> String {
        u8v_to_typed_str("SKey", &self.base_vector())
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
struct PublicKey (G2);

impl PublicKey {
    fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    fn to_str(&self) -> String {
        u8v_to_typed_str("PKey", &self.base_vector())
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
struct BlsSignature {
    sig  : G1,
    pkey : PublicKey
}

// ------------------------------------------------------------------------

fn hash(msg : &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.input(msg);
    let out = hasher.result();
    let mut h = [0u8; HASH_SIZE];
    h.copy_from_slice(&out[.. HASH_SIZE]);
    Hash(h)
}

fn sign_hash(h : &Hash, skey : &SecretKey) -> G1 {
    // return a raw signature on a hash
    unsafe {
        let v = [0u8; G1_SIZE_FR256];
        rust_libpbc::sign_hash(
            PBC_CONTEXT_FR256 as u64,
            v.as_ptr() as *mut _,
            skey.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            HASH_SIZE as u64);
        G1(v)
    }
}

fn check_hash(h : &Hash, sig : &G1, pkey : &PublicKey) -> bool {
    // check a hash with a raw signature, return t/f
    unsafe {
        0 == rust_libpbc::check_signature(
                PBC_CONTEXT_FR256 as u64,
                sig.base_vector().as_ptr() as *mut _,
                h.base_vector().as_ptr() as *mut _,
                HASH_SIZE as u64,
                pkey.base_vector().as_ptr() as *mut _)
    }
}

fn sign_message(msg : &[u8], skey : &SecretKey, pkey : &PublicKey) -> BlsSignature {
    // hash the message and form a BLS signature
    BlsSignature {
        sig  : sign_hash(&Hash::from_vector(&msg), skey),
        pkey : pkey.clone()
    }
}

fn check_message(msg : &[u8], sig : &BlsSignature) -> bool {
    // check the message against the BLS signature, return t/f
    check_hash(&Hash::from_vector(&msg), &sig.sig, &sig.pkey)
}