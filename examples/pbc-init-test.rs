// Test PBC Interface with Lynn's PBC Library and our LispPBCIntf glue layer.
// DM/Emotiq 10/18
/* -------------------------------------------------------------------------
The MIT License

Copyright (c) 2018 Emotiq AG

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
---------------------------------------------------------------------------- */

extern crate rust_libpbc;
extern crate gmp;
extern crate sha3;
extern crate rand;

use rand::prelude::*;

#[macro_use]
extern crate generic_array;
extern crate typenum;
use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::consts::U8;

use std::fmt;
use std::mem;
use sha3::{Digest, Sha3_256};

use std::sync::{Mutex, Arc};
use std::rc::Rc;
use std::thread;
use std::marker;
use std::ops::{Add, Sub, Mul, Div, Neg, AddAssign, SubAssign, MulAssign, DivAssign};

// -------------------------------------------------------------------
// Fast AR160 curves, but low security 2^80

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
const GT_SIZE_FR256 : usize = 384;

// -------------------------------------------------------------------
// Secure BN curves, security approx 2^128

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
const GT_SIZE_AR160 : usize = 128;

// -------------------------------------------------------------------

struct PBCInfo {
    context      : u8, // which slot in the gluelib context table
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
        pairing_size : GT_SIZE_AR160,
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
        pairing_size : GT_SIZE_FR256,
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

fn main() {

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
    // check connection to PBC library
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
    println!("");

    // init PBC library -- must only be performed once
    let init = Mutex::new(false);
    {
        let mut done = init.lock().unwrap();
        if ! *done {
            *done = true;
            init_pairings();
        }
    }

    // test hashing
    let h = Hash::from_vector(b"");
    println!("hash(\"\") = {}", h.to_str());
    assert_eq!(h.to_str(), "H(a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a)");
    println!("");

    // -------------------------------------
    // on Secure pairings
    // test PRNG
    println!("rand Zr = {}", secure::get_random_Zr());

    // test keying...
    let (skey, pkey, sig) = secure::make_deterministic_keys("Testing");
    println!("skey = {}", skey);
    println!("pkey = {}", pkey);
    println!("sig  = {}", sig);
    assert!(secure::check_keying(&pkey, &sig));
    println!("");

    // -------------------------------------
    // on Fast pairings
    // test PRNG
    println!("rand Zr = {}", fast::get_random_Zr());

    // test keying...
    let (skey, pkey, sig) = fast::make_deterministic_keys("Testing");
    println!("skey = {}", skey);
    println!("pkey = {}", pkey);
    println!("sig  = {}", sig);
    assert!(fast::check_keying(&pkey, &sig));

    // -------------------------------------
    // check some arithmetic on the Fast curves
    let a = 0x123456789i64;
    println!("chk Zr: 0x{:x} -> {}", a, fast::Zr::from_int(a));
    println!("chk Zr: -1 -> {}", fast::Zr::from_int(-1));
    println!("chk Zr: -1 + 1 -> {}", fast::Zr::from(-1) + 1);
}

// -----------------------------------------------------
// Hashing with SHA3

const HASH_SIZE : usize = 32;

#[derive(Copy, Clone)]
pub struct Hash([u8; HASH_SIZE]);

impl Hash {
    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn from_vector(msg : &[u8]) -> Hash {
        hash(msg)
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("H", &self.base_vector())
    }
}

pub fn hash(msg : &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.input(msg);
    let out = hasher.result();
    let mut h = [0u8; HASH_SIZE];
    h.copy_from_slice(&out[.. HASH_SIZE]);
    Hash(h)
}

// ------------------------------------------------------------------
// Secure Pairings using BN Curve FR256 (type F, r approx 256 bits)

mod secure {
    use super::*;

    #[derive(Copy, Clone)]
    pub struct Zr([u8;ZR_SIZE_FR256]);

    impl Zr {
        pub fn base_vector(&self) -> &[u8] {
            &self.0
        }

        pub fn from_str(s : &str) -> Zr {
            // result might be larger than prime order, r,
            // but will be interpreted by PBC lib as (Zr mod r).
            let mut v = [0u8;ZR_SIZE_FR256];
            str_to_u8v(&s, &mut v);
            Zr(v)
        }

        pub fn to_str(&self) -> String {
            u8v_to_typed_str("Zr", &self.base_vector())
        }
    }

    impl fmt::Display for Zr {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.to_str())
        }
    }
    
    // -----------------------------------------
    #[derive(Copy, Clone)]
    pub struct G1([u8;G1_SIZE_FR256]);

    impl G1 {
        pub fn base_vector(&self) -> &[u8] {
            &self.0
        }

        pub fn to_str(&self) -> String {
            u8v_to_typed_str("G1", &self.base_vector())
        }
    }

    impl fmt::Display for G1 {
        // for display of signatures
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.to_str())
        }
    }
    
// -----------------------------------------
    #[derive(Copy, Clone)]
    pub struct G2([u8;G2_SIZE_FR256]);

    impl G2 {
        pub fn base_vector(&self) -> &[u8] {
            &self.0
        }


        pub fn to_str(&self) -> String {
            u8v_to_typed_str("G2", &self.base_vector())
        }
    }

    impl fmt::Display for G2 {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.to_str())
        }
    }
    
    // -----------------------------------------
    #[derive(Copy, Clone)]
    pub struct SecretKey (Zr);

    impl SecretKey {
        pub fn base_vector(&self) -> &[u8] {
            self.0.base_vector()
        }

        pub fn to_str(&self) -> String {
            u8v_to_typed_str("SKey", &self.base_vector())
        }
    }

    impl fmt::Display for SecretKey {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.to_str())
        }
    }
    
    // -----------------------------------------
    #[derive(Copy, Clone)]
    pub struct PublicKey (G2);

    impl PublicKey {
        pub fn base_vector(&self) -> &[u8] {
            self.0.base_vector()
        }

        pub fn to_str(&self) -> String {
            u8v_to_typed_str("PKey", &self.base_vector())
        }
    }

    impl fmt::Display for PublicKey {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.to_str())
        }
    }
    
    // -----------------------------------------
    #[derive(Copy, Clone)]
    pub struct BlsSignature {
        sig  : G1,
        pkey : PublicKey
    }

    // ------------------------------------------------------------------------
    // BLS Signature Generation & Checking

    pub fn sign_hash(h : &Hash, skey : &SecretKey) -> G1 {
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

    pub fn check_hash(h : &Hash, sig : &G1, pkey : &PublicKey) -> bool {
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

    pub fn sign_message(msg : &[u8], skey : &SecretKey, pkey : &PublicKey) -> BlsSignature {
        // hash the message and form a BLS signature
        BlsSignature {
            sig  : sign_hash(&Hash::from_vector(&msg), skey),
            pkey : pkey.clone()
        }
    }

    pub fn check_message(msg : &[u8], sig : &BlsSignature) -> bool {
        // check the message against the BLS signature, return t/f
        check_hash(&Hash::from_vector(&msg), &sig.sig, &sig.pkey)
    }

    // ------------------------------------------------------------------
    // Key Generation & Checking

    pub fn get_random_Zr() -> Zr {
        Zr(random::<[u8;ZR_SIZE_FR256]>())
    }

    pub fn make_deterministic_keys(seed : &str) -> (SecretKey, PublicKey, G1) {
        let nel = seed.len();
        let mut v = vec![0u8; nel];
        let mut ix = 0;
        for c in seed.chars() {
            v[ix] = c as u8;
            ix += 1;
        }
        make_deterministic_keys_from_u8v(&v)
    }

    pub fn make_deterministic_keys_from_u8v(v : &[u8]) -> (SecretKey, PublicKey, G1) {
        let h = hash(&v);
        let sk = [0u8;ZR_SIZE_FR256]; // secret keys in Zr
        let pk = [0u8;G2_SIZE_FR256]; // public keys in G2
        unsafe {
            rust_libpbc::make_key_pair(
                PBC_CONTEXT_FR256 as u64,
                sk.as_ptr() as *mut _,
                pk.as_ptr() as *mut _,
                h.base_vector().as_ptr() as *mut _,
                HASH_SIZE as u64);
        }
        let hpk = hash(&pk);
        let skey = SecretKey(Zr(sk));
        let pkey = PublicKey(G2(pk));
        let sig  = sign_hash(&hpk, &skey);
        (skey, pkey, sig)
    }

    pub fn check_keying(pkey : &PublicKey, sig : &G1) -> bool {
        check_hash(&hash(&pkey.base_vector()), &sig, &pkey)
    }

    pub fn make_random_keys() -> (SecretKey, PublicKey, G1) {
        make_deterministic_keys_from_u8v(&get_random_Zr().base_vector())
    }
}

// --------------------------------------------------------------------------
// Faster, but less secure, pairings with curves AR160 (type A, r approx 160 bits)
// (intended for eRandHound ephemeral secrets)

mod fast {
    use super::*;

    #[derive(Copy, Clone)]
    pub struct Zr([u8;ZR_SIZE_AR160]);

    impl Zr {
        pub fn base_vector(&self) -> &[u8] {
            &self.0
        }

        pub fn from_str(s : &str) -> Zr {
            let mut v = [0u8;ZR_SIZE_AR160];
            str_to_u8v(&s, &mut v);
            Zr(v)
        }

        pub fn from_int(a : i64) -> Zr {
            let mut v = [0u8;ZR_SIZE_AR160]; // big-endian encoding as byte vector
            let mut va = if a < 0 {
                                    -(a as i128)
                                } 
                                else {
                                    a as i128
                                };
            for ix in 0 .. 8 {
                v[ZR_SIZE_AR160-ix-1] = (va & 0x0ff) as u8;
                va >>= 8;
            }
            if a < 0 {
                -Zr(v)
            } else {
                Zr(v)
            }
        }

        pub fn to_str(&self) -> String {
            u8v_to_typed_str("Zr", &self.base_vector())
        }
    }

    impl From<i64> for Zr {
        fn from(x : i64) -> Zr {
            Zr::from_int(x)
        }
    }

    impl fmt::Display for Zr {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.to_str())
        }
    }
    
    // -------------------------------------
    // Zr op i64

    impl Add<i64> for Zr {
        type Output = Zr;
        fn add(self, other: i64) -> Zr {
            self + Zr::from(other)
        }
    }

    impl Sub<i64> for Zr {
        type Output = Zr;
        fn sub(self, other: i64) -> Zr {
            self - Zr::from(other)
        }
    }

    impl Mul<i64> for Zr {
        type Output = Zr;
        fn mul(self, other: i64) -> Zr {
            self * Zr::from(other)
        }
    }

    impl Div<i64> for Zr {
        type Output = Zr;
        fn div(self, other: i64) -> Zr {
            self / Zr::from(other)
        }
    }

    // -------------------------------------
    // i64 op Zr
    impl Add<Zr> for i64 {
        type Output = Zr;
        fn add(self, other: Zr) -> Zr {
            Zr::from(self) + other
        }
    }

    impl Sub<Zr> for i64 {
        type Output = Zr;
        fn sub(self, other: Zr) -> Zr {
            Zr::from(self) - other
        }
    }

    impl Mul<Zr> for i64 {
        type Output = Zr;
        fn mul(self, other: Zr) -> Zr {
            Zr::from(self) * other
        }
    }

    impl Div<Zr> for i64 {
        type Output = Zr;
        fn div(self, other: Zr) -> Zr {
            Zr::from(self) / other
        }
    }

    // -------------------------------------
    // Zr op Zr

    impl Neg for Zr {
        type Output = Zr;
        fn neg(self) -> Zr {
            neg_Zr(&self)
        }
    }

    impl Add<Zr> for Zr {
        type Output = Zr;
        fn add(self, other: Zr) -> Zr {
            add_Zr_Zr(&self, &other)
        }
    }

    impl Sub<Zr> for Zr {
        type Output = Zr;
        fn sub(self, other: Zr) -> Zr {
            sub_Zr_Zr(&self, &other)
        }
    }

    impl Mul<Zr> for Zr {
        type Output = Zr;
        fn mul(self, other: Zr) -> Zr {
            mul_Zr_Zr(&self, &other)
        }
    }
    
    impl Div<Zr> for Zr {
        type Output = Zr;
        fn div(self, other: Zr) -> Zr {
            div_Zr_Zr(&self, &other)
        }
    }
    
    impl AddAssign<i64> for Zr {
        fn add_assign(&mut self, other: i64) {
            *self += Zr::from(other);
        }
    }
 
     impl SubAssign<i64> for Zr {
        fn sub_assign(&mut self, other: i64) {
            *self -= Zr::from(other);
        }
    }

    impl MulAssign<i64> for Zr {
        fn mul_assign(&mut self, other: i64) {
            *self *= Zr::from(other);
        }
    }
 
     impl DivAssign<i64> for Zr {
        fn div_assign(&mut self, other: i64) {
            *self /= Zr::from(other);
        }  
    }

    impl AddAssign<Zr> for Zr {
        fn add_assign(&mut self, other: Zr) {
            *self = *self + other;
        }
    }
 
     impl SubAssign<Zr> for Zr {
        fn sub_assign(&mut self, other: Zr) {
            *self = *self - other;
        }
    }

    impl MulAssign<Zr> for Zr {
        fn mul_assign(&mut self, other: Zr) {
            *self = *self * other;
        }   
    }
 
     impl DivAssign<Zr> for Zr {
        fn div_assign(&mut self, other: Zr) {
            *self = *self / other;
        }
    }

   // -----------------------------------------
    #[derive(Copy, Clone)]
    pub struct G1([u8;G1_SIZE_AR160]);

    impl G1 {
        pub fn base_vector(&self) -> &[u8] {
            &self.0
        }

        pub fn to_str(&self) -> String {
            u8v_to_typed_str("G1", &self.base_vector())
        }
    }

    impl fmt::Display for G1 {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.to_str())
        }
    }
    
    impl Neg for G1 {
        type Output = G1;
        fn neg(self) -> G1 {
            neg_G1(&self)
        }
    }

    impl Add<G1> for G1 {
        type Output = G1;
        fn add(self, other: G1) -> G1 {
            add_G1_G1(&self, &other)
        }
    }
    
    impl Sub<G1> for G1 {
        type Output = G1;
        fn sub(self, other: G1) -> G1 {
            sub_G1_G1(&self, &other)
        }
    }

    impl Mul<Zr> for G1 {
        type Output = G1;
        fn mul(self, other: Zr) -> G1 {
            mul_G1_Zr(&self, &other)
        }
    }
    
    impl Div<Zr> for G1 {
        type Output = G1;
        fn div(self, other: Zr) -> G1 {
            div_G1_Zr(&self, &other)
        }
    }

    impl Mul<G1> for Zr {
        type Output = G1;
        fn mul(self, other: G1) -> G1 {
            mul_G1_Zr(&other, &self)
        }
    }

    impl Mul<G1> for i64 {
        type Output = G1;
        fn mul(self, other: G1) -> G1 {
            Zr::from(self) * other
        }
    }
    
    impl Div<i64> for G1 {
        type Output = G1;
        fn div(self, other: i64) -> G1 {
            self / Zr::from(other)
        }
    }

    impl Mul<i64> for G1 {
        type Output = G1;
        fn mul(self, other: i64) -> G1 {
            self * Zr::from(other)
        }
    }

    impl AddAssign<G1> for G1 {
        fn add_assign(&mut self, other: G1) {
            *self = *self + other;
        }
    }
 
    impl SubAssign<G1> for G1 {
        fn sub_assign(&mut self, other: G1) {
            *self = *self - other;
        }
    }

    impl MulAssign<Zr> for G1 {
        fn mul_assign(&mut self, other: Zr) {
            *self = *self * other;
        }
    }
 
    impl DivAssign<Zr> for G1 {
        fn div_assign(&mut self, other: Zr) {
            *self = *self / other;
        }
    }

    impl MulAssign<i64> for G1 {
        fn mul_assign(&mut self, other: i64) {
            *self *= Zr::from(other);
        }
    }
 
    impl DivAssign<i64> for G1 {
        fn div_assign(&mut self, other: i64) {
            *self /= Zr::from(other);
        }
    }

// -----------------------------------------
    #[derive(Copy, Clone)]
    pub struct G2([u8;G2_SIZE_AR160]);

    impl G2 {
        pub fn base_vector(&self) -> &[u8] {
            &self.0
        }


        pub fn to_str(&self) -> String {
            u8v_to_typed_str("G2", &self.base_vector())
        }
    }

    impl fmt::Display for G2 {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.to_str())
        }
    }
    
    impl Neg for G2 {
        type Output = G2;
        fn neg(self) -> G2 {
            neg_G2(&self)
        }
    }

    impl Add<G2> for G2 {
        type Output = G2;
        fn add(self, other: G2) -> G2 {
            add_G2_G2(&self, &other)
        }
    }
    
    impl Sub<G2> for G2 {
        type Output = G2;
        fn sub(self, other: G2) -> G2 {
            sub_G2_G2(&self, &other)
        }
    }

    impl Mul<Zr> for G2 {
        type Output = G2;
        fn mul(self, other: Zr) -> G2 {
            mul_G2_Zr(&self, &other)
        }
    }
    
    impl Mul<i64> for G2 {
        type Output = G2;
        fn mul(self, other: i64) -> G2 {
            self * Zr::from(other)
        }
    }
    
    impl Div<Zr> for G2 {
        type Output = G2;
        fn div(self, other: Zr) -> G2 {
            div_G2_Zr(&self, &other)
        }
    }

    impl Div<i64> for G2 {
        type Output = G2;
        fn div(self, other: i64) -> G2 {
            self / Zr::from(other)
        }
    }

    impl Mul<G2> for Zr {
        type Output = G2;
        fn mul(self, other: G2) -> G2 {
            mul_G2_Zr(&other, &self)
        }
    }
    
    impl Mul<G2> for i64 {
        type Output = G2;
        fn mul(self, other: G2) -> G2 {
            other * Zr::from(self)
        }
    }
    
    impl AddAssign<G2> for G2 {
        fn add_assign(&mut self, other: G2) {
            *self = *self + other;
        }
    }
 
    impl SubAssign<G2> for G2 {
        fn sub_assign(&mut self, other: G2) {
            *self = *self - other;
        }
    }

    impl MulAssign<Zr> for G2 {
        fn mul_assign(&mut self, other: Zr) {
            *self = *self * other;
        }
    }
 
    impl DivAssign<Zr> for G2 {
        fn div_assign(&mut self, other: Zr) {
            *self = *self / other;
        }
    }

    impl MulAssign<i64> for G2 {
        fn mul_assign(&mut self, other: i64) {
            *self *= Zr::from(other);
        }
    }
 
    impl DivAssign<i64> for G2 {
        fn div_assign(&mut self, other: i64) {
            *self /= Zr::from(other);
        }
    }

// -----------------------------------------
    #[derive(Copy, Clone)]
    pub struct GT([u8;GT_SIZE_AR160]);

    impl GT {
        pub fn base_vector(&self) -> &[u8] {
            &self.0
        }


        pub fn to_str(&self) -> String {
            u8v_to_typed_str("GT", &self.base_vector())
        }
    }

    impl fmt::Display for GT {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.to_str())
        }
    }
    
    impl Mul<GT> for GT {
        type Output = GT;
        fn mul(self, other: GT) -> GT {
            mul_GT_GT(&self, &other)
        }
    }

    impl Div<GT> for GT {
        type Output = GT;
        fn div(self, other: GT) -> GT {
            div_GT_GT(&self, &other)
        }
    }

    impl MulAssign<GT> for GT {
        fn mul_assign(&mut self, other: GT) {
            *self = *self * other;
        }
    }
 
    impl DivAssign<GT> for GT {
        fn div_assign(&mut self, other: GT) {
            *self = *self / other;
        }
    }

// -----------------------------------------
    #[derive(Copy, Clone)]
    pub struct SecretKey (Zr);

    impl SecretKey {
        pub fn base_vector(&self) -> &[u8] {
            self.0.base_vector()
        }

        pub fn to_str(&self) -> String {
            u8v_to_typed_str("SKey", &self.base_vector())
        }
    }

    impl fmt::Display for SecretKey {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.to_str())
        }
    }
    
    // -----------------------------------------
    #[derive(Copy, Clone)]
    pub struct PublicKey (G2);

    impl PublicKey {
        pub fn base_vector(&self) -> &[u8] {
            self.0.base_vector()
        }

        pub fn to_str(&self) -> String {
            u8v_to_typed_str("PKey", &self.base_vector())
        }
    }

    impl fmt::Display for PublicKey {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.to_str())
        }
    }
    
// ------------------------------------------------------------------
    // Key Generation & Checking

    pub fn sign_hash(h : &Hash, skey : &SecretKey) -> G1 {
        // return a raw signature on a hash
        unsafe {
            let v = [0u8; G1_SIZE_AR160];
            rust_libpbc::sign_hash(
                PBC_CONTEXT_AR160 as u64,
                v.as_ptr() as *mut _,
                skey.base_vector().as_ptr() as *mut _,
                h.base_vector().as_ptr() as *mut _,
                HASH_SIZE as u64);
            G1(v)
        }
    }

    pub fn check_hash(h : &Hash, sig : &G1, pkey : &PublicKey) -> bool {
        // check a hash with a raw signature, return t/f
        unsafe {
            0 == rust_libpbc::check_signature(
                    PBC_CONTEXT_AR160 as u64,
                    sig.base_vector().as_ptr() as *mut _,
                    h.base_vector().as_ptr() as *mut _,
                    HASH_SIZE as u64,
                    pkey.base_vector().as_ptr() as *mut _)
        }
    }

    pub fn get_random_Zr() -> Zr {
        Zr(random::<[u8;ZR_SIZE_AR160]>())
    }

    pub fn make_deterministic_keys(seed : &str) -> (SecretKey, PublicKey, G1) {
        let nel = seed.len();
        let mut v = vec![0u8; nel];
        let mut ix = 0;
        for c in seed.chars() {
            v[ix] = c as u8;
            ix += 1;
        }
        make_deterministic_keys_from_u8v(&v)
    }

    pub fn make_deterministic_keys_from_u8v(v : &[u8]) -> (SecretKey, PublicKey, G1) {
        let h = hash(&v);
        let sk = [0u8;ZR_SIZE_AR160]; // secret keys in Zr
        let pk = [0u8;G2_SIZE_AR160]; // public keys in G2
        unsafe {
            rust_libpbc::make_key_pair(
                PBC_CONTEXT_AR160 as u64,
                sk.as_ptr() as *mut _,
                pk.as_ptr() as *mut _,
                h.base_vector().as_ptr() as *mut _,
                HASH_SIZE as u64);
        }
        let hpk = hash(&pk);
        let skey = SecretKey(Zr(sk));
        let pkey = PublicKey(G2(pk));
        let sig  = sign_hash(&hpk, &skey);
        (skey, pkey, sig)
    }

    pub fn check_keying(pkey : &PublicKey, sig : &G1) -> bool {
        check_hash(&hash(&pkey.base_vector()), &sig, &pkey)
    }

    pub fn make_random_keys() -> (SecretKey, PublicKey, G1) {
        make_deterministic_keys_from_u8v(&get_random_Zr().base_vector())
    }

    // ----------------------------------------------------------------
    // Curve Arithmetic...

    pub fn add_Zr_Zr(a : &Zr, b : &Zr) -> Zr {
        let mut ans = [0u8;ZR_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::add_Zr_vals(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _,
                b.base_vector().as_ptr() as *mut _);
            Zr(ans)
        }
    }

    pub fn sub_Zr_Zr(a : &Zr, b : &Zr) -> Zr {
        let mut ans = [0u8;ZR_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::sub_Zr_vals(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _,
                b.base_vector().as_ptr() as *mut _);
            Zr(ans)
        }
    }

    pub fn mul_Zr_Zr(a : &Zr, b : &Zr) -> Zr {
        let mut ans = [0u8;ZR_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::mul_Zr_vals(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _,
                b.base_vector().as_ptr() as *mut _);
            Zr(ans)
        }
    }

    pub fn div_Zr_Zr(a : &Zr, b : &Zr) -> Zr {
        let mut ans = [0u8;ZR_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::div_Zr_vals(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _,
                b.base_vector().as_ptr() as *mut _);
            Zr(ans)
        }
    }

    pub fn exp_Zr_Zr(a : &Zr, b : &Zr) -> Zr {
        let mut ans = [0u8;ZR_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::exp_Zr_vals(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _,
                b.base_vector().as_ptr() as *mut _);
            Zr(ans)
        }
    }

    pub fn neg_Zr(a : &Zr) -> Zr {
        let mut ans = [0u8;ZR_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::neg_Zr_val(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _);
            Zr(ans)
        }
    }

    pub fn inv_Zr(a : &Zr) -> Zr {
        let mut ans = [0u8;ZR_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::inv_Zr_val(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _);
            Zr(ans)
        }
    }

    // ---------------------------------

    pub fn mul_G1_Zr(a : &G1, b : &Zr) -> G1 {
        let mut ans = [0u8;G1_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::exp_G1z(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _,
                b.base_vector().as_ptr() as *mut _);
            G1(ans)
        }
    }

    pub fn div_G1_Zr(a : &G1, b : &Zr) -> G1 {
        let invb = inv_Zr(&b);
        mul_G1_Zr(&a, &invb)
    }

    pub fn add_G1_G1(a : &G1, b : &G1) -> G1 {
        let mut ans = [0u8;G1_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::add_G1_pts(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _,
                b.base_vector().as_ptr() as *mut _);
            G1(ans)
        }
    }

    pub fn sub_G1_G1(a : &G1, b : &G1) -> G1 {
        let mut ans = [0u8;G1_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::sub_G1_pts(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _,
                b.base_vector().as_ptr() as *mut _);
            G1(ans)
        }
    }

    pub fn neg_G1(a : &G1) -> G1 {
        let mut ans = [0u8;G1_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::neg_G1_pt(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _);
            G1(ans)
        }
    }

    // ------------------------------------------------------

    pub fn mul_G2_Zr(a : &G2, b : &Zr) -> G2 {
        let mut ans = [0u8;G2_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::exp_G2z(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _,
                b.base_vector().as_ptr() as *mut _);
            G2(ans)
        }
    }

    pub fn div_G2_Zr(a : &G2, b : &Zr) -> G2 {
        let invb = inv_Zr(&b);
        mul_G2_Zr(&a, &invb)
    }

    pub fn add_G2_G2(a : &G2, b : &G2) -> G2 {
        let mut ans = [0u8;G2_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::add_G2_pts(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _,
                b.base_vector().as_ptr() as *mut _);
            G2(ans)
        }
    }

    pub fn sub_G2_G2(a : &G2, b : &G2) -> G2 {
        let mut ans = [0u8;G2_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::sub_G2_pts(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _,
                b.base_vector().as_ptr() as *mut _);
            G2(ans)
        }
    }

    pub fn neg_G2(a : &G2) -> G2 {
        let mut ans = [0u8;G2_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::neg_G2_pt(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _);
            G2(ans)
        }
    }

    // -------------------------------------------------

    pub fn compute_pairing(a : &G1, b : &G2) -> GT {
        let ans = [0u8;GT_SIZE_AR160];
        unsafe {
            rust_libpbc::compute_pairing(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _,
                a.base_vector().as_ptr() as *mut _,
                b.base_vector().as_ptr() as *mut _);
            GT(ans)
        }
    }

    pub fn mul_GT_GT(a : &GT, b : &GT) -> GT {
        let mut ans = [0u8;GT_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::mul_GT_vals(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _,
                b.base_vector().as_ptr() as *mut _);
            GT(ans)
        }
    }

    pub fn div_GT_GT(a : &GT, b : &GT) -> GT {
        let mut ans = [0u8;GT_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::div_GT_vals(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _,
                b.base_vector().as_ptr() as *mut _);
            GT(ans)
        }
    }

    pub fn exp_GT_Zr(a : &GT, b : &Zr) -> GT {
        let mut ans = [0u8;GT_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::exp_GTz(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _,
                b.base_vector().as_ptr() as *mut _);
            GT(ans)
        }
    }

    pub fn inv_GT(a : &GT) -> GT {
        let mut ans = [0u8;GT_SIZE_AR160];
        ans.copy_from_slice(a.base_vector());
        unsafe {
            rust_libpbc::inv_GT_val(
                PBC_CONTEXT_AR160 as u64,
                ans.as_ptr() as *mut _);
            GT(ans)
        }
    }

}

