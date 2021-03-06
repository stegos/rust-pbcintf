extern crate cc;
extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let mut conf = cc::Build::new();

    if cfg!(debug_assertions) {
        conf.define("DEBUG", None);
    }

    conf.cpp(true)
        .file("src/pbc_intf.cpp")
        .compile("pbc_intf");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("src/pbc_intf.hpp")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rustc-link-search=/usr/local/lib");
    println!("cargo:rustc-link-search=/usr/lib/x86_64-linux-gnu");
    println!("cargo:rustc-link-lib=static=pbc");
    println!("cargo:rustc-link-lib=static=gmp");
}