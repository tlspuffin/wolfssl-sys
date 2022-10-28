/*!
 * Contains the build process for WolfSSL
 */

extern crate bindgen;

use std::{
    collections::HashSet,
    env,
    fs::{canonicalize, File},
    io,
    io::{ErrorKind, Write},
    path::PathBuf,
    process::Command,
};

use autotools::Config;

/**
 * Work around for bindgen creating duplicate values.
 */
#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl bindgen::callbacks::ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        if self.0.contains(name) {
            bindgen::callbacks::MacroParsingBehavior::Ignore
        } else {
            bindgen::callbacks::MacroParsingBehavior::Default
        }
    }
}

const REF: &str = if cfg!(feature = "vendored-wolfssl530") {
    "v5.3.0-stable"
} else if cfg!(feature = "vendored-wolfssl520") {
    "v5.2.0-stable"
} else if cfg!(feature = "vendored-wolfssl510") {
    "v5.1.0-stable"
} else if cfg!(feature = "vendored-wolfssl430") {
    "v4.3.0-stable"
} else {
    "master"
};

/**
 * Extract WolfSSL
 */
fn clone_wolfssl(dest: &str) -> std::io::Result<()> {
    std::fs::remove_dir_all(dest)?;
    Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--branch")
        .arg(REF)
        .arg("https://github.com/wolfSSL/wolfssl.git")
        .arg(dest)
        .status()?;

    Ok(())
}

pub fn insert_claim_interface(additional_headers: &PathBuf) -> std::io::Result<()> {
    let interface = security_claims::CLAIM_INTERFACE_H;

    let path = additional_headers.join("claim-interface.h");

    let mut file = File::create(path)?;
    file.write_all(interface.as_bytes())?;

    Ok(())
}

/**
Builds WolfSSL
*/
fn build_wolfssl(dest: &str) -> PathBuf {
    let cc = "clang".to_owned();

    let mut config = Config::new(dest);
    //let mut config = Config::new(format!("{}/wolfssl-5.3.0-stable", dest));
    config
        .reconf("-ivf")
        // Only build the static library
        .enable_static()
        .disable_shared()
        .enable("debug", None)
        // Enable OpenSSL Compatibility layer
        .enable("opensslall", None)
        .enable("opensslextra", None)
        .enable("context-extra-user-data", None)
        // Fortunately, there is one comfy option which I’ve used when compiling wolfSSL: --enable-all.
        // It enables all options, including the OpenSSL compatibility layer and leaves out the SSL 3 protocol.
        //.enable("all", None) // FIXME: Do not use this as its non-default
        //.enable("opensslcoexist", None) // FIXME: not needed
        .enable("keygen", None) // Support for RSA certs
        .enable("certgen", None) // Support x509 decoding
        // Enable TLS/1.3
        .enable("tls13", None)
        // Disable old TLS versions
        //.disable("oldtls", None) // FIXME: We want TLS 1.2
        // Enable AES hardware acceleration
        .enable("aesni", None)
        // Enable single threaded mode
        //.enable("singlethreaded", None) // FIXME: incompatible with "all"
        // Enable D/TLS
        .enable("dtls", None)
        // Enable single precision
        .enable("sp", None) // FIXME: Fixes a memory leak?
        // Enable single precision ASM
        .enable("sp-asm", None)
        // Enable setting the D/TLS MTU size
        .enable("dtls-mtu", None)
        // Disable SHA3
        .disable("sha3", None)
        // Enable Intel ASM optmisations
        .enable("intelasm", None)
        // Disable DH key exchanges
        //.disable("dh", None) // FIXME: Why should we disable it?
        // Enable elliptic curve exchanges
        .enable("curve25519", None)
        // Enable Secure Renegotiation
        .enable("secure-renegotiation", None)
        .enable("postauth", None) // FIXME; else the session resumption crashes? SEGV?
        //.enable("aesccm", None) // FIXME MAYBE ^
        //.enable("camellia", None) // FIXME MAYBE ^
        // Debugging
        /*.enable("atomicuser", None)
        .enable("aesgcm", None)
        .enable("aesgcm-stream", None)
        .enable("aesccm", None)
        .enable("aesctr", None)
        .enable("aesofb", None)
        .enable("aescfb", None)
        .enable("aescbc-length-checks", None)
        .enable("camellia", None)
        .enable("ripemd", None)
        .enable("sha224", None)
        .enable("sessioncerts", None)
        .enable("keygen", None)
        .enable("certgen", None)
        .enable("certreq", None)
        .enable("certext", None)
        .enable("sep", None)
        .enable("hkdf", None)
        .enable("curve25519", None)
        .enable("curve448", None)
        .enable("fpecc", None)
        .enable("eccencrypt", None)
        .enable("psk", None)
        .enable("cmac", None)
        .enable("xts", None)
        .enable("ocsp", None)
        .enable("ocspstapling", None)
        .enable("ocspstapling2", None)
        .enable("crl", None)
        .enable("supportedcurves", None)
        .enable("tlsx", None)
        .enable("pwdbased", None)
        .enable("aeskeywrap", None)
        .enable("x963kdf", None)
        .enable("scrypt", None)
        .enable("indef", None)
        .enable("enckeys", None)
        .enable("hashflags", None)
        .enable("defaultdhparams", None)
        .enable("base64encode", None)
        .enable("base16", None)
        .enable("arc4", None)
        .enable("des3", None)
        .enable("nullcipher", None)
        .enable("blake2", None)
        .enable("blake2s", None)
        .enable("md2", None)
        .enable("md4", None)
        .enable("cryptocb", None)
        .enable("anon", None)
        .enable("ssh", No*/
        // end crypto
        /*.enable("savesession", None)
        .enable("savecert", None)
        .enable("postauth", None)
        .enable("hrrcookie", None)
        .enable("fallback-scsv", None)
        .enable("mcast", None)
        .enable("webserver", None)
        .enable("crl-monitor", None)
        .enable("sni", None)
        .enable("maxfragment", None)
        .enable("alpn", None)
        .enable("truncatedhmac", None)
        .enable("trusted-ca", None)
        .enable("session-ticket", None)
        .enable("earlydata", None)*/
        .enable("psk", None) // FIXME: Only 4.3.0
        // CFLAGS
        //.cflag("-DWOLFSSL_DTLS_ALLOW_FUTURE")
        //.cflag("-DWOLFSSL_MIN_RSA_BITS=2048")
        //.cflag("-DWOLFSSL_MIN_ECC_BITS=256")
        .cflag("-DHAVE_EX_DATA") // FIXME: Only 4.3.0
        .cflag("-DWOLFSSL_CALLBACKS") // FIXME: Elso some msg callbacks are not called
        //FIXME broken: .cflag("-DHAVE_EX_DATA_CLEANUP_HOOKS") // Required for cleanup of ex data
        // Strip debug
        //.cflag("-g")// FIXME: Reenable?
        .cflag("-fPIC");

    if cfg!(feature = "sancov") {
        config.cflag("-fsanitize-coverage=trace-pc-guard");
    }

    if cfg!(feature = "asan") {
        config
            .cflag("-fsanitize=address")
            .cflag("-shared-libsan")
            .cflag("-Wl,-rpath=/usr/lib/clang/10/lib/linux/"); // We need to tell the library where ASAN is, else the tests fail within wolfSSL
        println!("cargo:rustc-link-lib=asan");
    }

    if cfg!(feature = "additional-headers") {
        let additional_headers = PathBuf::from(dest).join("additional_headers");

        std::fs::create_dir_all(&additional_headers).unwrap();
        insert_claim_interface(&additional_headers).unwrap();
        // Make additional headers available
        config.cflag(
            format!(
                " -I{}",
                canonicalize(&additional_headers).unwrap().to_str().unwrap()
            )
            .as_str(),
        );
    }

    let b = config
        .env("CC", cc)
        // Build it
        .build();
    println!("PathBuf:'{}'", b.display());
    b
}

fn patch_wolfssl(source_dir: &PathBuf, out_dir: &str, patch: &str) -> std::io::Result<()> {
    let status = Command::new("git")
        .current_dir(out_dir)
        .arg("am")
        .arg(source_dir.join("patches").join(patch).to_str().unwrap())
        .status()?;

    if !status.success() {
        return Err(io::Error::from(ErrorKind::Other));
    }

    Ok(())
}

fn main() -> std::io::Result<()> {
    let source_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = env::var("OUT_DIR").unwrap();
    clone_wolfssl(&out_dir)?;

    patch_wolfssl(&source_dir, &out_dir, "fix-CVE-2022-25640.patch").unwrap();
    patch_wolfssl(&source_dir, &out_dir, "fix-CVE-2022-39173.patch").unwrap();

    // Configure and build WolfSSL
    let dst = build_wolfssl(&out_dir);

    // We want to block some macros as they are incorrectly creating duplicate values
    // https://github.com/rust-lang/rust-bindgen/issues/687
    let mut hash_ignored_macros = HashSet::new();
    for i in &[
        "IPPORT_RESERVED",
        "EVP_PKEY_DH",
        "BIO_CLOSE",
        "BIO_NOCLOSE",
        "CRYPTO_LOCK",
        "ASN1_STRFLGS_ESC_MSB",
        "SSL_MODE_RELEASE_BUFFERS",
        // Woflss 4.3.0
        "GEN_IPADD",
        "EVP_PKEY_RSA",
    ] {
        hash_ignored_macros.insert(i.to_string());
    }
    let ignored_macros = IgnoreMacros(hash_ignored_macros);

    // Build the Rust binding
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .header(format!("{}/wolfssl/internal.h", out_dir))
        .clang_arg(format!("-I{}/include/", out_dir))
        .parse_callbacks(Box::new(ignored_macros))
        .rustfmt_bindings(true)
        .generate()
        .expect("Unable to generate bindings");

    // Write out the bindings
    bindings
        .write_to_file(dst.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // Tell cargo to tell rustc to link in WolfSSL
    println!("cargo:rustc-link-lib=static=wolfssl");
    println!(
        "cargo:rustc-link-search=native={}",
        format!("{}/lib/", out_dir)
    );
    println!("cargo:include={}", out_dir);

    // Invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // That should do it...
    Ok(())
}
