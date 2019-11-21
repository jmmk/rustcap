#[cfg(unix)]
extern crate pkg_config;

#[cfg(all(unix, feature = "static-libpcap"))]
extern crate cmake;

#[cfg(windows)]
use std::path::PathBuf;
#[cfg(all(unix, not(feature = "static-libpcap")))]
use std::process::Command;

#[cfg(windows)]
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut lib_path = PathBuf::from(&dir).join("Lib");
    if cfg!(target_arch = "x86_64") {
        lib_path.push("x64")
    }
    println!("cargo:rustc-link-search=native={}", lib_path.display());
    println!("cargo:rustc-link-lib=packet");
    println!("cargo:rustc-link-lib=wpcap");
}

#[cfg(all(unix, feature = "static-libpcap"))]
fn main() {
    let linux_kernel_headers = std::env::var("LINUX_KERNEL_HEADERS").ok();

    let mut cmake_config = cmake::Config::new("libpcap");

    if let Some(linux_kernel_headers) = linux_kernel_headers {
        cmake_config.define("DISABLE_USB", "ON");
        cmake_config.define("DISABLE_DBUS", "ON");
        cmake_config.define("DISABLE_BLUETOOTH", "ON");
        cmake_config.define("DISABLE_RDMA", "ON");
        cmake_config.define("ENABLE_REMOTE", "OFF");
        cmake_config.define("USE_STATIC_RT", "ON");
        cmake_config.define("BUILD_SHARED_LIBS", "OFF");
        cmake_config.cflag(format!("-I{}", linux_kernel_headers));
    }

    let mut dst = cmake_config.build();
    dst.push("lib");

    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-link-lib=static=pcap");
}

#[cfg(all(unix, not(feature = "static-libpcap")))]
fn main() {
    // First, try pkg_config (available in libpcap 1.9.0+)
    if pkg_config::probe_library("libpcap").is_ok() {
        return;
    }

    // Fall back to pcap-config
    match Command::new("pcap-config").arg("--libs").output() {
        Ok(output) => {
            parse_libs_cflags(&output.stdout)
        },
        _ => (),
    }

    // on macOS, pcap-config returns /usr/local/lib, but libpcap is actually in /usr/lib
    println!("cargo:rustc-link-search=native=/usr/lib");
}

/// Adapted from pkg_config
#[cfg(all(unix, not(feature = "static-libpcap")))]
fn parse_libs_cflags(output: &[u8]) {
    let words = split_flags(output);
    let parts = words
        .iter()
        .filter(|l| l.len() > 2)
        .map(|arg| (&arg[0..2], &arg[2..]))
        .collect::<Vec<_>>();

    for &(flag, val) in &parts {
        match flag {
            "-L" => {
                println!("cargo:rustc-link-search=native={}", val);
            }
            "-F" => {
                println!("cargo:rustc-link-search=framework={}", val);
            }
            "-l" => {
                println!("cargo:rustc-link-lib={}", val);
            }
            _ => {}
        }
    }
}

/// Copied from pkg_config
#[cfg(all(unix, not(feature = "static-libpcap")))]
fn split_flags(output: &[u8]) -> Vec<String> {
    let mut word = Vec::new();
    let mut words = Vec::new();
    let mut escaped = false;

    for &b in output {
        match b {
            _ if escaped => {
                escaped = false;
                word.push(b);
            }
            b'\\' => escaped = true,
            b'\t' | b'\n' | b'\r' | b' ' => {
                if !word.is_empty() {
                    words.push(String::from_utf8(word).unwrap());
                    word = Vec::new();
                }
            }
            _ => word.push(b),
        }
    }

    if !word.is_empty() {
        words.push(String::from_utf8(word).unwrap());
    }

    words
}
