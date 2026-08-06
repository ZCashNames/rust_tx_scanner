//! Reports which typecodes a viewing key contains, and — given an address — whether the
//! key actually controls it.
//!
//! The second use is the one an auditor needs. The registrar publishes an address and a
//! viewing key so anyone can replay the command stream; if those two do not correspond,
//! a would-be auditor scans and finds nothing, and cannot tell an honest empty result
//! from a wrong key. This answers that directly, offline, before trusting either value.
//!
//! ```text
//! probe_ufvk <uview1…|uivk1…>              # list typecodes
//! probe_ufvk <uview1…|uivk1…> <u1…>        # also check the key controls that address
//! ```
use zcash_address::unified::{Address, Container, Encoding, Fvk, Ivk, Receiver, Ufvk, Uivk};
use orchard::keys::{FullViewingKey, IncomingViewingKey, Scope};

/// Whether `ivk` can derive `address` — i.e. the key really controls it.
fn controls(ivk: &IncomingViewingKey, address: &str) -> Option<bool> {
    let (_net, ua) = Address::decode(address).ok()?;
    let raw: [u8; 43] = ua.items().iter().find_map(|i| match i {
        Receiver::Orchard(d) => Some(*d),
        _ => None,
    })?;
    let addr = Option::from(orchard::Address::from_raw_address_bytes(&raw))?;
    Some(ivk.diversifier_index(&addr).is_some())
}

fn check_pairing(key: &str, address: &str) {
    let ivk = if key.starts_with("uview") {
        Ufvk::decode(key).ok().and_then(|(_, k)| {
            k.items().into_iter().find_map(|f| match f {
                Fvk::Orchard(d) => FullViewingKey::from_bytes(&d).map(|fvk| fvk.to_ivk(Scope::External)),
                _ => None,
            })
        })
    } else {
        Uivk::decode(key).ok().and_then(|(_, k)| {
            k.items().into_iter().find_map(|i| match i {
                Ivk::Orchard(d) => Option::from(IncomingViewingKey::from_bytes(&d)),
                _ => None,
            })
        })
    };

    match ivk.and_then(|ivk| controls(&ivk, address)) {
        Some(true) => println!("  PAIRING OK   — this key controls that address"),
        Some(false) => {
            println!("  PAIRING FAIL — this key does NOT control that address");
            std::process::exit(2);
        }
        None => {
            eprintln!("  could not check: no Orchard component in the key, or the address is not a UA");
            std::process::exit(1);
        }
    }
}

fn main() {
    let key = std::env::args().nth(1)
        .expect("usage: probe_ufvk <uview1…|uivk1…> [address]");
    let address = std::env::args().nth(2);

    if key.starts_with("uview") {
        let (net, ufvk) = Ufvk::decode(&key).expect("decode UFVK");
        println!("  UFVK, network {net:?}");
        for fvk in ufvk.items() {
            match fvk {
                Fvk::Orchard(d) => println!("    Orchard (0x03)   {} bytes", d.len()),
                Fvk::Sapling(d) => println!("    Sapling (0x02)   {} bytes", d.len()),
                Fvk::P2pkh(d) => println!("    P2PKH   (0x00)   {} bytes", d.len()),
                Fvk::Unknown { typecode, data } => {
                    println!("    Unknown (0x{typecode:02x})   {} bytes", data.len())
                }
            }
        }
    } else if key.starts_with("uivk") {
        let (net, uivk) = Uivk::decode(&key).expect("decode UIVK");
        println!("  UIVK, network {net:?}");
        for ivk in uivk.items() {
            match ivk {
                Ivk::Orchard(d) => println!("    Orchard (0x03)   {} bytes", d.len()),
                Ivk::Sapling(d) => println!("    Sapling (0x02)   {} bytes", d.len()),
                Ivk::P2pkh(d) => println!("    P2PKH   (0x00)   {} bytes", d.len()),
                Ivk::Unknown { typecode, data } => {
                    println!("    Unknown (0x{typecode:02x})   {} bytes", data.len())
                }
            }
        }
    } else {
        eprintln!("  not a uview/uivk key");
        std::process::exit(1);
    }

    if let Some(address) = address {
        check_pairing(&key, &address);
    }
}
