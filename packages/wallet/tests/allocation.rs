//! One profiler per child test process; the reviewed dependency owns the allocator.
use std::fmt::Write as _;

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

fn prefix(count: u16, witness: bool) -> Vec<u8> {
    let mut bytes = vec![2, 0, 0, 0, u8::from(witness), 253];
    bytes.extend(count.to_le_bytes());
    bytes
}

fn input(bytes: &mut Vec<u8>) {
    bytes.extend([0; 32]);
    bytes.extend([255; 4]);
    bytes.push(0);
    bytes.extend([255; 4]);
}

/// Claim: Per-vector allocator measurements cover hostile, maximum and over-limit counts, short payloads and nested witnesses; rejected prefixes allocate nothing in the adapter, and successful layouts stay below the declared requested-allocation envelope and release their measured live storage.
/// ´claim:wallet:decoder-reservations-have-measured-bounds´
/// ´test:integration:decoder-reservations´
#[test]
fn decoder_reservations() {
    let selected = std::env::var("PN_WALLET_ALLOCATION_VECTOR").ok();
    let limits = pn_wallet::Limits {
        bytes: 1_048_576,
        items: 1024,
        script: 10_000,
        witness: 65_536,
        allocation: 134_217_728,
    };
    let mut maximum = prefix(1024, false);
    for _ in 0..1024 {
        input(&mut maximum);
    }
    maximum.extend([0; 5]);
    let mut nested = vec![2, 0, 0, 0, 1, 1];
    input(&mut nested);
    nested.extend([0; 5]);
    nested.extend([0, 0, 253, 254, 3]);
    for _ in 0..1022 {
        nested.extend([1, 7]);
    }
    nested.push(0);
    let rows = [
        ("maximum-short", prefix(1024, false), false),
        ("over-limit", prefix(1025, false), false),
        (
            "hostile",
            vec![2, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255],
            false,
        ),
        ("maximum", maximum, true),
        ("nested", nested, true),
    ];
    let mut evidence = String::from("vector,requested,peak,live\n");
    for (name, bytes, accepted) in rows {
        if selected.is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "decoder_reservations", "--nocapture"])
                .env("PN_WALLET_ALLOCATION_VECTOR", name)
                .status()
                .unwrap();
            assert!(status.success(), "allocation child {name}");
            let row = std::fs::read_to_string(format!("../../.lane/wallet-allocation-{name}.csv")).unwrap();
            evidence.push_str(&row);
            continue;
        }
        if selected.as_deref() != Some(name) {
            continue;
        }
        let profiler = dhat::Profiler::builder().testing().build();
        let decoded = pn_wallet::decode_transaction(&bytes, limits);
        let success = decoded.is_ok();
        drop(decoded);
        let stats = dhat::HeapStats::get();
        let requested = usize::try_from(stats.total_bytes).unwrap();
        let peak = stats.max_bytes;
        let live = stats.curr_bytes;
        drop(profiler);
        assert_eq!(success, accepted, "{name}");
        assert_eq!(live, 0, "{name}");
        assert!(peak <= limits.allocation && requested <= limits.allocation, "{name}");
        if !accepted {
            assert_eq!(requested, 0, "{name}");
        }
        let mut row = String::new();
        writeln!(&mut row, "{name},{requested},{peak},{live}").unwrap();
        std::fs::create_dir_all("../../.lane").unwrap();
        std::fs::write(format!("../../.lane/wallet-allocation-{name}.csv"), row).unwrap();
    }
    if selected.is_none() {
        std::fs::write("../../.lane/wallet-allocation.csv", evidence).unwrap();
    }
}
