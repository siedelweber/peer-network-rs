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

fn maximum_block() -> Vec<u8> {
    let mut full = prefix(4095, false);
    for index in 0..4095 {
        full.extend([0; 32]);
        full.extend([255; 4]);
        let length = if index == 0 { 8215u16 } else { 932 };
        full.push(253);
        full.extend(length.to_le_bytes());
        full.extend(vec![0; usize::from(length)]);
        full.extend([255; 4]);
    }
    full.extend([0; 5]);
    let mut full_block = vec![0; 76];
    full_block.extend([0, 0, 1]);
    full_block.extend(full);
    assert_eq!(full_block.len(), 4_000_000);
    full_block
}

/// Claim: Per-vector allocator measurements cover hostile, maximum and over-limit counts, short payloads and nested witnesses; rejected prefixes allocate nothing in the adapter, and successful layouts stay below the declared requested-allocation envelope and release their measured live storage.
/// ´claim:wallet:decoder-reservations-have-measured-bounds´
/// ´test:integration:decoder-reservations´
#[test]
fn decoder_reservations() {
    let selected = std::env::var("PN_WALLET_ALLOCATION_VECTOR").ok();
    let limits = pn_wallet::Limits {
        bytes: 4_000_000,
        items: 4096,
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
    let mut block = vec![0; 76];
    block.extend([0, 0, 1]);
    block.extend(include_bytes!("../fuzz/seeds/proof-transaction"));
    let full_block = maximum_block();
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
        ("proof", include_bytes!("../fuzz/seeds/proof-transaction").to_vec(), true),
        ("block-proof", block, true),
        ("block-dynafed", include_bytes!("../fuzz/seeds/dynafed-block").to_vec(), true),
        ("block-4096", full_block, true),
        ("block-short", vec![0; 76], false),
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
        let mut limits = limits;
        if matches!(name, "maximum-short" | "over-limit" | "hostile" | "maximum" | "nested") {
            limits.items = 1024;
        }
        let envelope = 16 * bytes.len() + 15_360 * limits.items + 4_194_304;
        let profiler = dhat::Profiler::builder().testing().build();
        let success = if name.starts_with("block-") {
            let decoded = pn_wallet::decode_block(&bytes, limits);
            let success = decoded.is_ok();
            drop(decoded);
            success
        } else {
            let decoded = pn_wallet::decode_transaction(&bytes, limits);
            let success = decoded.is_ok();
            drop(decoded);
            success
        };
        let stats = dhat::HeapStats::get();
        let requested = usize::try_from(stats.total_bytes).unwrap();
        let peak = stats.max_bytes;
        let live = stats.curr_bytes;
        drop(profiler);
        assert_eq!(success, accepted, "{name}");
        assert_eq!(live, 0, "{name}");
        assert!(peak <= envelope && requested <= envelope, "{name}");
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
