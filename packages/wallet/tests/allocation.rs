//! One profiler per child test process; the reviewed dependency owns the allocator.
use std::fmt::Write as _;
mod oracle;

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

// Keep the authored case visible to the source census, but emit a plain
// synchronous function for this harness-free executable, not a libtest case.
macro_rules! synchronous_case {
    (@marker test) => {};
    (@case [$($docs:tt)*] #[doc = $doc:literal] $($rest:tt)*) => {
        synchronous_case!(@case [$($docs)* #[doc = $doc]] $($rest)*);
    };
    (@case [$($docs:tt)*] #[$marker:ident] fn $name:ident($($args:tt)*) $body:block) => {
        synchronous_case!(@marker $marker);
        $($docs)*
        fn $name($($args)*) $body
    };
    ($($case:tt)*) => {
        synchronous_case!(@case [] $($case)*);
    };
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--allocation-vector") {
        assert!(args.len() == 2 || args.len() == 4, "allocation child arguments");
        let control = if args.len() == 4 {
            assert_eq!(args[2], "--allocation-control");
            Some(args[3].as_str())
        } else {
            None
        };
        decoder_reservations(Some(&args[1]), control);
        return;
    }
    // Nextest asks for the complete and ignored-only inventories separately,
    // then invokes the selected case with --exact and --nocapture.
    let mut list = false;
    let mut ignored = false;
    let mut exact = false;
    let mut filters = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--list" => list = true,
            "--ignored" => ignored = true,
            "--exact" => exact = true,
            "--nocapture" | "--include-ignored" => {}
            "--format" => assert_eq!(args.next().map(String::as_str), Some("terse")),
            value if !value.starts_with('-') => filters.push(value),
            _ => panic!("unsupported allocation harness argument: {arg}"),
        }
    }
    let name = "decoder_reservations";
    let selected = !ignored
        && (filters.is_empty()
            || filters
                .iter()
                .any(|filter| if exact { name == *filter } else { name.contains(filter) }));
    if list {
        if selected {
            list_case();
        }
    } else if selected {
        decoder_reservations(None, None);
    }
}

// Nextest discovery is the test harness protocol, not command result JSON.
fn list_case() {
    use std::io::Write as _;
    writeln!(std::io::stdout().lock(), "decoder_reservations: test").unwrap();
}

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

fn surjection_block() -> Vec<u8> {
    let transaction = oracle::transaction(include_bytes!("../fuzz/seeds/proof-transaction")).unwrap();
    let output = transaction.outputs.iter().find(|output| output.witness[0] != 0).unwrap();
    // The upstream seed's short CompactSize prefixes a serialized surjection
    // proof. Retain that proof, but omit the independent range proof so all
    // 4,094 outputs and their native parsed proofs fit the byte envelope.
    let proof_length = usize::from(output.witness[0]);
    assert!((1..253).contains(&proof_length));
    let mut bytes = vec![2, 0, 0, 0, 1, 1];
    input(&mut bytes);
    bytes.push(253);
    bytes.extend(4094u16.to_le_bytes());
    for _ in 0..4094 {
        bytes.extend(&output.asset);
        bytes.extend(&output.value);
        bytes.extend(&output.nonce);
        bytes.push(0); // Empty output script is structurally permitted.
    }
    bytes.extend([0; 8]); // Lock time and the single input's empty witness.
    for _ in 0..4094 {
        bytes.extend(&output.witness[..=proof_length]);
        bytes.push(0); // No range proof.
    }
    let mut block = vec![0; 76];
    block.extend([0, 0, 1]);
    block.extend(bytes);
    assert_eq!(block.len(), 692_023);
    let (_, decoded) = oracle::block(&block).unwrap();
    assert_eq!(decoded[0].outputs.len(), 4094);
    assert!(decoded[0].outputs.iter().all(|output| output.witness[0] != 0));
    block
}

synchronous_case! {
/// Claim: Per-vector allocator measurements cover hostile, maximum and over-limit counts, short payloads and nested witnesses; rejected prefixes allocate nothing in the adapter, and successful layouts stay below the declared requested-allocation envelope and release their measured live storage.
#[doc = "´claim:wallet:decoder-reservations-have-measured-bounds´"]
#[doc = "´test:integration:decoder-reservations´"]
#[test]
fn decoder_reservations(selected: Option<&str>, control: Option<&str>) {
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
        ("block-surjections", surjection_block(), true),
        ("block-short", vec![0; 76], false),
    ];
    let mut evidence = String::from("vector,requested,peak,live\n");
    assert!(
        selected.is_none_or(|selected| rows.iter().any(|(name, _, _)| *name == selected)),
        "unknown allocation vector"
    );
    for (name, bytes, accepted) in rows {
        if selected.is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--allocation-vector", name])
                .status()
                .unwrap();
            assert!(status.success(), "allocation child {name}");
            let row = std::fs::read_to_string(format!("../../.lane/wallet-allocation-{name}.csv")).unwrap();
            evidence.push_str(&row);
            continue;
        }
        if selected != Some(name) {
            continue;
        }
        measure(name, &bytes, accepted, limits, control);
    }
    if selected.is_none() {
        for control in ["live", "envelope", "rejected"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--allocation-vector", "block-short", "--allocation-control", control])
                .output()
                .unwrap();
            assert!(!output.status.success(), "allocation control {control} must refuse");
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(error.contains(&format!("block-short: {control}")), "{error}");
        }
        std::fs::write("../../.lane/wallet-allocation.csv", evidence).unwrap();
    }
}

}

fn measure(name: &str, bytes: &[u8], accepted: bool, limits: pn_wallet::Limits, control: Option<&str>) {
    let mut limits = limits;
    if matches!(name, "maximum-short" | "over-limit" | "hostile" | "maximum" | "nested") {
        limits.items = 1024;
    }
    if control.is_some() {
        assert_eq!(name, "block-short");
        limits.items = 1;
    }
    let envelope = 16 * bytes.len() + 15_360 * limits.items + 4_194_304;
    // Inspect outside the measurement window. A process-wide profiler is
    // attributable only while this synchronous child is its sole thread.
    assert_eq!(
        std::fs::read_dir("/proc/self/task").unwrap().count(),
        1,
        "sole allocation thread"
    );
    let profiler = dhat::Profiler::builder().testing().build();
    let retained = match control {
        Some("live") => Some(std::hint::black_box(vec![0u8; 1])),
        Some("envelope") => {
            drop(std::hint::black_box(Vec::<u8>::with_capacity(envelope + 1)));
            None
        }
        Some("rejected") => {
            drop(std::hint::black_box(vec![0u8; 1]));
            None
        }
        None => None,
        Some(_) => panic!("unknown allocation control"),
    };
    let success = if name.starts_with("block-") {
        let decoded = pn_wallet::decode_block(bytes, limits);
        let success = decoded.is_ok();
        drop(decoded);
        success
    } else {
        let decoded = pn_wallet::decode_transaction(bytes, limits);
        let success = decoded.is_ok();
        drop(decoded);
        success
    };
    let stats = dhat::HeapStats::get();
    let requested = usize::try_from(stats.total_bytes).unwrap();
    let peak = stats.max_bytes;
    let live = stats.curr_bytes;
    drop(profiler);
    drop(retained);
    assert_eq!(success, accepted, "{name}");
    assert_eq!(live, 0, "{name}: live");
    assert!(peak <= envelope && requested <= envelope, "{name}: envelope");
    if !accepted {
        assert_eq!(requested, 0, "{name}: rejected");
    }
    let mut row = String::new();
    writeln!(&mut row, "{name},{requested},{peak},{live}").unwrap();
    std::fs::create_dir_all("../../.lane").unwrap();
    std::fs::write(format!("../../.lane/wallet-allocation-{name}.csv"), row).unwrap();
}
