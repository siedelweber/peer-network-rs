"""Negative witnesses for codec confinement and the complete case census."""
from pathlib import Path
import unittest
import copy
from wallet_cases import check as check_cases
from wallet_boundary import check, check_features, check_build_scripts, check_production_tree
import wallet_crypto
import json
import tomllib
import subprocess
import os


class WalletBoundary(unittest.TestCase):
    def test_rpc_type_boundary(self):
        """Claim: The RPC bootstrap requires secret carriers and has no Display representation, and a caller cannot supply arbitrary method strings or wallet selections to the closed read interface.
        ´claim:discipline:wallet-rpc-types-confine-private-authority´
        ´test:integration:test-rpc-type-boundary´
        """
        source=Path('packages/wallet/src/lib.rs')
        original=source.read_bytes()
        probe=b'''\nfn private_rpc_probe(config: RpcConfig, client: &RpcClient, root: std::fs::File) {
            let _display = format!("{config}");
            let _method = client.read("getwalletinfo");
            let _wallet = Read::Wallet("private_wallet_sentinel");
            let _plain = RpcConfig::new(RpcLink::HostSecured, String::new(), 42110, root, String::new(), 1);
        }\n'''
        try:
            source.write_bytes(original+probe)
            result=subprocess.run(['cargo','check','--offline','--locked','--profile','gate','-p','pn-wallet','--lib'],capture_output=True,check=False,timeout=180)
        finally:
            source.write_bytes(original)
        Path('.lane/wallet-rpc-compile-fail.log').write_bytes(result.stderr)
        self.assertNotEqual(result.returncode,0)
        for message in [b'E0277',b'E0308',b'E0599',b'SecretBox',b'Display',b'expected `Read`',b'Wallet']:
            self.assertIn(message,result.stderr)

    def test_dependency_features(self):
        """Claim: The codec's unified curve, hash and entropy features match the reviewed vocabulary; normal host dependencies exclude the wallet and normal wallet dependencies exclude the heap profiler.
        ´claim:discipline:wallet-development-edges-stay-out-of-production´
        ´test:integration:test-dependency-features´
        """
        self.assertTrue(check_features())
        manifest = Path('packages/wallet/Cargo.toml')
        original = manifest.read_bytes()
        try:
            changed = original.replace(b'dhat = "=0.3.3"\n', b'').replace(
                b'[dependencies]\n', b'[dependencies]\ndhat = "=0.3.3"\n')
            self.assertNotEqual(changed, original)
            manifest.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, 'production graph'):
                check_features()
        finally:
            manifest.write_bytes(original)
        allowed = json.loads(Path('ci/wallet-production-packages.json').read_text())
        for dependency in ['dhat 0.3.3', 'proptest 1.12.0', 'libfuzzer-sys 0.4.13', 'arbitrary 1.5.0', 'pn-wallet-fuzz 0.0.0']:
            name, version = dependency.split()
            for owner in ['pn-wallet', 'pn-graph']:
                with self.assertRaisesRegex(ValueError, 'production graph'):
                    check_production_tree(owner, f'{owner} v0.1.0\n{name} v{version}\n', allowed)
        with self.assertRaisesRegex(ValueError, 'production graph'):
            check_production_tree('pn-host', 'pn-host v0.1.0\npn-wallet v0.1.0\n', allowed)
        rows = tomllib.loads(Path('docs/inputs/wallet-dependencies.toml').read_text())['rows']
        for row in rows:
            package = dict(name=row['name'], version=row['version'], manifest_path='/fixture/Cargo.toml',
                           targets=[] if row['build']=='none' else [dict(kind=['custom-build'], src_path='/fixture/'+row['build'])])
            self.assertIsNone(check_build_scripts([row], [package]))
            bad = dict(row, build='build.rs' if row['build']=='none' else 'none')
            with self.assertRaisesRegex(ValueError, 'build-script field'):
                check_build_scripts([bad], [package])
    def test_fixture_ports(self):
        """Claim: The Elements fixture allocator draws from ports disjoint from PostgreSQL's 42100 to 42119, accepts a port whose closed connections linger in TIME_WAIT, skips a port another process listens on, and starts the daemon on another port when its probed port is taken before launch, and keeps concurrent binary version checks each in its own data directory; a harness failure prints its error type and message, including a missing binary's path, and a stalled producer exchange names its method and elapsed time against the socket bound.
        ´claim:discipline:wallet-fixture-ports-survive-time-wait´
        ´test:integration:test-fixture-ports´
        """
        import socket
        import time
        import types
        import wallet_elements
        self.assertFalse(set(wallet_elements.PORTS) & set(range(42100, 42120)))
        # Closing the accepted side first leaves the server port in TIME_WAIT, as the daemon does.
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('127.0.0.1', 0))
            server.listen()
            port = server.getsockname()[1]
            client = socket.create_connection(('127.0.0.1', port))
            accepted, _ = server.accept()
            accepted.close()
            time.sleep(0.1)
            client.close()
        with socket.socket() as plain, self.assertRaises(OSError):
            plain.bind(('127.0.0.1', port))
        with wallet_elements.port_selection([port]) as chosen:
            self.assertEqual(chosen, port)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            with self.assertRaisesRegex(RuntimeError, 'range exhausted'):
                with wallet_elements.port_selection([listener.getsockname()[1]]):
                    pass
        # Another account takes the probed port before launch: the daemon starts on the next one.
        probe = wallet_elements.free
        held = next(candidate for candidate in wallet_elements.PORTS if probe(candidate))
        root = (Path('.lane')/'wallet-port-race').resolve()
        with socket.socket() as taker:
            taker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            taker.bind(('127.0.0.1', held))
            taker.listen()
            # The scan starts at offset zero and reports the held port free, so the first launch meets it.
            draw = wallet_elements.secrets
            wallet_elements.secrets = types.SimpleNamespace(randbelow=lambda _bound: 0, token_hex=draw.token_hex)
            wallet_elements.free = lambda candidate: candidate == held or (candidate > held and probe(candidate))
            try:
                wallet_elements.start(root)
                started = json.loads((root/'producer.json').read_text())['port']
            finally:
                wallet_elements.free = probe
                wallet_elements.secrets = draw
                wallet_elements.stop(root)
        self.assertGreater(started, held)
        self.assertIn(started, wallet_elements.PORTS)
        # Concurrent fixtures check the binary at once; each query stays in its own data directory.
        import concurrent.futures
        roots = [(Path('.lane')/f'wallet-version-{n}').resolve() for n in range(4)]
        for directory in roots:
            directory.mkdir(parents=True, exist_ok=True)
        with concurrent.futures.ThreadPoolExecutor(4) as pool:
            versions = list(pool.map(wallet_elements.installed_version, roots))
        expected = json.loads(Path('packages/wallet/provisioning.json').read_text())['binary']
        self.assertEqual(versions, [expected] * 4)
        result = subprocess.run(['python3', '-B', 'ci/wallet_elements.py', 'stop', '--root', '/'],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr.strip(),
                         'Elements fixture unavailable: RuntimeError: Elements fixture must be directly under workspace .lane')
        missing = subprocess.run(['python3', '-B', 'ci/wallet_elements.py', 'start', '--root', '.lane/wallet-cause-witness'],
                                 capture_output=True, text=True, check=False, env=dict(os.environ, PN_ELEMENTS_BIN='/nonexistent'))
        self.assertEqual(missing.returncode, 1)
        self.assertTrue(missing.stderr.startswith('Elements fixture unavailable: FileNotFoundError: '))
        self.assertIn('/nonexistent/elementsd', missing.stderr)
        # A stalled producer exchange names its public method and elapsed time against the socket bound.
        with socket.socket() as silent:
            silent.bind(('127.0.0.1', 0))
            silent.listen()
            bound = wallet_elements.RPC_TIMEOUT
            wallet_elements.RPC_TIMEOUT = 0.2
            try:
                with self.assertRaisesRegex(TimeoutError, r'^getblockcount exceeded the 0\.2 s socket bound after \d+\.\d{3} s$'):
                    wallet_elements.rpc(dict(port=silent.getsockname()[1], producer='fixture:fixture'), 'getblockcount')
            finally:
                wallet_elements.RPC_TIMEOUT = bound

    def test_codec_pins(self):
        """Claim: Every registry package of the wallet's normal and build closure carries its reviewed archive checksum in the lockfile, and both built C archives export exactly the reviewed module families, with ECDH, SCHNORRSIG, EXTRAKEYS and ELLSWIFT in secp256k1-sys and SURJECTIONPROOF, GENERATOR, RANGEPROOF, ECDSA_ADAPTOR and WHITELIST in secp256k1-zkp-sys; a changed checksum, a missing module, an unreviewed module or an unknown family refuses.
        ´claim:discipline:wallet-codec-pins-match-review´
        ´test:integration:test-codec-pins´
        """
        self.assertTrue(wallet_crypto.check())
        rows = [dict(name='elements', version='0.27.0', checksum='a' * 64)]
        lock = dict(package=[dict(name='elements', version='0.27.0', checksum='a' * 64), dict(name='pn-wallet', version='0.1.0')])
        tree = {('elements', '0.27.0'), ('pn-wallet', '0.1.0')}
        self.assertIsNone(wallet_crypto.check_checksums(lock, rows, tree))
        for changed in ['b' * 64, None]:
            altered = [dict(rows[0], checksum=changed)] if changed else []
            with self.assertRaisesRegex(ValueError, 'checksum differs'):
                wallet_crypto.check_checksums(lock, altered, tree)
        with self.assertRaisesRegex(ValueError, 'checksums disagree'):
            wallet_crypto.check_checksums(lock, rows + [dict(rows[0], checksum='c' * 64)], tree)
        for package, spec in wallet_crypto.SNAPSHOTS.items():
            reviewed = {spec['prefix'] + name for name in spec['enabled'].values()}
            reviewed |= {spec['prefix'] + family + '_fixture' for family in spec['families']}
            self.assertIsNone(wallet_crypto.check_modules(package, reviewed))
            first = next(iter(spec['enabled'].values()))
            for symbols in [reviewed - {spec['prefix'] + first},
                            reviewed | {spec['prefix'] + next(iter(spec['absent'].values()))},
                            reviewed | {spec['prefix'] + 'musig_unreviewed'}]:
                with self.assertRaisesRegex(ValueError, 'C modules differ'):
                    wallet_crypto.check_modules(package, symbols)
        with self.assertRaisesRegex(ValueError, 'static library'):
            wallet_crypto.archive_symbols(b'not an archive')

    def test_codec_provenance(self):
        """Claim: The workspace channel, the answering rustc's commit and the compiler identity each sys crate's built library embeds must all match the build policy's pinned rustc commit for nightly-2026-10-16, the bundled snapshots name exactly the upstream revisions record 023 cites, and the record states those revisions, modules and compiler; another channel, a compiler and both libraries agreeing on another nightly, a library disagreeing with the compiler, an empty library, another revision or an omitted record value refuses.
        ´claim:discipline:wallet-codec-provenance-matches-build´
        ´test:integration:test-codec-provenance´
        """
        self.assertTrue(wallet_crypto.check())
        channel, commit = wallet_crypto.reviewed_compiler(Path('.'))
        self.assertIsNone(wallet_crypto.check_channel(channel, channel))
        with self.assertRaisesRegex(ValueError, 'reviewed pin'):
            wallet_crypto.check_channel('nightly', channel)
        def answering(hash_, release):
            return f'rustc {release}\nrelease: {release}\ncommit-hash: {hash_}\ncommit-date: 2026-10-15\n'
        version = f'rustc 1.101.0-nightly ({commit[:9]} 2026-10-15)'
        library = b'\0' + version.encode() + b'\0'
        self.assertIsNone(wallet_crypto.check_answering(answering(commit, '1.101.0-nightly'), commit))
        self.assertIsNone(wallet_crypto.check_compiler('secp256k1-sys', library, version, commit))
        # The declaration is unchanged while the compiler and both libraries agree on another nightly.
        other = ''.join('e' if digit == 'f' else 'f' for digit in commit)
        other_version = f'rustc 1.102.0-nightly ({other[:9]} 2026-11-01)'
        with self.assertRaisesRegex(ValueError, 'pinned commit'):
            wallet_crypto.check_answering(answering(other, '1.102.0-nightly'), commit)
        for package in wallet_crypto.SNAPSHOTS:
            with self.assertRaisesRegex(ValueError, 'another compiler'):
                wallet_crypto.check_compiler(package, b'\0' + other_version.encode() + b'\0', other_version, commit)
        for rlib in [b'\0' + other_version.encode() + b'\0', b'', library + other_version.encode()]:
            with self.assertRaisesRegex(ValueError, 'another compiler'):
                wallet_crypto.check_compiler('secp256k1-sys', rlib, version, commit)
        record = Path('adr/023-cryptographic-base.md').read_text()
        for package, spec in wallet_crypto.SNAPSHOTS.items():
            revision = '# vendored\n' + spec['revision'] + '\n'
            self.assertIsNone(wallet_crypto.check_provenance(package, revision))
            for wrong in ['# vendored\n' + 'f' * 40 + '\n', revision + spec['revision'] + '\n', '']:
                with self.assertRaisesRegex(ValueError, 'provenance differs'):
                    wallet_crypto.check_provenance(package, wrong)
            for value in [spec['revision'], next(iter(spec['enabled']))]:
                with self.assertRaisesRegex(ValueError, 'record omits'):
                    wallet_crypto.check_record(record.replace(value, ''), channel)
        with self.assertRaisesRegex(ValueError, 'record omits the pinned compiler'):
            wallet_crypto.check_record(record.replace(channel, ''), channel)

    def test_case_census(self):
        """Claim: Every declared case must remain present, bind a real source claim with a passed result when scoped, and block discharge while any case is held.
        ´claim:discipline:wallet-census-refuses-missing-evidence´
        ´test:integration:test-case-census´
        """
        groups = [{'name': 'layout', 'cases': ['one', 'two']}]
        rows = [{'group': 'layout', 'case': c, 'status': 'scoped', 'claims': ['claim']} for c in ['one', 'two']]
        obligations = [{'name': 'ROOT::verif:devnet:wallet-layout', 'case_census': ['one', 'two'], 'status': 'scoped-supported', 'claims': ['claim']}]
        sites = [{'claim': 'claim', 'operation': 'test'}]
        results = [{'operation': 'test', 'outcome': 'passed'}]
        self.assertEqual(check_cases(groups, rows, obligations, sites, results), 2)
        for invalid in [rows[:1], rows+rows[:1]]:
            with self.assertRaisesRegex(ValueError, 'census'): check_cases(groups, invalid, obligations, sites, results)
        with self.assertRaisesRegex(ValueError, 'source claim'): check_cases(groups, rows, obligations, [], results)
        with self.assertRaisesRegex(ValueError, 'passed execution'): check_cases(groups, rows, obligations, sites, [])
        held = copy.deepcopy(rows)
        held[0].update(status='held', claims=[], missing='later integration')
        with self.assertRaisesRegex(ValueError, 'held case'): check_cases(groups, held, obligations, sites, results)

    def test_confinement(self):
        """Claim: Cargo identifies renamed codec dependencies, and the source check rejects global-context, hash-path and re-export uses outside the sole decoder adapter.
        ´claim:discipline:wallet-codec-paths-stay-confined´
        ´test:integration:test-confinement´
        """
        self.assertTrue(check())
        source=Path('packages/wallet/src/lib.rs')
        original=source.read_bytes()
        manifest=Path('packages/wallet/Cargo.toml')
        original_manifest=manifest.read_bytes()
        for fixture in (
            b'\nfn misplaced() { let _ = &*elements::secp256k1_zkp::SECP256K1; }\n',
            b'\nuse elements::hashes as hidden_hashes;\n',
            b'\npub use elements as exposed;\n',
            b'\npub type Exposed = elements::Transaction;\n',
            b'\npub fn exposed() -> elements::Transaction { todo!() }\n',
            b'\npub struct Exposed { pub value: elements::Transaction }\n',
            b'\npub enum Exposed { Value(elements::Transaction) }\n',
            b'\npub const EXPOSED: Option<elements::Transaction> = None;\n',
            b'\npub static EXPOSED: Option<elements::Transaction> = None;\n',
        ):
            try:
                source.write_bytes(original+fixture)
                with self.assertRaisesRegex(ValueError,'codec path outside'):check()
            finally:source.write_bytes(original)
        adapter = Path('packages/wallet/src/decoder.rs')
        adapter_original = adapter.read_bytes()
        for fixture, cause in [
            (b'pub use elements as exposed;', 're-export'),
            (b'pub(crate) use elements as exposed;', 're-export'),
            (b'use elements::*;', 'codec glob import'),
            (b'pub type Exposed = elements::Transaction;', 'public type alias'),
            (b'pub fn exposed() -> elements::Transaction { todo!() }', 'public signature'),
            (b'pub const fn exposed() -> elements::Transaction { todo!() }', 'public signature'),
            (b'use elements::Transaction as Hidden; pub fn exposed() -> Hidden { todo!() }', 'public signature'),
            (b'pub struct Exposed { pub value: elements::Transaction }', 'public struct'),
            (b'pub struct Exposed { pub value: std::collections::BTreeMap<u8, elements::Transaction> }', 'public struct'),
            (b'use elements::Transaction as Hidden; pub struct Exposed(pub(crate) Option<Hidden>);', 'public struct'),
            (b'pub struct Exposed { pub callback: fn() -> elements::Transaction }', 'public struct'),
            (b'pub struct Exposed { pub callback: fn() -> u8, pub value: elements::Transaction }', 'public struct'),
            (b'pub struct Exposed(pub Option<fn() -> u8>, pub elements::Transaction);', 'public struct'),
            (b'pub struct Exposed<F: Fn() -> u8> { callback: F, pub value: elements::Transaction }', 'public struct'),
            (b'pub struct Exposed<F> where F: Fn() -> u8 { callback: F, pub value: elements::Transaction }', 'public struct'),
            (b'pub enum Exposed { Value { value: elements::Transaction } }', 'public enum'),
            (b'use elements::Transaction as Hidden; pub enum Exposed { Value(Hidden) }', 'public enum'),
            (b'pub const EXPOSED: Option<elements::Transaction> = None;', 'public const'),
            (b'use elements::Transaction as Hidden; pub const EXPOSED: Option<Hidden> = None;', 'public const'),
            (b'pub static EXPOSED: Option<elements::Transaction> = None;', 'public static'),
            (b'use elements::Transaction as Hidden; pub static EXPOSED: Option<Hidden> = None;', 'public static'),
            (b'fn misplaced() { let _ = &*elements::secp256k1_zkp::SECP256K1; }', 'production global context'),
            (b'#[cfg(any(test, feature="fuzzing"))] fn misplaced() { let _ = &*elements::secp256k1_zkp::SECP256K1; }', 'production global context'),
        ]:
            try:
                adapter.write_bytes(adapter_original+b'\n'+fixture+b'\n')
                with self.assertRaisesRegex(ValueError,cause): check()
            finally: adapter.write_bytes(adapter_original)
        # Private codec storage stays admitted beside public callbacks.
        for fixture in (
            b'pub struct Wrapper { pub callback: fn() -> u8, value: elements::Transaction }',
            b'pub struct Wrapper<F: Fn() -> u8> { pub callback: F, value: elements::Transaction }',
            b'pub struct Wrapper(pub Option<fn() -> u8>, elements::Transaction);',
        ):
            try:
                adapter.write_bytes(adapter_original+b'\n'+fixture+b'\n')
                self.assertTrue(check())
            finally: adapter.write_bytes(adapter_original)
        try:
            manifest.write_bytes(original_manifest.replace(
                b'elements = { version', b'innocent = { package = "elements", version'))
            self.assertNotEqual(manifest.read_bytes(),original_manifest)
            source.write_bytes(original+b'\nuse innocent::hashes as hidden_hashes;\n')
            with self.assertRaisesRegex(ValueError,'codec path outside'):check()
        finally:
            source.write_bytes(original)
            manifest.write_bytes(original_manifest)


if __name__ == '__main__':
    unittest.main()
