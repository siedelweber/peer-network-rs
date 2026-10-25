"""Negative witnesses for codec confinement and the complete case census."""
from pathlib import Path
import unittest
import copy
from wallet_cases import check as check_cases
from wallet_boundary import check, check_features, check_build_scripts, check_production_tree
import json
import tomllib


class WalletBoundary(unittest.TestCase):
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
            with self.assertRaisesRegex(ValueError, 'production graph'):
                check_production_tree('pn-wallet', f'pn-wallet v0.1.0\n{name} v{version}\n', allowed)
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
            (b'pub type Exposed = elements::Transaction;', 'public type alias'),
            (b'pub fn exposed() -> elements::Transaction { todo!() }', 'public signature'),
            (b'pub const fn exposed() -> elements::Transaction { todo!() }', 'public signature'),
            (b'use elements::Transaction as Hidden; pub fn exposed() -> Hidden { todo!() }', 'public signature'),
            (b'fn misplaced() { let _ = &*elements::secp256k1_zkp::SECP256K1; }', 'production global context'),
            (b'#[cfg(any(test, feature="fuzzing"))] fn misplaced() { let _ = &*elements::secp256k1_zkp::SECP256K1; }', 'production global context'),
        ]:
            try:
                adapter.write_bytes(adapter_original+b'\n'+fixture+b'\n')
                with self.assertRaisesRegex(ValueError,cause): check()
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
