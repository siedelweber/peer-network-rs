"""Negative witnesses for codec confinement and the complete case census."""
from pathlib import Path
import unittest
import copy
from wallet_cases import check as check_cases
from wallet_boundary import check, check_features


class WalletBoundary(unittest.TestCase):
    def test_dependency_features(self):
        """Claim: The codec's unified curve, hash and entropy features match the reviewed vocabulary; normal host dependencies exclude the wallet and normal wallet dependencies exclude the heap profiler.
        ´claim:discipline:wallet-development-edges-stay-out-of-production´
        ´test:integration:test-dependency-features´
        """
        self.assertTrue(check_features())
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
        ):
            try:
                source.write_bytes(original+fixture)
                with self.assertRaisesRegex(ValueError,'codec path outside'):check()
            finally:source.write_bytes(original)
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
