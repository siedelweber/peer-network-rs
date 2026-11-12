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
    def test_authentication_verification_admission(self):
        """Claim: The authentication source admits only its listed binding items and path, rejecting alternatives; independent Python equations agree with every publication row. Actual artifact reproduction belongs to the codec artifact controls.
        ´claim:discipline:authentication-verification-admission-is-reproduced´
        ´test:integration:test-authentication-verification-admission´
        """
        import authentication_crypto
        import authentication_bip340
        self.assertEqual(authentication_bip340.check(), dict(publication_rows=19, malformed_points=5, valid=9))
        from hash_citations import establish
        import csv
        reader = establish(Path('.'), dict(reader='authentication-signature-fixtures', establishment='defined'))
        with Path('packages/act-authentication/tests/bip340.csv').open() as publication:
            public_key = next(csv.DictReader(publication))['public key']
        self.assertTrue(reader(public_key, ''))
        self.assertFalse(reader('unaccounted', ''))
        source = Path(authentication_crypto.BACKEND).read_text()
        authentication_crypto.check_sources({authentication_crypto.BACKEND: source})
        for changed in (source.replace('preallocated_verification_only', 'new'),
                        source.replace('verify_schnorr', 'sign_schnorr'),
                        source + '\nuse secp256k1_zkp as hidden;\n',
                        source + '\nPartialEq::eq(&key.0, &key.0);\n',
                        source + '\nstd::cmp::PartialEq::eq(&key.0, &key.0);\n',
                        source + '\n<secp256k1_zkp::XOnlyPublicKey>::serialize(&key.0);\n',
                        source + '\nkey.escape::<u8>();\n',
                        source + '\nkey.0 < other.0;\n',
                        source + '\nformat!("{}", key.0);\n',
                        source + '\nimpl Key {}\n'):
            with self.assertRaises(ValueError):
                authentication_crypto.check_sources({authentication_crypto.BACKEND: changed})
        with self.assertRaises(ValueError):
            authentication_crypto.check_sources({'packages/act-authentication/src/other.rs': source})

    def test_authentication_encoding_values(self):
        """Claim: Canonical authentication golden values and three role messages match independent Python framing and SHA-256, and an altered message is refused by the comparison.
        ´claim:discipline:authentication-encoding-values-independent´
        ´test:integration:test-authentication-encoding-values´
        """
        from authentication_encoding_vectors import check, vectors
        value = check()
        self.assertEqual(value, vectors())
        changed = copy.deepcopy(value)
        changed['rows'][0]['messages'][1] = '00' * 32
        with self.assertRaisesRegex(ValueError, "golden values differ"):
            check(changed)

    def test_authentication_values(self):
        """Claim: The committed public key digests and tagged scripts match independent hashlib reconstruction, raw contract bytes match their explicit RPC conversion, an independent SHA-256 compression reconstructs every retained daemon entropy, asset and token identifier, transaction identifiers are recomputed from raw bytes, and altered digests are refused.
        ´claim:discipline:authentication-values-have-independent-byte-checks´
        ´test:integration:test-authentication-values´
        """
        from authentication_vectors import check
        value = json.loads(Path('packages/act-authentication/tests/golden.json').read_text())
        self.assertEqual(check(value), (3, 3))
        changed = copy.deepcopy(value)
        changed['keys'][0]['digest'] = '00' * 32
        with self.assertRaisesRegex(ValueError, 'key digest or script differs'):
            check(changed)
        changed = copy.deepcopy(value)
        changed['assets'][0]['asset'] = '00' * 32
        with self.assertRaisesRegex(ValueError, 'asset differs'):
            check(changed)
        for corpus in ['legacy_version_one', 'assets']:
            for name in ['token', 'asset', 'entropy']:
                changed = copy.deepcopy(value)
                changed[corpus][0]['issuance_results'][0][name] = '00' * 32
                with self.assertRaisesRegex(ValueError, 'independent '+name+' differs'):
                    check(changed)
            changed = copy.deepcopy(value)
            changed[corpus][0]['txid'] = '00' * 32
            with self.assertRaisesRegex(ValueError, 'transaction identifier differs'):
                check(changed)
        changed = copy.deepcopy(value)
        changed['assets'][1]['reordered_txid'] = '00' * 32
        with self.assertRaisesRegex(ValueError, 'reordered transaction identifier differs'):
            check(changed)

    def test_archive_provisioning(self):
        """Claim: The declared archive route refuses missing and wrong-checksum fixture bytes at fetch or offline read, ignores unrelated files, and cannot substitute Cargo's cache for its external input.
        ´claim:discipline:vendor-archives-require-explicit-provisioning´
        ´test:integration:test-archive-provisioning´
        """
        import hashlib
        import io
        import tempfile
        from unittest.mock import patch
        from provision_vendor import COMMAND, checked_archive, fetch_archive
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent/'tree'; root.mkdir()
            archives = parent/'archives'
            cargo = parent/'cargo/registry/cache/fixture'; cargo.mkdir(parents=True)
            data = b'public pinned archive fixture'
            checksum = hashlib.sha256(data).hexdigest()
            filename = 'example-1.0.0.crate'
            (cargo/filename).write_bytes(data)
            urls = []
            def fetch(url):
                urls.append(url)
                return io.BytesIO(data)
            with patch.dict(os.environ, PN_VENDOR_ARCHIVES=str(archives), CARGO_HOME=str(parent/'cargo')):
                # A valid Cargo cache archive cannot rescue the missing declared input.
                with self.assertRaisesRegex(ValueError, COMMAND.replace('.', r'\.')):
                    checked_archive(root, 'example', '1.0.0', checksum)
                with self.assertRaisesRegex(ValueError, 'fetch checksum differs'):
                    fetch_archive(root, 'example', '1.0.0', checksum, lambda _: io.BytesIO(b'wrong'))
                self.assertFalse((archives/filename).exists())
                result = fetch_archive(root, 'example', '1.0.0', checksum, fetch)
                self.assertEqual(urls, ['https://static.crates.io/crates/example/example-1.0.0.crate'])
                self.assertEqual(result.read_bytes(), data)
                (archives/'undeclared-1.0.0.crate').write_bytes(b'untrusted')
                self.assertEqual(checked_archive(root, 'example', '1.0.0', checksum), result)
                result.write_bytes(b'wrong')
                with self.assertRaisesRegex(ValueError, 'archive checksum differs'):
                    checked_archive(root, 'example', '1.0.0', checksum)
                with self.assertRaisesRegex(ValueError, 'fetch checksum differs'):
                    fetch_archive(root, 'example', '1.0.0', checksum, lambda _: io.BytesIO(b'wrong'))
                self.assertEqual(result.read_bytes(), b'wrong')
                # Offline consumption cannot call the network, even with no Cargo cache.
                result.write_bytes(data)
                (cargo/filename).unlink()
                with patch('urllib.request.urlopen', side_effect=AssertionError('network read')):
                    self.assertEqual(checked_archive(root, 'example', '1.0.0', checksum), result)
            with patch.dict(os.environ, PN_VENDOR_ARCHIVES=str(root/'archives')):
                with self.assertRaisesRegex(ValueError, 'outside the repository'):
                    checked_archive(root, 'example', '1.0.0', checksum)

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
        """Claim: The Elements fixture allocator draws from ports disjoint from PostgreSQL's declared range and automatic client allocation, accepts a port whose closed connections linger in TIME_WAIT, skips a port another process listens on, and starts the daemon on another port when its probed port is taken before launch, and keeps concurrent binary version checks each in its own data directory; a harness failure prints its error type and message, including a missing binary's path, and a stalled producer exchange names its method and elapsed time against the socket bound. The real legacy wallet uses the declared producer keypool; only wallet creation and private-key import select the administrative socket bound, and each administrative success, RPC error or timeout emits public timing without replay.
        ´claim:discipline:wallet-fixture-ports-survive-time-wait´
        ´test:integration:test-fixture-ports´
        """
        import socket
        import time
        import types
        import wallet_elements
        import tempfile
        from host_postgresql import POSTGRESQL_PORTS, check_ports
        self.assertFalse(set(wallet_elements.PORTS) & set(POSTGRESQL_PORTS))
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc/'ip_local_port_range').write_text('32768 60999\n')
            (proc/'ip_local_reserved_ports').write_text('')
            check_ports(wallet_elements.PORTS, proc)
            (proc/'ip_local_port_range').write_text('20000 60999\n')
            with self.assertRaisesRegex(RuntimeError, 'overlap automatic allocation'):
                check_ports(wallet_elements.PORTS, proc)
            (proc/'ip_local_reserved_ports').write_text('22100-22159\n')
            check_ports(wallet_elements.PORTS, proc)
        # Closing the accepted side first leaves the server port in TIME_WAIT, as the daemon does.
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('127.0.0.1', 0))
            server.listen()
            port = server.getsockname()[1]
            client = socket.create_connection(('127.0.0.1', port))
            accepted, _ = server.accept()
            accepted.close()
            client.settimeout(30)
            self.assertEqual(client.recv(1), b'', 'server FIN must be observed before client close')
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
                config = json.loads((root/'producer.json').read_text())
                started = config['port']
                wallet_elements.rpc(config, 'createwallet', ['producer', False, False, '', False, False])
                wallet = wallet_elements.rpc(config, 'getwalletinfo')
                self.assertFalse(wallet['descriptors'])
                self.assertEqual(wallet['keypoolsize'], wallet_elements.PRODUCER_KEYPOOL)
                self.assertEqual(wallet['keypoolsize_hd_internal'], wallet_elements.PRODUCER_KEYPOOL)
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

        # Method-selected bounds and public timing survive success, RPC errors
        # and transport timeouts; no outcome replays the request.
        from unittest.mock import patch, MagicMock
        from contextlib import redirect_stderr
        import io
        self.assertGreater(wallet_elements.RPC_ADMIN_TIMEOUT, wallet_elements.RPC_TIMEOUT)
        for method in ['createwallet', 'importprivkey', 'getblockcount', 'getnewaddress', 'invalidateblock']:
            administrative = method in ('createwallet', 'importprivkey')
            expected = wallet_elements.RPC_ADMIN_TIMEOUT if administrative else wallet_elements.RPC_TIMEOUT
            for outcome in ['success', 'error', 'timeout']:
                connection = MagicMock()
                response = connection.getresponse.return_value
                response.status = 200
                response.read.return_value = json.dumps(dict(jsonrpc='2.0', id=1, result='fixture')).encode()
                if outcome == 'error':
                    response.read.return_value = json.dumps(dict(jsonrpc='2.0', id=1, error=dict(code=-1))).encode()
                elif outcome == 'timeout':
                    connection.getresponse.side_effect = TimeoutError('private transport sentinel')
                diagnostic = io.StringIO()
                ticks = [100, 100.25, 100.5] if outcome == 'timeout' else [100, 100.25]
                with patch.object(wallet_elements.http.client, 'HTTPConnection', return_value=connection) as factory, \
                     patch.object(wallet_elements.time, 'monotonic', side_effect=ticks), redirect_stderr(diagnostic):
                    if outcome == 'success':
                        self.assertEqual(wallet_elements.rpc(dict(port=1, producer='private credential sentinel'), method), 'fixture')
                    else:
                        error = TimeoutError if outcome == 'timeout' else RuntimeError
                        with self.assertRaises(error):
                            wallet_elements.rpc(dict(port=1, producer='private credential sentinel'), method)
                factory.assert_called_once_with('127.0.0.1', 1, timeout=expected)
                connection.request.assert_called_once()
                connection.close.assert_called_once()
                if administrative:
                    elapsed = '0.500000' if outcome == 'timeout' else '0.250000'
                    self.assertEqual(diagnostic.getvalue(),
                                     f'WALLET-RPC class=administrative method={method} outcome={outcome} '
                                     f'wall_s={elapsed} socket_bound_s={expected}\n')
                else:
                    self.assertEqual(diagnostic.getvalue(), '')

        # A slow success is retained in the test root and printed at shutdown,
        # independent of whether the caller consumes its captured stderr.
        from contextlib import redirect_stdout
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'wallet'; root.mkdir()
            connection = MagicMock()
            response = connection.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps(dict(jsonrpc='2.0', id=1, result='fixture')).encode()
            config = dict(port=1, producer='private credential sentinel', rpc_log=str(root/'wallet-rpc.log'), case='fixture::wallet')
            output = io.StringIO()
            with patch.object(wallet_elements.http.client, 'HTTPConnection', return_value=connection), \
                 patch.object(wallet_elements.time, 'monotonic', side_effect=[100, 110.25]), \
                 patch.dict(os.environ, CARGO_TARGET_DIR=directory, PN_FLAKE_LEDGER=str(Path(directory)/'gate-flakes.jsonl'), PN_GATE_SOURCE='fixture-source'), \
                 redirect_stderr(io.StringIO()), redirect_stdout(output):
                self.assertEqual(wallet_elements.rpc(config, 'createwallet'), 'fixture')
                wallet_elements.report_rpc(root)
            connection.request.assert_called_once()
            retained = (root/'wallet-rpc.log').read_text()
            self.assertIn('WALLET-RPC class=administrative method=createwallet outcome=success wall_s=10.250000', retained)
            self.assertIn(retained, output.getvalue())
            row, = [json.loads(line) for line in (Path(directory)/'gate-flakes.jsonl').read_text().splitlines()]
            self.assertEqual((row['event'], row['commit'], row['case'], row['duration_s']),
                             ('slow-success', 'fixture-source', 'fixture::wallet', 10.25))
            self.assertEqual(row['steady_bound_s'], wallet_elements.RPC_TIMEOUT)
            self.assertEqual(row['administrative_bound_s'], wallet_elements.RPC_ADMIN_TIMEOUT)
            self.assertNotIn('private credential sentinel', retained+output.getvalue())

    def test_codec_pins(self):
        """Claim: Every registry package of the wallet's normal and build closure carries its reviewed archive checksum in the lockfile, and both built C archives export exactly the reviewed module families, with ECDH, SCHNORRSIG, EXTRAKEYS and ELLSWIFT in secp256k1-sys and SURJECTIONPROOF, GENERATOR, RANGEPROOF, ECDSA_ADAPTOR and WHITELIST in secp256k1-zkp-sys; a changed checksum, a missing module, an unreviewed module or an unknown family refuses.
        ´claim:discipline:wallet-codec-pins-match-review´
        ´test:integration:test-codec-pins´
        """
        self.assertTrue(wallet_crypto.check())
        import tempfile
        import hashlib
        import io
        import tarfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'vendor/example').mkdir(parents=True)
            file = root/'vendor/example/lib.rs'; file.write_bytes(b'public fixture')
            row = dict(name='example', version='1.0.0', path='vendor/example', content_manifest='contents.json')
            cache = Path(self.enterContext(tempfile.TemporaryDirectory()))
            archive=cache/'example-1.0.0.crate'
            with tarfile.open(archive,'w:gz') as output:
                entry=tarfile.TarInfo('example-1.0.0/lib.rs'); entry.size=len(file.read_bytes())
                output.addfile(entry,io.BytesIO(file.read_bytes()))
            checksum=hashlib.sha256(archive.read_bytes()).hexdigest()
            self.enterContext(patch.dict(os.environ,PN_VENDOR_ARCHIVES=str(cache)))
            reviewed = {('example','1.0.0'):checksum}
            evidence = dict(name='example',version='1.0.0',archive_checksum=checksum,
                            files={'lib.rs':hashlib.sha256(file.read_bytes()).hexdigest()})
            manifest = root/'contents.json'; manifest.write_text(json.dumps(evidence))
            self.assertIsNone(wallet_crypto.check_vendor_contents(root,row,reviewed))
            from wallet_boundary import check_reviewed_archives
            pin_rows=[dict(name='example', version='1.0.0', checksum=checksum)]
            with patch('wallet_boundary.vendor_packages', return_value=[dict(row,mode='patch')]):
                self.assertIsNone(check_reviewed_archives(root,[dict(name='example',version='1.0.0')],pin_rows))
                with self.assertRaisesRegex(ValueError,'missing from lock'):
                    check_reviewed_archives(root,[],pin_rows)
                with self.assertRaisesRegex(ValueError,'checksum differs'):
                    check_reviewed_archives(root,[dict(name='example',version='1.0.0',checksum='b'*64)],pin_rows)
                with self.assertRaisesRegex(ValueError,'duplicated'):
                    check_reviewed_archives(root,[dict(name='example',version='1.0.0')],pin_rows*2)
            with patch('wallet_boundary.vendor_packages', return_value=[]):
                with self.assertRaisesRegex(ValueError,'checksum differs'):
                    check_reviewed_archives(root,[dict(name='example',version='1.0.0')],pin_rows)
            for field in ['name','version','archive_checksum']:
                manifest.write_text(json.dumps(dict(evidence, **{field:'changed'})))
                with self.assertRaises(ValueError): wallet_crypto.check_vendor_contents(root,row,reviewed)
            manifest.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(ValueError,'review missing'): wallet_crypto.check_vendor_contents(root,row,{})
            file.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'contents differ'): wallet_crypto.check_vendor_contents(root,row,reviewed)
            # Even a self-consistent unpatched tree/manifest cannot differ from the archive.
            manifest.write_text(json.dumps(dict(evidence,files={'lib.rs':hashlib.sha256(file.read_bytes()).hexdigest()})))
            with self.assertRaisesRegex(ValueError,'complete archive members differ'):
                wallet_crypto.check_vendor_contents(root,row,reviewed)
            manifest.write_text(json.dumps(evidence))
            file.unlink()
            with self.assertRaisesRegex(ValueError,'contents differ'): wallet_crypto.check_vendor_contents(root,row,reviewed)
            file.write_bytes(b'public fixture'); (file.parent/'extra').write_bytes(b'extra')
            with self.assertRaisesRegex(ValueError,'contents differ'): wallet_crypto.check_vendor_contents(root,row,reviewed)
        # Omission still binds every archive member; only reviewed changelog prose
        # may be absent, never source, build input, licence or notice material.
        import io
        import tarfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root/'vendor/example'; source.mkdir(parents=True)
            cache = Path(self.enterContext(tempfile.TemporaryDirectory()))
            members = {'src/lib.rs': b'pub fn fixture() {}', 'build.rs': b'fn main() {}',
                       'LICENSE': b'Fixture licence', 'NOTICE': b'Fixture notice',
                       'CHANGELOG.md': b'Upstream history'}
            archive = cache/'example-1.0.0.crate'
            with tarfile.open(archive, 'w:gz') as output:
                for name, data in members.items():
                    entry = tarfile.TarInfo('example-1.0.0/'+name); entry.size=len(data)
                    output.addfile(entry, io.BytesIO(data))
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            hashes = {name:hashlib.sha256(data).hexdigest() for name,data in members.items()}
            row = dict(name='example',version='1.0.0',path='vendor/example',content_manifest='contents.json',omitted_documentation=['CHANGELOG.md'])
            evidence = dict(name='example',version='1.0.0',archive_checksum=checksum,
                            files={name:digest for name,digest in hashes.items() if name!='CHANGELOG.md'},
                            omitted={'CHANGELOG.md':hashes['CHANGELOG.md']})
            for name,data in members.items():
                if name!='CHANGELOG.md':
                    file=source/name; file.parent.mkdir(parents=True,exist_ok=True); file.write_bytes(data)
            manifest=root/'contents.json'
            def check(value):
                manifest.write_text(json.dumps(value))
                wallet_crypto.check_vendor_contents(root,row,{('example','1.0.0'):checksum})
            with patch.dict(os.environ,PN_VENDOR_ARCHIVES=str(cache)):
                self.assertIsNone(check(evidence))
                archive_bytes=archive.read_bytes()
                archive.unlink()
                with self.assertRaisesRegex(ValueError,'archive unavailable'): check(evidence)
                archive.write_bytes(b'wrong archive')
                with self.assertRaisesRegex(ValueError,'archive checksum differs'): check(evidence)
                archive.write_bytes(archive_bytes)
                # A real input reference cannot be hidden as documentation-only.
                with tarfile.open(archive,'w:gz') as output:
                    for name,data in dict(members, **{'build.rs':b'include_str!("CHANGELOG.md");'}).items():
                        entry=tarfile.TarInfo('example-1.0.0/'+name);entry.size=len(data)
                        output.addfile(entry,io.BytesIO(data))
                old_checksum=checksum; checksum=hashlib.sha256(archive.read_bytes()).hexdigest()
                with self.assertRaisesRegex(ValueError,'referenced by a build or test input'):
                    check(dict(evidence,archive_checksum=checksum))
                archive.write_bytes(archive_bytes);checksum=old_checksum
                for name in ('src/lib.rs','build.rs','LICENSE','NOTICE'):
                    changed=dict(evidence,files={key:value for key,value in evidence['files'].items() if key!=name},
                                 omitted=dict(evidence['omitted'],**{name:hashes[name]}))
                    with self.assertRaisesRegex(ValueError,'omitted-member declaration differs'): check(changed)
                    row['omitted_documentation']=['CHANGELOG.md',name]
                    with self.assertRaisesRegex(ValueError,'not reviewed documentation-only'): check(changed)
                    row['omitted_documentation']=['CHANGELOG.md']
                with self.assertRaisesRegex(ValueError,'complete archive members differ'):
                    check(dict(evidence,omitted={'CHANGELOG.md':'b'*64}))
                with self.assertRaisesRegex(ValueError,'omitted-member declaration differs'):
                    check(dict(evidence,omitted={}))
                with self.assertRaisesRegex(ValueError,'omitted-member declaration differs'):
                    check({key:value for key,value in evidence.items() if key!='omitted'})
                changed=dict(evidence,files=dict(evidence['files'],**{'src/lib.rs':'b'*64}))
                with self.assertRaisesRegex(ValueError,'complete archive members differ'): check(changed)
                (source/'src/lib.rs').write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError,'contents differ'): check(evidence)
                # A declared patch must produce the carried bytes from the checked archive.
                original = members['src/lib.rs']
                replacement = b'pub fn owned() {}'
                patch_bytes = (b'diff --git a/src/lib.rs b/src/lib.rs\n'
                               b'--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n'
                               b'-pub fn fixture() {}\n\\ No newline at end of file\n'
                               b'+pub fn owned() {}\n\\ No newline at end of file\n')
                sidecar=root/'vendor/example.patch'; sidecar.write_bytes(patch_bytes)
                row['patch_file']='vendor/example.patch'
                patched_hash=hashlib.sha256(replacement).hexdigest()
                patched=dict(evidence,files=dict(evidence['files'],**{'src/lib.rs':patched_hash}),
                             patch=dict(path=row['patch_file'],sha256=hashlib.sha256(patch_bytes).hexdigest(),
                                        members={'src/lib.rs':dict(upstream=hashes['src/lib.rs'],patched=patched_hash)}))
                (source/'src/lib.rs').write_bytes(replacement)
                self.assertIsNone(check(patched))
                bad=patch_bytes.replace(b'-pub fn fixture() {}',b'-no matching source')
                sidecar.write_bytes(bad)
                with self.assertRaisesRegex(ValueError,'patch does not apply'):
                    check(dict(patched,patch=dict(patched['patch'],sha256=hashlib.sha256(bad).hexdigest())))
                sidecar.write_bytes(patch_bytes)
                excess=dict(patched['patch']['members'], **{'build.rs':dict(upstream=hashes['build.rs'],patched=hashes['build.rs'])})
                with self.assertRaisesRegex(ValueError,'patch member set differs'):
                    check(dict(patched,patch=dict(patched['patch'],members=excess)))
                sidecar.write_bytes(patch_bytes+b'changed')
                with self.assertRaisesRegex(ValueError,'patch digest differs'): check(patched)
                sidecar.write_bytes(patch_bytes)
                wrong_hash=hashlib.sha256(b'other result').hexdigest()
                wrong=dict(patched,files=dict(patched['files'],**{'src/lib.rs':wrong_hash}),
                           patch=dict(patched['patch'],members={'src/lib.rs':dict(upstream=hashes['src/lib.rs'],patched=wrong_hash)}))
                (source/'src/lib.rs').write_bytes(b'other result')
                with self.assertRaisesRegex(ValueError,'patch result differs'): check(wrong)
                with self.assertRaisesRegex(ValueError,'contents differ'): check(patched)
                row.pop('patch_file')
                with self.assertRaisesRegex(ValueError,'contents differ'): check(evidence)
                (source/'src/lib.rs').write_bytes(original)
        with self.assertRaisesRegex(ValueError,'unbound'):
            wallet_crypto.check_checksums(dict(package=[dict(name='secp256k1',version='0.29.1')]),[],{('secp256k1','0.29.1')})
        with self.assertRaisesRegex(ValueError,'unbound'):
            wallet_crypto.check_checksums(dict(package=[dict(name='elements',version='0.27.0')]),[],{('elements','0.27.0')})
        with self.assertRaisesRegex(ValueError,'unbound'):
            wallet_crypto.check_checksums(dict(package=[dict(name='bitcoin',version='0.32.102')]),[],{('bitcoin','0.32.102')})
        for source in ['registry+https://example.invalid/index#secp256k1-sys@0.10.1',
                       'path+file:///fixture/vendor/secp256k1-sys#0.10.1']:
            self.assertEqual(wallet_crypto.artifact_package(dict(package_id=source)),('secp256k1-sys','0.10.1'))
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
        from functools import lru_cache
        from unittest.mock import patch
        import wallet_boundary
        # Only a pure lexical transform is reused, keyed by all source bytes.
        # Every changed probe is masked afresh; Cargo identity is never cached.
        self.enterContext(patch('wallet_boundary.rust_mask', lru_cache(maxsize=256)(wallet_boundary.rust_mask)))
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
