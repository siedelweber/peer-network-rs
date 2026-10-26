//! SCRAM-SHA-256 without channel binding on an explicitly host-secured link.
use crate::{
    Configuration, Refusal,
    secret::Buffer,
    wire::{self, Socket},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use sha2::{Digest, Sha256};

const DERIVATION_LIMIT: usize = 2;
static DERIVATIONS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(DERIVATION_LIMIT);

pub(crate) const ITERATIONS: std::ops::RangeInclusive<u32> = 4096..=600_000;

fn encode(bytes: &[u8]) -> Result<Buffer, Refusal> {
    let mut result = Buffer::new();
    let length = STANDARD
        .encode_slice(bytes, result.storage())
        .map_err(|_| Refusal::RepresentationLimit)?;
    result.set_length(length)?;
    Ok(result)
}
fn decode(bytes: &[u8]) -> Result<Buffer, Refusal> {
    let mut result = Buffer::new();
    let length = STANDARD
        .decode_slice(bytes, result.storage())
        .map_err(|_| Refusal::ScramFormat)?;
    result.set_length(length)?;
    Ok(result)
}
fn attribute(message: &[u8], key: u8) -> Result<&[u8], Refusal> {
    let mut found = None;
    for item in message.split(|v| *v == b',') {
        if item.len() < 3 || item[1] != b'=' || item[0] == b'm' {
            return Err(Refusal::ScramFormat);
        }
        if item[0] == key && found.replace(&item[2..]).is_some() {
            return Err(Refusal::ScramFormat);
        }
    }
    found.ok_or(Refusal::ScramFormat)
}
// Caveat: The MAC writes its derived key directly into protected output; the digest API requires a mutable byte array.
// (´[ROOT-cav:observe:secret-host-scram-mac-1]´)
// Justified: The MAC writes its derived key directly into protected output; the digest API requires a mutable byte array.
#[allow(clippy::disallowed_methods)]
fn mac(key: &[u8], bytes: &[u8]) -> Result<SecretBox<[u8; 32]>, Refusal> {
    let mut state = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Refusal::ScramFormat)?;
    state.update(bytes);
    let mut output = SecretBox::new(Box::new([0; 32]));
    sha2::digest::FixedOutput::finalize_into(
        state,
        output
            .expose_secret_mut(/* (´[ROOT-cav:observe:secret-host-scram-mac-1]´) */)
            .as_mut_slice()
            .try_into()
            .map_err(|_| Refusal::ScramFormat)?,
    );
    Ok(output)
}
fn authentication(frame: &wire::Frame, expected: u32) -> Result<&[u8], Refusal> {
    if frame.kind != b'R' {
        return Err(if frame.kind == b'E' {
            Refusal::ServerAuthentication
        } else {
            Refusal::Protocol
        });
    }
    let (code, rest) = frame.payload.bytes().split_at_checked(4).ok_or(Refusal::Protocol)?;
    let actual = u32::from_be_bytes(code.try_into().map_err(|_| Refusal::Protocol)?);
    if actual != expected {
        return Err(Refusal::authentication(actual));
    }
    Ok(rest)
}
// Caveat: PBKDF2 writes the derived password key directly into protected output; its API requires a mutable byte array.
// (´[ROOT-cav:observe:secret-host-scram-derive-1]´)
// Justified: PBKDF2 writes the derived password key directly into protected output; its API requires a mutable byte array.
#[allow(clippy::disallowed_methods)]
async fn derive(password: Buffer, salt: Buffer, iterations: u32) -> Result<SecretBox<[u8; 32]>, Refusal> {
    let permit = DERIVATIONS.acquire().await.map_err(|_| Refusal::ScramFormat)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        #[cfg(test)]
        if password.bytes() == b"public-permit-password" {
            let hook = PERMIT_HOOK.lock().unwrap().pop().unwrap();
            let _ = hook.0.send(());
            hook.1
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| Refusal::ScramFormat)?;
        }
        #[cfg(test)]
        if password.bytes() == b"public-progress-password" {
            let hook = PROGRESS_HOOK.lock().unwrap().take();
            if let Some((started, progress)) = hook {
                let _ = started.send(());
                progress
                    .recv_timeout(std::time::Duration::from_secs(3))
                    .map_err(|_| Refusal::ScramFormat)?;
            }
        }
        let mut salted = SecretBox::new(Box::new([0; 32]));
        pbkdf2::pbkdf2::<Hmac<Sha256>>(
            password.bytes(),
            salt.bytes(),
            iterations,
            salted.expose_secret_mut(/* (´[ROOT-cav:observe:secret-host-scram-derive-1]´) */),
        )
        .map_err(|_| Refusal::ScramFormat)?;
        Ok(salted)
    })
    .await
    .map_err(|_| Refusal::ScramFormat)?
}
// Caveat: The nonce acquisition lends its protected array to the entropy API only until that call returns; the API cannot accept the carrier.
// (´[ROOT-cav:observe:secret-host-scram-login-1]´)
// Caveat: The nonce is borrowed by base64 encoding into a protected buffer for that call; the encoder requires a byte slice.
// (´[ROOT-cav:observe:secret-host-scram-login-2]´)
// Caveat: The salted password is borrowed by the Client Key MAC; the MAC API requires bytes and its ordinary keyed state lasts until finalization.
// (´[ROOT-cav:observe:secret-host-scram-login-3]´)
// Caveat: The client key enters ordinary SHA-256 state until finalization into protected output; the digest API cannot consume the carrier.
// (´[ROOT-cav:observe:secret-host-scram-login-4]´)
// Caveat: The stored-key output lends its protected array to digest finalization for that call; the digest API requires mutable bytes.
// (´[ROOT-cav:observe:secret-host-scram-login-5]´)
// Caveat: The salted password is borrowed by the Server Key MAC until finalization; its keyed state cannot be represented by the carrier API.
// (´[ROOT-cav:observe:secret-host-scram-login-6]´)
// Caveat: The stored key is borrowed by the transcript MAC until finalization into protected output; the MAC API requires key bytes.
// (´[ROOT-cav:observe:secret-host-scram-login-7]´)
// Caveat: The proof lends mutable protected bytes to the XOR loop until the loop ends; iteration cannot operate on the carrier directly.
// (´[ROOT-cav:observe:secret-host-scram-login-8]´)
// Caveat: The client key lends bytes to the proof XOR loop, including ordinary copied byte operands until each iteration ends; the arithmetic requires ordinary bytes.
// (´[ROOT-cav:observe:secret-host-scram-login-9]´)
// Caveat: The signature lends bytes to the proof XOR loop, including ordinary copied byte operands until each iteration ends; the arithmetic requires ordinary bytes.
// (´[ROOT-cav:observe:secret-host-scram-login-10]´)
// Caveat: The proof is borrowed for base64 encoding into a protected buffer until encoding returns; the encoder requires a byte slice.
// (´[ROOT-cav:observe:secret-host-scram-login-11]´)
// Caveat: The server key enters the verifier's ordinary MAC state until server-signature verification returns; the MAC API cannot accept or retain the carrier.
// (´[ROOT-cav:observe:secret-host-scram-login-12]´)
// Justified: Nonce and derived authentication material are borrowed by entropy, digest, MAC and encoding operations and the proof loop; these consumers require byte slices and outputs remain secret-owned.
#[allow(clippy::disallowed_methods)]
pub(crate) async fn login(socket: &mut Socket, config: &Configuration) -> Result<(), Refusal> {
    wire::startup(socket, config).await?;
    let mechanisms = wire::read(socket).await?;
    let offered = authentication(&mechanisms, 10)?;
    if !offered.ends_with(&[0, 0]) || !offered.split(|v| *v == 0).any(|v| v == b"SCRAM-SHA-256") {
        return Err(Refusal::UnsupportedAuthentication);
    }
    let mut random = SecretBox::new(Box::new([0; 32]));
    getrandom::fill(random.expose_secret_mut(/* (´[ROOT-cav:observe:secret-host-scram-login-1]´) */))
        .map_err(|_| Refusal::Entropy)?;
    let nonce = encode(random.expose_secret(/* (´[ROOT-cav:observe:secret-host-scram-login-2]´) */))?;
    let mut bare = Buffer::from_bytes(b"n=,r=")?;
    bare.append(nonce.bytes())?;
    let mut initial = Buffer::from_bytes(b"SCRAM-SHA-256\0")?;
    initial.append(
        &u32::try_from(bare.bytes().len() + 3)
            .map_err(|_| Refusal::RepresentationLimit)?
            .to_be_bytes(),
    )?;
    initial.append(b"n,,")?;
    initial.append(bare.bytes())?;
    wire::send(socket, b'p', initial.bytes()).await?;
    let continuation = wire::read(socket).await?;
    let server_first = authentication(&continuation, 11)?;
    let server_nonce = attribute(server_first, b'r')?;
    if !server_nonce.starts_with(nonce.bytes()) || server_nonce.len() <= nonce.bytes().len() {
        return Err(Refusal::ServerNonce);
    }
    let salt = decode(attribute(server_first, b's')?)?;
    let iterations = std::str::from_utf8(attribute(server_first, b'i')?)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| ITERATIONS.contains(v))
        .ok_or(Refusal::ScramIterations)?;
    let salted = derive(Buffer::from_bytes(config.field(4))?, salt, iterations).await?;
    let client_key = mac(
        salted.expose_secret(/* (´[ROOT-cav:observe:secret-host-scram-login-3]´) */),
        b"Client Key",
    )?;
    let mut stored = SecretBox::new(Box::new([0; 32]));
    Digest::finalize_into(
        Sha256::new_with_prefix(client_key.expose_secret(/* (´[ROOT-cav:observe:secret-host-scram-login-4]´) */)),
        stored
            .expose_secret_mut(/* (´[ROOT-cav:observe:secret-host-scram-login-5]´) */)
            .as_mut_slice()
            .try_into()
            .map_err(|_| Refusal::ScramFormat)?,
    );
    let server_key = mac(
        salted.expose_secret(/* (´[ROOT-cav:observe:secret-host-scram-login-6]´) */),
        b"Server Key",
    )?;
    let mut final_without_proof = Buffer::from_bytes(b"c=biws,r=")?;
    final_without_proof.append(server_nonce)?;
    let mut transcript = Buffer::new();
    transcript.append(bare.bytes())?;
    transcript.append(b",")?;
    transcript.append(server_first)?;
    transcript.append(b",")?;
    transcript.append(final_without_proof.bytes())?;
    let signature = mac(
        stored.expose_secret(/* (´[ROOT-cav:observe:secret-host-scram-login-7]´) */),
        transcript.bytes(),
    )?;
    let mut proof = SecretBox::new(Box::new([0; 32]));
    for ((output, key), sig) in proof
        .expose_secret_mut(/* (´[ROOT-cav:observe:secret-host-scram-login-8]´) */)
        .iter_mut()
        .zip(client_key.expose_secret(/* (´[ROOT-cav:observe:secret-host-scram-login-9]´) */))
        .zip(signature.expose_secret(/* (´[ROOT-cav:observe:secret-host-scram-login-10]´) */))
    {
        *output = key ^ sig;
    }
    let encoded_proof = encode(proof.expose_secret(/* (´[ROOT-cav:observe:secret-host-scram-login-11]´) */))?;
    let mut final_message = final_without_proof;
    final_message.append(b",p=")?;
    final_message.append(encoded_proof.bytes())?;
    wire::send(socket, b'p', final_message.bytes()).await?;
    let server_final = wire::read(socket).await?;
    let signature = decode(attribute(authentication(&server_final, 12)?, b'v')?)?;
    let mut verifier =
        Hmac::<Sha256>::new_from_slice(server_key.expose_secret(/* (´[ROOT-cav:observe:secret-host-scram-login-12]´) */))
            .map_err(|_| Refusal::ScramFormat)?;
    verifier.update(transcript.bytes());
    verifier
        .verify_slice(signature.bytes())
        .map_err(|_| Refusal::ServerSignature)?;
    let success = wire::read(socket).await?;
    if !authentication(&success, 0)?.is_empty() {
        return Err(Refusal::Protocol);
    }
    Ok(())
}

#[cfg(test)]
static PROGRESS_HOOK: std::sync::Mutex<Option<(tokio::sync::oneshot::Sender<()>, std::sync::mpsc::Receiver<()>)>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
static PERMIT_HOOK: std::sync::Mutex<Vec<(tokio::sync::oneshot::Sender<()>, std::sync::mpsc::Receiver<()>)>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
mod tests {
    /// Claim: Two blocking derivations hold the process permits even after their logins are cancelled; an excess login remains outside the blocking pool until a job finishes, and all permits return after completion.
    /// ´claim:host:cancelled-logins-retain-derivation-permits´
    /// ´test:unit:derivation-permits´
    #[test]
    fn derivation_permits() {
        use super::*;
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let mut releases = Vec::new();
            let mut jobs = Vec::new();
            for _ in 0..2 {
                let (started, ready) = tokio::sync::oneshot::channel();
                let (release, receive) = std::sync::mpsc::channel();
                PERMIT_HOOK.lock().unwrap().push((started, receive));
                jobs.push(tokio::spawn(derive(Buffer::from_bytes(b"public-permit-password").unwrap(), Buffer::from_bytes(b"salt").unwrap(), 4096)));
                tokio::time::timeout(std::time::Duration::from_secs(5), ready).await.unwrap().unwrap();
                releases.push(release);
            }
            assert_eq!(DERIVATIONS.available_permits(), 0);
            let (started, mut ready) = tokio::sync::oneshot::channel();
            let (release_excess, receive) = std::sync::mpsc::channel();
            PERMIT_HOOK.lock().unwrap().push((started, receive));
            let mut excess = tokio::spawn(derive(Buffer::from_bytes(b"public-permit-password").unwrap(), Buffer::from_bytes(b"salt").unwrap(), 4096));
            assert!(tokio::time::timeout(std::time::Duration::from_millis(30), &mut ready).await.is_err());
            assert!(tokio::time::timeout(std::time::Duration::from_millis(30), &mut excess).await.is_err());
            for job in jobs { job.abort(); assert!(job.await.unwrap_err().is_cancelled()); }
            assert_eq!(DERIVATIONS.available_permits(), 0);
            assert!(tokio::time::timeout(std::time::Duration::from_millis(30), &mut excess).await.is_err());
            for release in releases { release.send(()).unwrap(); }
            tokio::time::timeout(std::time::Duration::from_secs(5), ready).await.unwrap().unwrap();
            release_excess.send(()).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), excess).await.unwrap().unwrap().unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while DERIVATIONS.available_permits() != 2 { tokio::task::yield_now().await; }
            }).await.unwrap();
            cli_common::emit(&serde_json::json!({"kind":"derivation_permits","limit":2,"cancelled_jobs_retain_permits":true,"excess_waits":true})).unwrap();
        });
    }

    /// Claim: A current-thread executor forwards a public relay frame while a ceiling login is inside its blocking derivation job; a bounded rendezvous fails if that job is moved back onto the executor.
    /// ´claim:host:ceiling-login-leaves-relay-progress-independent´
    /// ´test:unit:ceiling-login-progress´
    #[test]
    fn ceiling_login_progress() {
        use super::*;
        use tokio::io::AsyncReadExt;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let config = Configuration::acquire(Some("host-secured"), &mut br#"{"transport":"unix","endpoint":"public-fixture","port":"1","user":"public-user","password":"public-progress-password","database":"public-database"}"#.as_slice()).unwrap();
            let (mut socket, mut server) = wire::fixture_pair();
            let (started, ready) = tokio::sync::oneshot::channel();
            let (progress, receive) = std::sync::mpsc::channel();
            *PROGRESS_HOOK.lock().unwrap() = Some((started, receive));
            let login = tokio::spawn(async move { super::login(&mut socket, &config).await });
            let peer = tokio::spawn(async move {
                let size = server.read_u32().await.unwrap();
                let mut startup = vec![0; usize::try_from(size).unwrap()-4];
                server.read_exact(&mut startup).await.unwrap();
                wire::send(&mut server, b'R', b"\0\0\0\x0aSCRAM-SHA-256\0\0").await.unwrap();
                let initial = wire::read(&mut server).await.unwrap();
                let offset = initial.payload.bytes().windows(2).position(|v| v == b"r=").unwrap()+2;
                let mut first = Buffer::from_bytes(b"\0\0\0\x0br=").unwrap();
                first.append(&initial.payload.bytes()[offset..]).unwrap();
                first.append(b"-server,s=c2FsdA==,i=600000").unwrap();
                wire::send(&mut server, b'R', first.bytes()).await.unwrap();
                let proof = wire::read(&mut server).await.unwrap();
                assert_eq!(proof.kind,b'p');
                wire::send(&mut server,b'E',b"public fixture ends after proof").await.unwrap();
            });
            ready.await.unwrap();
            let (mut sending, mut receiving) = tokio::io::duplex(64);
            let relay = tokio::spawn(async move { wire::send(&mut sending,b'D',b"public-progress").await.unwrap(); });
            assert_eq!(wire::read(&mut receiving).await.unwrap().payload.bytes(),b"public-progress");
            progress.send(()).unwrap();
            relay.await.unwrap();
            assert_eq!(login.await.unwrap(),Err(Refusal::ServerAuthentication));
            peer.await.unwrap();
        });
    }

    /// Claim: The SCRAM derivation at 600,000 rounds matches an independently computed Python hashlib known answer; the cost campaign derives the same public fixture key twice at each declared work factor, with timing reported without changing authentication or a test verdict.
    /// ´claim:host:scram-work-factor-cost-is-nonbinding´
    /// ´test:unit:derivation-cost´
    #[test]
    // Fixture-only secret boundary: No deployment secret is accepted by this test fixture route.
    // Caveat: The known-answer assertion borrows the derived public fixture key until comparison returns; equality requires its ordinary byte array.
    // (´[ROOT-cav:observe:secret-host-scram-derivation-cost-1]´)
    // Caveat: The first public-fixture PBKDF2 run writes directly into protected output until derivation returns; the API requires mutable bytes.
    // (´[ROOT-cav:observe:secret-host-scram-derivation-cost-2]´)
    // Caveat: The second public-fixture PBKDF2 run writes directly into protected output until derivation returns; the API requires mutable bytes.
    // (´[ROOT-cav:observe:secret-host-scram-derivation-cost-3]´)
    // Caveat: The repeated-run assertion borrows the first public fixture key until comparison returns; equality requires ordinary byte arrays.
    // (´[ROOT-cav:observe:secret-host-scram-derivation-cost-4]´)
    // Caveat: The repeated-run assertion borrows the second public fixture key until comparison returns; equality requires ordinary byte arrays.
    // (´[ROOT-cav:observe:secret-host-scram-derivation-cost-5]´)
    // Justified: Only this test boundary's fixture secrets are borrowed for acquisition, comparison or fixture computation; these APIs require ordinary references to establish the carrier contract.
    #[allow(clippy::disallowed_methods)]
    fn derivation_cost() {
        use secrecy::{ExposeSecret as _, ExposeSecretMut as _, SecretBox};
        // Independently computed with Python 3 hashlib (OpenSSL), not the Rust PBKDF2:
        // list(hashlib.pbkdf2_hmac("sha256", b"public-fixture-password",
        //                         b"public-fixture-salt", 600000, 32))
        let expected = [
            49, 138, 104, 75, 137, 204, 90, 99, 159, 151, 219, 158, 182, 75, 167, 227, 2, 57, 205, 198, 229, 149, 66, 33, 229,
            101, 90, 249, 131, 231, 124, 187,
        ];
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let actual = super::derive(
                    crate::secret::Buffer::from_bytes(b"public-fixture-password").unwrap(),
                    crate::secret::Buffer::from_bytes(b"public-fixture-salt").unwrap(),
                    600_000,
                )
                .await
                .unwrap();
                assert_eq!(
                    actual.expose_secret(/* (´[ROOT-cav:observe:secret-host-scram-derivation-cost-1]´) */),
                    &expected
                );
            });
        for iterations in [4096, 100_000, 600_000] {
            let mut first = SecretBox::new(Box::new([0_u8; 32]));
            let mut second = SecretBox::new(Box::new([0_u8; 32]));
            let started = std::time::Instant::now();
            pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
                b"public-fixture-password",
                b"public-fixture-salt",
                iterations,
                first.expose_secret_mut(/* (´[ROOT-cav:observe:secret-host-scram-derivation-cost-2]´) */),
            )
            .unwrap();
            let elapsed = started.elapsed().as_secs_f64();
            pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
                b"public-fixture-password",
                b"public-fixture-salt",
                iterations,
                second.expose_secret_mut(/* (´[ROOT-cav:observe:secret-host-scram-derivation-cost-3]´) */),
            )
            .unwrap();
            assert_eq!(
                first.expose_secret(/* (´[ROOT-cav:observe:secret-host-scram-derivation-cost-4]´) */),
                second.expose_secret(/* (´[ROOT-cav:observe:secret-host-scram-derivation-cost-5]´) */)
            );
            cli_common::emit(&serde_json::json!({"kind":"scram_cost", "iterations":iterations, "wall_seconds":elapsed})).unwrap();
        }
    }
}
