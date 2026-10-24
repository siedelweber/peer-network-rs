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
fn mac(key: &[u8], bytes: &[u8]) -> Result<SecretBox<[u8; 32]>, Refusal> {
    let mut state = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Refusal::ScramFormat)?;
    state.update(bytes);
    let mut output = SecretBox::new(Box::new([0; 32]));
    sha2::digest::FixedOutput::finalize_into(
        state,
        output
            .expose_secret_mut()
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
async fn derive(password: Buffer, salt: Buffer, iterations: u32) -> Result<SecretBox<[u8; 32]>, Refusal> {
    tokio::task::spawn_blocking(move || {
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
        pbkdf2::pbkdf2::<Hmac<Sha256>>(password.bytes(), salt.bytes(), iterations, salted.expose_secret_mut())
            .map_err(|_| Refusal::ScramFormat)?;
        Ok(salted)
    })
    .await
    .map_err(|_| Refusal::ScramFormat)?
}
pub(crate) async fn login(socket: &mut Socket, config: &Configuration) -> Result<(), Refusal> {
    wire::startup(socket, config).await?;
    let mechanisms = wire::read(socket).await?;
    let offered = authentication(&mechanisms, 10)?;
    if !offered.ends_with(&[0, 0]) || !offered.split(|v| *v == 0).any(|v| v == b"SCRAM-SHA-256") {
        return Err(Refusal::UnsupportedAuthentication);
    }
    let mut random = SecretBox::new(Box::new([0; 32]));
    getrandom::fill(random.expose_secret_mut()).map_err(|_| Refusal::Entropy)?;
    let nonce = encode(random.expose_secret())?;
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
    let client_key = mac(salted.expose_secret(), b"Client Key")?;
    let mut stored = SecretBox::new(Box::new([0; 32]));
    Digest::finalize_into(
        Sha256::new_with_prefix(client_key.expose_secret()),
        stored
            .expose_secret_mut()
            .as_mut_slice()
            .try_into()
            .map_err(|_| Refusal::ScramFormat)?,
    );
    let server_key = mac(salted.expose_secret(), b"Server Key")?;
    let mut final_without_proof = Buffer::from_bytes(b"c=biws,r=")?;
    final_without_proof.append(server_nonce)?;
    let mut transcript = Buffer::new();
    transcript.append(bare.bytes())?;
    transcript.append(b",")?;
    transcript.append(server_first)?;
    transcript.append(b",")?;
    transcript.append(final_without_proof.bytes())?;
    let signature = mac(stored.expose_secret(), transcript.bytes())?;
    let mut proof = SecretBox::new(Box::new([0; 32]));
    for ((output, key), sig) in proof
        .expose_secret_mut()
        .iter_mut()
        .zip(client_key.expose_secret())
        .zip(signature.expose_secret())
    {
        *output = key ^ sig;
    }
    let encoded_proof = encode(proof.expose_secret())?;
    let mut final_message = final_without_proof;
    final_message.append(b",p=")?;
    final_message.append(encoded_proof.bytes())?;
    wire::send(socket, b'p', final_message.bytes()).await?;
    let server_final = wire::read(socket).await?;
    let signature = decode(attribute(authentication(&server_final, 12)?, b'v')?)?;
    let mut verifier = Hmac::<Sha256>::new_from_slice(server_key.expose_secret()).map_err(|_| Refusal::ScramFormat)?;
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
mod tests {
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

    /// Claim: The SCRAM cost campaign derives the same public fixture key twice at each declared work factor; timing is reported without changing authentication or a test verdict.
    /// ´claim:host:scram-work-factor-cost-is-nonbinding´
    /// ´test:unit:derivation-cost´
    #[test]
    fn derivation_cost() {
        use secrecy::{ExposeSecret as _, ExposeSecretMut as _, SecretBox};
        for iterations in [4096, 100_000, 600_000] {
            let mut first = SecretBox::new(Box::new([0_u8; 32]));
            let mut second = SecretBox::new(Box::new([0_u8; 32]));
            let started = std::time::Instant::now();
            pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
                b"public-fixture-password",
                b"public-fixture-salt",
                iterations,
                first.expose_secret_mut(),
            )
            .unwrap();
            let elapsed = started.elapsed().as_secs_f64();
            pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
                b"public-fixture-password",
                b"public-fixture-salt",
                iterations,
                second.expose_secret_mut(),
            )
            .unwrap();
            assert_eq!(first.expose_secret(), second.expose_secret());
            cli_common::emit(&serde_json::json!({"kind":"scram_cost", "iterations":iterations, "wall_seconds":elapsed})).unwrap();
        }
    }
}
