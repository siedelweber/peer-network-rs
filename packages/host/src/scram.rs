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
    // The primitive's return buffer is the bounded residue admitted in ADR 015.
    output.expose_secret_mut().copy_from_slice(&state.finalize().into_bytes());
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
        .filter(|v| (1..=100_000).contains(v))
        .ok_or(Refusal::ScramIterations)?;
    let mut salted = SecretBox::new(Box::new([0; 32]));
    pbkdf2::pbkdf2::<Hmac<Sha256>>(config.field(4), salt.bytes(), iterations, salted.expose_secret_mut())
        .map_err(|_| Refusal::ScramFormat)?;
    let client_key = mac(salted.expose_secret(), b"Client Key")?;
    let mut stored = SecretBox::new(Box::new([0; 32]));
    stored
        .expose_secret_mut()
        .copy_from_slice(&Sha256::digest(client_key.expose_secret()));
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
