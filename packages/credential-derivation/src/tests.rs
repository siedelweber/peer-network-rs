use super::{Error, Input, Output, mac, salted_password, stored_key, verifier};

struct Vector {
    password: &'static [u8],
    iterations: u32,
    salt: [u8; 16],
    salted: [u8; 32],
    client: [u8; 32],
    stored: [u8; 32],
    server: [u8; 32],
    verifier: &'static [u8],
}

mod vectors;

/// Claim: Three public inputs match independently reconstructed salted passwords and distinct client/server/stored keys; both admitted verifier inputs match every framed output byte.
/// ´claim:crypto:derivation-matches-independent-vectors´
/// ´test:unit:independent-vectors´
#[test]
fn independent_vectors() {
    for v in vectors::VECTORS {
        let mut salted = [0; 32];
        assert_eq!(
            salted_password(Input(v.password), Input(&v.salt), v.iterations, Output(&mut salted)),
            Ok(())
        );
        assert_eq!(salted, v.salted, "salted password includes the declared work factor");
        let mut client = [0; 32];
        let mut server = [0; 32];
        let mut stored = [0; 32];
        assert_eq!(mac(Input(&salted), Input(b"Client Key"), Output(&mut client)), Ok(()));
        assert_eq!(client, v.client, "client key has its own protocol role");
        assert_eq!(mac(Input(&salted), Input(b"Server Key"), Output(&mut server)), Ok(()));
        assert_eq!(server, v.server, "server key has its own protocol role");
        assert_eq!(stored_key(Input(&client), Output(&mut stored)), Ok(()));
        assert_eq!(stored, v.stored, "stored key hashes the client key");
        if v.iterations == 600_000 {
            let mut text = [0; 135];
            assert_eq!(
                verifier(Input(&v.salt), Input(&stored), Input(&server), Output(&mut text)),
                Ok(())
            );
            assert_eq!(text.as_slice(), v.verifier, "verifier preserves every field and framing byte");
        }
    }
}

/// Claim: The finite length and work-factor controls refuse before modifying the caller's destination, and borrowed private representations remain constant.
/// ´claim:crypto:derivation-refuses-without-output-or-private-diagnostics´
/// ´test:unit:bounds-and-representations´
#[test]
fn bounds_and_representations() {
    let mut output = [17; 135];
    for iterations in [600_001, 0, 4095] {
        assert_eq!(
            salted_password(Input(b"fixture"), Input(b"salt"), iterations, Output(&mut output[..32])),
            Err(Error::Bound)
        );
        assert_eq!(output, [17; 135], "work refusal does not write output");
    }
    assert_eq!(stored_key(Input(&[0; 31]), Output(&mut output[..32])), Err(Error::Bound));
    assert_eq!(
        verifier(Input(&[0; 15]), Input(&[0; 32]), Input(&[0; 32]), Output(&mut output)),
        Err(Error::Bound)
    );
    assert_eq!(output, [17; 135], "length refusal does not write output");
    let oversized = vec![0; 1_048_577];
    for (password, salt) in [
        (oversized.as_slice(), b"salt".as_slice()),
        (b"fixture".as_slice(), oversized.as_slice()),
    ] {
        assert_eq!(
            salted_password(Input(password), Input(salt), 4096, Output(&mut output[..32])),
            Err(Error::Bound)
        );
    }
    for (key, message) in [
        (oversized.as_slice(), b"message".as_slice()),
        (b"key".as_slice(), oversized.as_slice()),
    ] {
        assert_eq!(mac(Input(key), Input(message), Output(&mut output[..32])), Err(Error::Bound));
    }
    assert_eq!(
        salted_password(Input(b"fixture"), Input(b"salt"), 4096, Output(&mut output[..31])),
        Err(Error::Bound)
    );
    assert_eq!(
        mac(Input(b"key"), Input(b"message"), Output(&mut output[..31])),
        Err(Error::Bound)
    );
    assert_eq!(stored_key(Input(&[0; 32]), Output(&mut output[..31])), Err(Error::Bound));
    assert_eq!(
        verifier(Input(&[0; 16]), Input(&[0; 31]), Input(&[0; 32]), Output(&mut output)),
        Err(Error::Bound)
    );
    assert_eq!(
        verifier(Input(&[0; 16]), Input(&[0; 32]), Input(&[0; 31]), Output(&mut output)),
        Err(Error::Bound)
    );
    assert_eq!(
        verifier(Input(&[0; 16]), Input(&[0; 32]), Input(&[0; 32]), Output(&mut output[..134])),
        Err(Error::Bound)
    );
    assert_eq!(output, [17; 135], "each isolated bound leaves the destination unchanged");
    assert_eq!(format!("{:?}", Input(b"private-fixture")), "CredentialInput([REDACTED])");
    assert_eq!(format!("{:?}", Output(&mut output)), "CredentialOutput([REDACTED])");
    assert_eq!(format!("{:?}", Error::Bound), "Bound");
}
