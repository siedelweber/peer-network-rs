// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transaction Decoders
//!
//! These are encapsulated because there are many of them, but in the end we
//! only expose the top-level ones outside of this module.

use core::fmt;

use super::{
    AssetIssuance, OutPoint, Script, Sequence, Transaction, TxIn, TxInWitness, TxOut, TxOutWitness,
    Txid,
};
use crate::confidential::{RangeProofDecoder, RangeProofDecoderError};
use crate::encoding::{
    ArrayDecoder, Decode, Decoder, Decoder2, Decoder2Error, Decoder3, Decoder4, Decoder4Error,
    DecoderStatus, UnexpectedEofError, VecDecoder,
};
use crate::locktime::{LockTime, LockTimeDecoder};
use crate::{PeginWitnessDecoder, PeginWitnessDecoderError, WitnessDecoder, WitnessDecoderError};

/// Decoder for the [`OutPoint`] type.
///
/// This is a non-public struct and we do not implement [`Decode`] for [`OutPoint`]
/// because we can't actually encode/decode outpoints independently of the rest of
/// a [`TxIn`]. This is because we mask bits into the vout of the outpoint.
#[derive(Default)]
struct OutPointDecoder {
    inner: Decoder2<ArrayDecoder<32>, ArrayDecoder<4>>,
}

/// Decoder error for the [`OutPoint`] type.
#[derive(Clone, PartialEq, Eq, Debug)]
struct OutPointDecoderError(Decoder2Error<UnexpectedEofError, UnexpectedEofError>);

impl fmt::Display for OutPointDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("error decoding outpoint")
    }
}

impl std::error::Error for OutPointDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl Decoder for OutPointDecoder {
    type Output = OutPoint;
    type Error = OutPointDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(OutPointDecoderError)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let (txid, vout) = self.inner.end().map_err(OutPointDecoderError)?;
        Ok(OutPoint { txid: Txid::from_byte_array(txid), vout: u32::from_le_bytes(vout) })
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

decoder_newtype! {
    /// Decoder for the [`Sequence`] type.
    #[derive(Default)]
    pub struct SequenceDecoder(ArrayDecoder<4>);

    /// Decoder error for the [`Sequence`] type.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct SequenceDecoderError(UnexpectedEofError);
    const ERROR_DISPLAY = "error decoding sequence";

    impl Decode for Sequence {
        fn convert_inner(bytes) -> Result<_, UnexpectedEofError> {
            Ok(Sequence::from_consensus(u32::from_le_bytes(bytes)))
        }
    }
}

decoder_newtype! {
    /// Decoder for the [`AssetIssuance`] type.
    #[derive(Default)]
    pub struct AssetIssuanceDecoder(Decoder4<
        crate::AssetBlindingNonceDecoder,
        crate::AssetEntropyDecoder,
        crate::confidential::ValueDecoder,
        crate::confidential::ValueDecoder,
    >);
    /// Decoder error for the [`AssetIssuance`] type.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct AssetIssuanceDecoderError(Decoder4Error<
        crate::AssetBlindingNonceDecoderError,
        crate::AssetEntropyDecoderError,
        crate::confidential::ValueDecoderError,
        crate::confidential::ValueDecoderError,
    >);
    const ERROR_DISPLAY = "error decoding asset issuance";

    impl Decode for AssetIssuance {
        fn convert_inner(output) -> Result<_, AssetIssuanceDecoderError> {
            let (asset_blinding_nonce, asset_entropy, amount, inflation_keys) = output;
            Ok(AssetIssuance {
                asset_blinding_nonce,
                asset_entropy,
                amount,
                inflation_keys,
            })
        }
    }
}

decoder_state_machine! {
    /// Decoder for the [`TxIn`] type.
    pub struct TxInDecoder(enum TxInDecoderInner {
        Done(TxIn),
        Errored,
        Initial {
            decoder: Decoder3<
                OutPointDecoder,
                crate::script::ScriptDecoder,
                SequenceDecoder,
            >,
            => transition_initial(output, ...) -> Result {
                let (mut outpoint, script_sig, sequence) = output;
                let (is_pegin, has_issuance) = if outpoint.vout == 0xffff_ffff {
                    (false, false)
                } else {
                    let vout = outpoint.vout;
                    outpoint.vout &= !((1 << 30) | (1 << 31));
                    (vout & (1 << 30) != 0, vout & (1 << 31) != 0)
                };
                if has_issuance {
                    Ok(TxInDecoderInner::AssetIssuance {
                        decoder: AssetIssuanceDecoder::default(),
                        outpoint, script_sig, sequence, is_pegin,
                    })
                } else {
                    if outpoint.vout != 0xffff_ffff {
                        outpoint.vout &= !((1 << 30) | (1 << 31));
                    }
                    Ok(TxInDecoderInner::Done(TxIn {
                        previous_output: outpoint,
                        is_pegin,
                        script_sig,
                        sequence,
                        asset_issuance: AssetIssuance::null(),
                        witness: TxInWitness::default(),
                    }))
                }
            }
        },
        AssetIssuance {
            decoder: AssetIssuanceDecoder,
            outpoint: OutPoint,
            script_sig: Script,
            sequence: Sequence,
            is_pegin: bool
            => transition_asset_issuance(asset_issuance, ...) -> Result {
                if asset_issuance.is_null() {
                    return Err(TxInDecoderErrorInner::SuperfluousIssuance);
                }

                Ok(TxInDecoderInner::Done(TxIn {
                    previous_output: outpoint,
                    is_pegin,
                    script_sig,
                    sequence,
                    asset_issuance,
                    witness: TxInWitness::default(),
                }))
            }
        },
    });

    /// Decoder error for the [`TxIn`] type.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TxInDecoderError(enum TxInDecoderErrorInner {
        [macro-inserted decoder variants]
        SuperfluousIssuance,
    });
}

impl Default for TxInDecoder {
    fn default() -> Self { Self(TxInDecoderInner::Initial { decoder: Decoder3::default() }) }
}

impl fmt::Display for TxInDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TxInDecoderErrorInner as Inner;
        match self.0 {
            Inner::Initial(..) => f.write_str("error decoding outpoint, scriptsig or sequence"),
            Inner::AssetIssuance(..) => f.write_str("error decoding asset issuance"),
            Inner::SuperfluousIssuance =>
                f.write_str("input had issuance flag set, but null issuance"),
        }
    }
}

impl std::error::Error for TxInDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use TxInDecoderErrorInner as Inner;
        match self.0 {
            Inner::Initial(ref e) => Some(e),
            Inner::AssetIssuance(ref e) => Some(e),
            Inner::SuperfluousIssuance => None,
        }
    }
}

/// Decoder for the [`TxInWitness`] type.
#[derive(Default)]
pub struct TxInWitnessDecoder {
    inner: Decoder4<RangeProofDecoder, RangeProofDecoder, WitnessDecoder, PeginWitnessDecoder>,
}

/// Decoder error for the [`TxInWitness`] type.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxInWitnessDecoderError(
    Decoder4Error<
        RangeProofDecoderError,
        RangeProofDecoderError,
        WitnessDecoderError,
        PeginWitnessDecoderError,
    >,
);

impl fmt::Display for TxInWitnessDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("error decoding transaction input witness")
    }
}

impl std::error::Error for TxInWitnessDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl Decoder for TxInWitnessDecoder {
    type Output = TxInWitness;
    type Error = TxInWitnessDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(TxInWitnessDecoderError)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let (amount_rangeproof, inflation_keys_rangeproof, script_witness, pegin_witness) =
            self.inner.end().map_err(TxInWitnessDecoderError)?;

        Ok(TxInWitness {
            amount_rangeproof,
            inflation_keys_rangeproof,
            script_witness,
            pegin_witness,
        })
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl Decode for TxInWitness {
    type Decoder = TxInWitnessDecoder;
}

/// An decoder for the witnesses in a sequence of [`TxIn`]s.
///
/// Comsumes a vec of [`TxIn`]s on construction and then yields that
/// same vector, with the witness fields overwritten.
#[derive(Default)]
struct TxInWitnessesDecoder {
    txins: Vec<TxIn>,
    index: usize,
    // Invariant: if this is Some then
    decoder: Option<TxInWitnessDecoder>,
}

impl TxInWitnessesDecoder {
    fn new(txins: Vec<TxIn>) -> Self { Self { txins, index: 0, decoder: None } }
}

impl Decoder for TxInWitnessesDecoder {
    type Output = Vec<TxIn>;
    type Error = TxInWitnessDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        loop {
            let Some(next_txin) = self.txins.get_mut(self.index) else {
                return Ok(DecoderStatus::Ready);
            };

            let mut decoder = self.decoder.take().unwrap_or_else(TxInWitness::decoder);
            if decoder.push_bytes(bytes)?.needs_more() {
                self.decoder = Some(decoder);
                return Ok(DecoderStatus::NeedsMore);
            }
            next_txin.witness = decoder.end()?;
            self.index += 1;
        }
    }

    fn end(mut self) -> Result<Self::Output, Self::Error> {
        loop {
            let Some(last_txin) = self.txins.get_mut(self.index) else {
                return Ok(self.txins);
            };

            last_txin.witness = self.decoder.take().unwrap_or_else(TxInWitness::decoder).end()?;
            self.index += 1;
        }
    }

    fn read_limit(&self) -> usize {
        self.decoder.as_ref().map_or(0, TxInWitnessDecoder::read_limit)
    }
}

decoder_newtype! {
    /// Decoder for the [`TxOutWitness`] type.
    #[derive(Default)]
    pub struct TxOutWitnessDecoder(Decoder2<
        crate::confidential::SurjectionProofDecoder,
        crate::confidential::RangeProofDecoder,
    >);

    /// Decoder error for the [`TxOutWitness`] type.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TxOutWitnessDecoderError(Decoder2Error<
        crate::confidential::SurjectionProofDecoderError,
        crate::confidential::RangeProofDecoderError,
    >);
    const ERROR_DISPLAY = "error decoding transaction output witness";

    impl Decode for TxOutWitness {
        fn convert_inner(output) -> Result<_, TxOutWitnessDecoderErrorInner> {
            let (surjection_proof, rangeproof) = output;
            Ok(TxOutWitness {surjection_proof, rangeproof })
        }
    }
}

/// An decoder for the witnesses in a sequence of [`TxOut`]s.
///
/// Comsumes a vec of [`TxOut`]s on construction and then yields that
/// same vector, with the witness fields overwritten.
#[derive(Default)]
struct TxOutWitnessesDecoder {
    txouts: Vec<TxOut>,
    index: usize,
    // Invariant: if this is Some then
    decoder: Option<TxOutWitnessDecoder>,
}

impl TxOutWitnessesDecoder {
    fn new(txouts: Vec<TxOut>) -> Self { Self { txouts, index: 0, decoder: None } }
}

impl Decoder for TxOutWitnessesDecoder {
    type Output = Vec<TxOut>;
    type Error = TxOutWitnessDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        loop {
            let Some(next_txout) = self.txouts.get_mut(self.index) else {
                return Ok(DecoderStatus::Ready);
            };

            let mut decoder = self.decoder.take().unwrap_or_else(TxOutWitness::decoder);
            if decoder.push_bytes(bytes)?.needs_more() {
                self.decoder = Some(decoder);
                return Ok(DecoderStatus::NeedsMore);
            }
            next_txout.witness = decoder.end()?;
            self.index += 1;
        }
    }

    fn end(mut self) -> Result<Self::Output, Self::Error> {
        loop {
            let Some(last_txout) = self.txouts.get_mut(self.index) else {
                return Ok(self.txouts);
            };

            last_txout.witness = self.decoder.take().unwrap_or_else(TxOutWitness::decoder).end()?;
            self.index += 1;
        }
    }

    fn read_limit(&self) -> usize {
        self.decoder.as_ref().map_or(0, TxOutWitnessDecoder::read_limit)
    }
}

decoder_newtype! {
    /// Decoder for the [`TxOut`] type.
    #[derive(Default)]
    pub struct TxOutDecoder(Decoder4<
        crate::confidential::AssetDecoder,
        crate::confidential::ValueDecoder,
        crate::confidential::NonceDecoder,
        crate::script::ScriptDecoder,
    >);


    /// Decoder error for the [`TxOut`] type.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TxOutDecoderError(Decoder4Error<
            crate::confidential::AssetDecoderError,
            crate::confidential::ValueDecoderError,
            crate::confidential::NonceDecoderError,
            crate::script::ScriptDecoderError,
    >);
    const ERROR_DISPLAY = "error decoding transaction output witness";

    impl Decode for TxOut {
        fn convert_inner(output) -> Result<_, TxOutDecoderErrorInner> {
            let (asset, value, nonce, script_pubkey) = output;
            Ok(TxOut { asset, value, nonce, script_pubkey, witness: TxOutWitness::empty() })
        }
    }
}

decoder_state_machine! {
    /// Decoder for the [`Transaction`] type.
    pub struct TransactionDecoder(enum TransactionDecoderInner {
        Done(Transaction),
        Errored,
        DecodingNonWitness {
            decoder: Decoder4<
                ArrayDecoder<4>,
                ArrayDecoder<1>,
                Decoder2<
                    VecDecoder<TxIn>,
                    VecDecoder<TxOut>,
                >,
                LockTimeDecoder,
            >,
            => transition_non_witness(output, ...) -> Result {
                let (version, wit_flag, (input, output), lock_time) = output;
                match wit_flag {
                    [0] => Ok(TransactionDecoderInner::Done(Transaction {
                        version: u32::from_le_bytes(version),
                        lock_time,
                        input,
                        output,
                    })),
                    [1] => Ok(TransactionDecoderInner::DecodingWitnesses {
                        decoder: Decoder2::new(
                            TxInWitnessesDecoder::new(input),
                            TxOutWitnessesDecoder::new(output),
                        ),
                        version: u32::from_le_bytes(version),
                        lock_time,
                    }),
                    [x] => Err(TransactionDecoderErrorInner::InvalidWitnessFlag(x)),
                }
            }
        },
        DecodingWitnesses {
            decoder: Decoder2<
                TxInWitnessesDecoder,
                TxOutWitnessesDecoder,
            >,
            version: u32,
            lock_time: LockTime
            => transition_witnesses(output, ...) -> Result {
                let (input, output) = output;
                if input.iter().all(|input| input.witness.is_empty()) &&
                    output.iter().all(|output| output.witness.is_empty()) {
                    Err(TransactionDecoderErrorInner::NoWitnesses)
                } else {
                    Ok(TransactionDecoderInner::Done(Transaction {
                        version,
                        lock_time,
                        input,
                        output,
                    }))
                }
            }
        },
    });

    /// Decoder error for the [`Transaction`] type.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TransactionDecoderError(enum TransactionDecoderErrorInner {
        [macro-inserted decoder variants]
        InvalidWitnessFlag(u8),
        NoWitnesses,
    });
}

impl Default for TransactionDecoder {
    fn default() -> Self {
        Self(TransactionDecoderInner::DecodingNonWitness { decoder: Decoder4::default() })
    }
}

impl fmt::Display for TransactionDecoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use TransactionDecoderErrorInner as Inner;

        match self.0 {
            Inner::DecodingNonWitness(..) =>
                f.write_str("failed to decode non-witness part of transaction"),
            Inner::DecodingWitnesses(..) => f.write_str("failed to decode transaction witnesses"),
            Inner::InvalidWitnessFlag(flag) => {
                write!(f, "invalid witness flag {flag} (must be 0 or 1)")
            }
            Inner::NoWitnesses => f.write_str("witness flag set but all witnesses were empty"),
        }
    }
}

impl std::error::Error for TransactionDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use TransactionDecoderErrorInner as Inner;

        match self.0 {
            Inner::DecodingNonWitness(ref e) => Some(e),
            Inner::DecodingWitnesses(ref e) => Some(e),
            Inner::InvalidWitnessFlag(_) => None,
            Inner::NoWitnesses => None,
        }
    }
}
