// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transaction Encoders
//!
//! These are encapsulated because there are many of them, but in the end we
//! only expose the top-level ones outside of this module.

use super::{AssetIssuance, Sequence, Transaction, TxIn, TxInWitness, TxOut, TxOutWitness};
use crate::confidential::RangeProofEncoder;
use crate::encoding::{
    encoder_newtype, encoder_newtype_exact, ArrayEncoder, ArrayRefEncoder, Encode, Encoder,
    Encoder2, Encoder4, Encoder6, EncoderStatus, PrefixedSliceEncoder,
};
use crate::locktime::LockTimeEncoder;
use crate::{PeginWitnessEncoder, WitnessEncoder};

// While we define an [`OutPointEncoder`] struct, we don't actually implement `Encode` or `Decode`
// for [`OutPoint`], since the outpoint encoding depends on pegin/issuance data from the rest of
// the txin. We just use it as a private building block.

encoder_newtype_exact! {
    /// Encoder for the [`OutPoint`] type.
    #[derive(Clone, Debug)]
    struct OutPointEncoder<'e>(Encoder2<
        ArrayRefEncoder<'e, 32>,
        ArrayEncoder<4>,
    >);
}

impl<'e> OutPointEncoder<'e> {
    fn from_txin(txin: &'e TxIn) -> Self {
        let mut vout = txin.previous_output.vout;
        if txin.is_pegin {
            vout |= 1 << 30;
        }
        if txin.has_issuance() {
            vout |= 1 << 31;
        }

        Self::new(Encoder2::new(
            ArrayRefEncoder::without_length_prefix(txin.previous_output.txid.as_byte_array()),
            ArrayEncoder::without_length_prefix(vout.to_le_bytes()),
        ))
    }
}

encoder_newtype_exact! {
    /// Encoder for the [`Sequence`] type.
    #[derive(Clone, Debug)]
    pub struct SequenceEncoder<'e>(ArrayEncoder<4>);
}

impl Encode for Sequence {
    type Encoder<'e> = SequenceEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        SequenceEncoder::new(ArrayEncoder::without_length_prefix(
            self.to_consensus_u32().to_le_bytes(),
        ))
    }
}

encoder_newtype_exact! {
    /// Encoder for the [`AssetIssuance`] type.
    #[derive(Clone, Debug)]
    pub struct AssetIssuanceEncoder<'e>(Encoder4<
        crate::AssetBlindingNonceEncoder<'e>,
        crate::AssetEntropyEncoder<'e>,
        crate::confidential::ValueEncoder<'e>,
        crate::confidential::ValueEncoder<'e>,
    >);
}

impl Encode for AssetIssuance {
    type Encoder<'e> = AssetIssuanceEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        AssetIssuanceEncoder::new(Encoder4::new(
            self.asset_blinding_nonce.encoder(),
            self.asset_entropy.encoder(),
            self.amount.encoder(),
            self.inflation_keys.encoder(),
        ))
    }
}

encoder_newtype_exact! {
    /// Encoder for the [`TxInWitness`] type.
    #[derive(Clone, Debug)]
    pub struct TxInWitnessEncoder<'e>(Encoder4<
        RangeProofEncoder<'e>,
        RangeProofEncoder<'e>,
        WitnessEncoder<'e>,
        PeginWitnessEncoder<'e>,
    >);
}

impl Encode for TxInWitness {
    type Encoder<'e> = TxInWitnessEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        TxInWitnessEncoder::new(Encoder4::new(
            self.amount_rangeproof.encoder(),
            self.inflation_keys_rangeproof.encoder(),
            self.script_witness.encoder(),
            self.pegin_witness.encoder(),
        ))
    }
}

/// An encoder for the witnesses in a sequence of [`TxIn`]s.
#[derive(Clone, Debug)]
struct TxInWitnessesEncoder<'e> {
    txins: &'e [TxIn],
    cur_enc: Option<TxInWitnessEncoder<'e>>,
}

impl<'e> TxInWitnessesEncoder<'e> {
    fn new(txins: &'e [TxIn]) -> Self {
        Self { txins, cur_enc: txins.first().map(|txin| txin.witness.encoder()) }
    }
}

impl Encoder for TxInWitnessesEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        self.cur_enc.as_ref().map(Encoder::current_chunk).unwrap_or_default()
    }

    fn advance(&mut self) -> EncoderStatus {
        let Some(cur) = self.cur_enc.as_mut() else {
            return EncoderStatus::Finished;
        };

        loop {
            if cur.advance().has_more() {
                return EncoderStatus::HasMore;
            }
            // self.inputs guaranteed to be non-empty if cur_enc is non-None.
            self.txins = &self.txins[1..];
            if let Some(txin) = self.txins.first() {
                *cur = txin.witness.encoder();
                if !cur.current_chunk().is_empty() {
                    return EncoderStatus::HasMore;
                }
            } else {
                self.cur_enc = None;
                return EncoderStatus::Finished;
            }
        }
    }
}

encoder_newtype_exact! {
    /// Encoder for the [`TxIn`] type.
    #[derive(Clone, Debug)]
    pub struct TxInEncoder<'e>(Encoder4<
        OutPointEncoder<'e>,
        crate::script::ScriptEncoder<'e>,
        SequenceEncoder<'e>,
        Option<AssetIssuanceEncoder<'e>>,
    >);
}

impl Encode for TxIn {
    type Encoder<'e> = TxInEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        TxInEncoder::new(Encoder4::new(
            OutPointEncoder::from_txin(self),
            self.script_sig.encoder(),
            self.sequence.encoder(),
            self.has_issuance().then(|| self.asset_issuance.encoder()),
        ))
    }
}

encoder_newtype_exact! {
    /// Encoder for the [`TxOutWitness`] type.
    #[derive(Clone, Debug)]
    pub struct TxOutWitnessEncoder<'e>(Encoder2<
        crate::confidential::SurjectionProofEncoder<'e>,
        crate::confidential::RangeProofEncoder<'e>,
    >);
}

impl Encode for TxOutWitness {
    type Encoder<'e> = TxOutWitnessEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        TxOutWitnessEncoder::new(Encoder2::new(
            self.surjection_proof.encoder(),
            self.rangeproof.encoder(),
        ))
    }
}

/// An encoder for the witnesses in a sequence of [`TxOut`]s.
#[derive(Clone, Debug)]
struct TxOutWitnessesEncoder<'e> {
    txouts: &'e [TxOut],
    cur_enc: Option<TxOutWitnessEncoder<'e>>,
}

impl<'e> TxOutWitnessesEncoder<'e> {
    fn new(txouts: &'e [TxOut]) -> Self {
        Self { txouts, cur_enc: txouts.first().map(|txout| txout.witness.encoder()) }
    }
}

impl Encoder for TxOutWitnessesEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        self.cur_enc.as_ref().map(Encoder::current_chunk).unwrap_or_default()
    }

    fn advance(&mut self) -> EncoderStatus {
        let Some(cur) = self.cur_enc.as_mut() else {
            return EncoderStatus::Finished;
        };

        loop {
            if cur.advance().has_more() {
                return EncoderStatus::HasMore;
            }
            // self.inputs guaranteed to be non-empty if cur_enc is non-None.
            self.txouts = &self.txouts[1..];
            if let Some(txout) = self.txouts.first() {
                *cur = txout.witness.encoder();
                if !cur.current_chunk().is_empty() {
                    return EncoderStatus::HasMore;
                }
            } else {
                self.cur_enc = None;
                return EncoderStatus::Finished;
            }
        }
    }
}

encoder_newtype_exact! {
    /// Encoder for the [`TxOut`] type.
    #[derive(Clone, Debug)]
    pub struct TxOutEncoder<'e>(Encoder4<
        crate::confidential::AssetEncoder<'e>,
        crate::confidential::ValueEncoder<'e>,
        crate::confidential::NonceEncoder<'e>,
        crate::script::ScriptEncoder<'e>,
    >);
}

impl Encode for TxOut {
    type Encoder<'e> = TxOutEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        TxOutEncoder::new(Encoder4::new(
            self.asset.encoder(),
            self.value.encoder(),
            self.nonce.encoder(),
            self.script_pubkey.encoder(),
        ))
    }
}

encoder_newtype! {
    /// Encoder for the [`Transaction`] type.
    pub struct TransactionEncoder<'e>(Encoder6<
        ArrayEncoder<4>,
        ArrayEncoder<1>,
        PrefixedSliceEncoder<'e, TxIn>,
        PrefixedSliceEncoder<'e, TxOut>,
        LockTimeEncoder<'e>,
        Option<Encoder2<
            TxInWitnessesEncoder<'e>,
            TxOutWitnessesEncoder<'e>,
        >>
    >);
}

impl Encode for Transaction {
    type Encoder<'e> = TransactionEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        let witness_flag = self.has_witness();
        TransactionEncoder::new(Encoder6::new(
            ArrayEncoder::without_length_prefix(self.version.to_le_bytes()),
            ArrayEncoder::without_length_prefix([u8::from(witness_flag)]),
            PrefixedSliceEncoder::new(&self.input),
            PrefixedSliceEncoder::new(&self.output),
            self.lock_time.encoder(),
            witness_flag.then(|| {
                Encoder2::new(
                    TxInWitnessesEncoder::new(&self.input),
                    TxOutWitnessesEncoder::new(&self.output),
                )
            }),
        ))
    }
}
