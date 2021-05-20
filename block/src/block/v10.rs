//  Copyright (C) 2017-2019  The AXIOM TEAM Association.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Wrappers around Block document V10.

use crate::*;
use dubp_documents::identity::IdentityDocumentV10;
use dubp_documents::membership::v10::MembershipDocumentV10;
use dubp_documents::revocation::{CompactRevocationDocumentV10, RevocationDocumentV10};
use dubp_documents::transaction::v10::{TransactionDocumentV10, TransactionDocumentV10Stringified};
use dubp_documents::{
    certification::{v10::CertificationDocumentV10, CompactCertificationDocumentV10},
    dubp_wallet::prelude::SourceAmount,
};
use std::borrow::Cow;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct DubpBlockV10Content {
    /// Version
    pub version: usize,
    /// number
    pub number: BlockNumber,
    /// Minimal proof of work difficulty
    pub pow_min: usize,
    /// Local time of the block issuer
    pub time: u64,
    /// Average time
    pub median_time: u64,
    /// Members count
    pub members_count: usize,
    /// Monetary mass
    pub monetary_mass: u64,
    /// Unit base (power of ten)
    pub unit_base: usize,
    /// Number of compute members in the current frame
    pub issuers_count: usize,
    /// Current frame size (in blocks)
    pub issuers_frame: usize,
    /// Current frame variation buffer
    pub issuers_frame_var: isize,
    /// Currency.
    pub currency: CurrencyName,
    /// Block issuer
    pub issuer: ed25519::PublicKey,
    /// Currency parameters (only in genesis block)
    pub parameters: Option<BlockV10Parameters>,
    /// Hash of the previous block
    pub previous_hash: Hash,
    /// Issuer of the previous block
    pub previous_issuer: ed25519::PublicKey,
    /// Amount of new dividend created at this block, None if no dividend is created at this block
    pub dividend: Option<usize>,
    /// Identities
    pub identities: Vec<IdentityDocumentV10>,
    /// joiners
    pub joiners: Vec<MembershipDocumentV10>,
    /// Actives (=renewals)
    pub actives: Vec<MembershipDocumentV10>,
    /// Leavers
    pub leavers: Vec<MembershipDocumentV10>,
    /// Revokeds
    pub revoked: Vec<TextDocumentFormat<RevocationDocumentV10>>,
    /// Excludeds
    pub excluded: Vec<ed25519::PublicKey>,
    /// Certifications
    pub certifications: Vec<TextDocumentFormat<CertificationDocumentV10>>,
    /// Transactions
    pub transactions: Vec<TransactionDocumentV10>,
}

impl DubpBlockV10Content {
    pub(crate) fn gen_hashable_text(&self) -> String {
        let mut identities_str = String::from("");
        for identity in &self.identities {
            identities_str.push('\n');
            identities_str.push_str(&identity.generate_compact_text());
        }
        let mut joiners_str = String::new();
        for joiner in &self.joiners {
            joiners_str.push('\n');
            joiners_str.push_str(&joiner.generate_compact_text());
        }
        let mut actives_str = String::new();
        for active in &self.actives {
            actives_str.push('\n');
            actives_str.push_str(&active.generate_compact_text());
        }
        let mut leavers_str = String::new();
        for leaver in &self.leavers {
            leavers_str.push('\n');
            leavers_str.push_str(&leaver.generate_compact_text());
        }
        let mut identities_str = String::new();
        for identity in &self.identities {
            identities_str.push('\n');
            identities_str.push_str(&identity.generate_compact_text());
        }
        let mut revokeds_str = String::new();
        for revocation in &self.revoked {
            revokeds_str.push('\n');
            revokeds_str.push_str(&revocation.as_compact_text());
        }
        let mut excludeds_str = String::new();
        for exclusion in &self.excluded {
            excludeds_str.push('\n');
            excludeds_str.push_str(&exclusion.to_string());
        }
        let mut certifications_str = String::new();
        for certification in &self.certifications {
            certifications_str.push('\n');
            certifications_str.push_str(&certification.as_compact_text());
        }
        let mut transactions_str = String::new();
        for transaction in &self.transactions {
            transactions_str.push('\n');
            transactions_str.push_str(&transaction.generate_compact_text());
        }
        let mut dividend_str = String::new();
        if let Some(dividend) = self.dividend {
            if dividend > 0 {
                dividend_str.push_str("UniversalDividend: ");
                dividend_str.push_str(&dividend.to_string());
                dividend_str.push('\n');
            }
        }
        let mut parameters_str = String::new();
        if let Some(params) = self.parameters {
            parameters_str.push_str("Parameters: ");
            parameters_str.push_str(&params.to_string());
            parameters_str.push('\n');
        }
        let mut previous_hash_str = String::new();
        if self.number.0 > 0 {
            previous_hash_str.push_str("PreviousHash: ");
            previous_hash_str.push_str(&self.previous_hash.to_string());
            previous_hash_str.push('\n');
        }
        let mut previous_issuer_str = String::new();
        if self.number.0 > 0 {
            previous_issuer_str.push_str("PreviousIssuer: ");
            previous_issuer_str.push_str(&self.previous_issuer.to_string());
            previous_issuer_str.push('\n');
        }
        format!(
            "Version: {version}
Type: Block
Currency: {currency}
Number: {block_number}
PoWMin: {pow_min}
Time: {time}
MedianTime: {median_time}
{dividend}UnitBase: {unit_base}
Issuer: {issuer}
IssuersFrame: {issuers_frame}
IssuersFrameVar: {issuers_frame_var}
DifferentIssuersCount: {issuers_count}
{parameters}{previous_hash}{previous_issuer}MembersCount: {members_count}
Identities:{identities}
Joiners:{joiners}
Actives:{actives}
Leavers:{leavers}
Revoked:{revoked}
Excluded:{excluded}
Certifications:{certifications}
Transactions:{transactions}
",
            version = self.version,
            currency = self.currency,
            block_number = self.number,
            pow_min = self.pow_min,
            time = self.time,
            median_time = self.median_time,
            dividend = dividend_str,
            unit_base = self.unit_base,
            issuer = self.issuer,
            issuers_frame = self.issuers_frame,
            issuers_frame_var = self.issuers_frame_var,
            issuers_count = self.issuers_count,
            parameters = parameters_str,
            previous_hash = previous_hash_str,
            previous_issuer = previous_issuer_str,
            members_count = self.members_count,
            identities = identities_str,
            joiners = joiners_str,
            actives = actives_str,
            leavers = leavers_str,
            revoked = revokeds_str,
            excluded = excludeds_str,
            certifications = certifications_str,
            transactions = transactions_str,
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct DubpBlockV10AfterPowData {
    pub nonce: u64,
    pub signature: ed25519::Signature,
    pub hash: BlockHash,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct DubpBlockV10Builder {
    /// Block content
    content: DubpBlockV10Content,
    /// Block inner hash (=hash of content)
    inner_hash: Hash,
}

impl DubpBlockV10Builder {
    pub fn new(content: DubpBlockV10Content) -> Self {
        DubpBlockV10Builder {
            inner_hash: Hash::compute(content.gen_hashable_text().as_bytes()),
            content,
        }
    }
    pub fn inner_hash(&self) -> Hash {
        self.inner_hash
    }
    pub fn build_unchecked(self, after_pow_data: DubpBlockV10AfterPowData) -> DubpBlockV10 {
        DubpBlockV10 {
            content: self.content,
            inner_hash: Some(self.inner_hash),
            nonce: after_pow_data.nonce,
            signature: after_pow_data.signature,
            hash: after_pow_data.hash,
        }
    }
}

/// Wrap a Block document.
///
/// Must be created by parsing/deserialization or using a builder.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct DubpBlockV10 {
    /// Block content
    content: DubpBlockV10Content,
    /// Block inner hash (=hash of content)
    /// Reduced block contains None because this field can be computed and checked with block hash
    inner_hash: Option<Hash>,
    /// Nonce
    nonce: u64,
    /// Block signature
    signature: ed25519::Signature,
    /// Block hash
    hash: BlockHash,
}

impl DubpBlockTrait for DubpBlockV10 {
    type Signator = ed25519::Signator;

    fn common_time(&self) -> u64 {
        self.content.median_time
    }
    fn compute_hashed_string(&self) -> String {
        format!("{}{}\n", self.compute_signed_string(), self.signature)
    }
    fn compute_signed_string(&self) -> String {
        let inner_hash = if let Some(inner_hash) = self.inner_hash {
            inner_hash
        } else {
            self.compute_inner_hash()
        };
        format!(
            "InnerHash: {}\nNonce: {}\n",
            inner_hash.to_hex(),
            self.nonce
        )
    }
    fn current_frame_size(&self) -> usize {
        self.content.issuers_frame
    }
    fn currency_name(&self) -> CurrencyName {
        self.content.currency.clone()
    }
    fn currency_parameters(&self) -> Option<CurrencyParameters> {
        if let Some(genesis_parameters) = self.content.parameters {
            Some(CurrencyParameters::from((
                &self.content.currency,
                genesis_parameters,
            )))
        } else {
            None
        }
    }
    fn dividend(&self) -> Option<SourceAmount> {
        if let Some(dividend) = self.content.dividend {
            Some(SourceAmount::new(
                dividend as i64,
                self.content.unit_base as i64,
            ))
        } else {
            None
        }
    }
    fn generate_compact_inner_text(&self) -> String {
        self.content.gen_hashable_text()
    }
    fn hash(&self) -> BlockHash {
        self.hash
    }
    fn inner_hash(&self) -> Hash {
        if let Some(inner_hash) = self.inner_hash {
            inner_hash
        } else {
            self.compute_inner_hash()
        }
    }
    fn issuers_count(&self) -> usize {
        self.content.issuers_count
    }
    fn issuers_frame(&self) -> usize {
        self.content.issuers_frame
    }
    fn issuer(&self) -> ed25519::PublicKey {
        self.content.issuer
    }
    fn local_time(&self) -> u64 {
        self.content.time
    }
    fn members_count(&self) -> usize {
        self.content.members_count
    }
    fn monetary_mass(&self) -> u64 {
        self.content.monetary_mass
    }
    fn nonce(&self) -> u64 {
        self.nonce
    }
    fn number(&self) -> BlockNumber {
        self.content.number
    }
    fn pow_min(&self) -> usize {
        self.content.pow_min
    }
    fn previous_blockstamp(&self) -> Blockstamp {
        if self.content.number.0 > 0 {
            Blockstamp {
                number: BlockNumber(self.content.number.0 - 1),
                hash: BlockHash(self.content.previous_hash),
            }
        } else {
            Blockstamp::default()
        }
    }
    fn previous_hash(&self) -> Hash {
        self.content.previous_hash
    }
    fn reduce(&mut self) {
        //self.hash = None;
        self.inner_hash = None;
        for i in &mut self.content.identities {
            i.reduce();
        }
        for i in &mut self.content.joiners {
            i.reduce();
        }
        for i in &mut self.content.actives {
            i.reduce();
        }
        for i in &mut self.content.leavers {
            i.reduce();
        }
        for i in &mut self.content.transactions {
            i.reduce();
        }
    }
    fn sign(&mut self, signator: &Self::Signator) -> Result<(), SignError> {
        self.signature = signator.sign(self.compute_signed_string().as_bytes());
        Ok(())
    }
    fn signature(&self) -> ed25519::Signature {
        self.signature
    }
    fn verify_inner_hash(&self) -> Result<(), VerifyBlockHashError> {
        match self.inner_hash {
            Some(inner_hash) => {
                let computed_hash = self.compute_inner_hash();
                if inner_hash == computed_hash {
                    Ok(())
                } else {
                    Err(VerifyBlockHashError::InvalidHash {
                        block_number: self.content.number,
                        expected_hash: computed_hash,
                        actual_hash: inner_hash,
                    })
                }
            }
            None => Err(VerifyBlockHashError::MissingHash {
                block_number: self.content.number,
            }),
        }
    }
    fn verify_signature(&self) -> Result<(), SigError> {
        self.content
            .issuer
            .verify(self.compute_signed_string().as_bytes(), &self.signature)
    }
    fn verify_hash(&self) -> Result<(), VerifyBlockHashError> {
        let expected_hash = self.compute_hash();
        if self.hash == expected_hash {
            Ok(())
        } else {
            warn!(
                "Block #{} have invalid hash (expected='{}', actual='{}', datas='{}').",
                self.content.number.0,
                expected_hash,
                self.hash,
                self.compute_hashed_string()
            );
            Err(VerifyBlockHashError::InvalidHash {
                block_number: self.content.number,
                expected_hash: expected_hash.0,
                actual_hash: self.hash.0,
            })
        }
    }
    fn unit_base(&self) -> usize {
        self.content.unit_base
    }
}

impl DubpBlockV10 {
    pub fn identities(&self) -> &[IdentityDocumentV10] {
        &self.content.identities
    }
    pub fn joiners(&self) -> &[MembershipDocumentV10] {
        &self.content.joiners
    }
    pub fn actives(&self) -> &[MembershipDocumentV10] {
        &self.content.actives
    }
    pub fn leavers(&self) -> &[MembershipDocumentV10] {
        &self.content.leavers
    }
    pub fn revoked(&self) -> Vec<Cow<CompactRevocationDocumentV10>> {
        self.content
            .revoked
            .iter()
            .map(|revo| revo.to_compact_document())
            .collect()
    }
    pub fn excluded(&self) -> &[ed25519::PublicKey] {
        &self.content.excluded
    }
    pub fn certifications(&self) -> Vec<Cow<CompactCertificationDocumentV10>> {
        self.content
            .certifications
            .iter()
            .map(|cert| cert.to_compact_document())
            .collect()
    }
    pub fn transactions(&self) -> &[TransactionDocumentV10] {
        &self.content.transactions
    }
    /// Needed only for BMA (to be removed)
    #[cfg(not(tarpaulin_include))]
    pub fn as_compact_text(&self) -> String {
        let compact_inner_text = self.generate_compact_inner_text();
        let inner_hash = if let Some(inner_hash) = self.inner_hash {
            inner_hash
        } else {
            Hash::compute(compact_inner_text.as_bytes())
        };
        format!(
            "{}InnerHash: {}\nNonce: ",
            compact_inner_text,
            inner_hash.to_hex()
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DubpBlockV10Stringified {
    /// Version
    pub version: u64,
    /// Nonce
    pub nonce: u64,
    /// number
    pub number: u64,
    /// Minimal proof of work difficulty
    pub pow_min: u64,
    /// Local time of the block issuer
    pub time: u64,
    /// Average time
    pub median_time: u64,
    /// Members count
    pub members_count: u64,
    /// Monetary mass
    pub monetary_mass: u64,
    /// Unit base (power of ten)
    #[serde(rename = "unitbase")]
    pub unit_base: u64,
    /// Number of compute members in the current frame
    pub issuers_count: u64,
    /// Current frame size (in blocks)
    pub issuers_frame: u64,
    /// Current frame variation buffer
    pub issuers_frame_var: i64,
    /// Currency.
    pub currency: String,
    /// Block issuer.
    pub issuer: String,
    /// Block signature.
    pub signature: String,
    /// Block hash.
    pub hash: Option<String>,
    /// Currency parameters (only in genesis block)
    pub parameters: Option<String>,
    /// Hash of the previous block
    pub previous_hash: Option<String>,
    /// Issuer of the previous block
    pub previous_issuer: Option<String>,
    /// Hash of the deterministic content of the block
    #[serde(rename = "inner_hash")]
    pub inner_hash: Option<String>,
    /// Amount of new dividend created at this block, None if no dividend is created at this block
    pub dividend: Option<u64>,
    /// Identities
    pub identities: Vec<String>,
    /// joiners
    pub joiners: Vec<String>,
    /// Actives (=renewals)
    pub actives: Vec<String>,
    /// Leavers
    pub leavers: Vec<String>,
    /// Revokeds
    pub revoked: Vec<String>,
    /// Excludeds
    pub excluded: Vec<String>,
    /// Certifications
    pub certifications: Vec<String>,
    /// Transactions
    pub transactions: Vec<TransactionDocumentV10Stringified>,
}

impl ToStringObject for DubpBlockV10 {
    type StringObject = DubpBlockV10Stringified;
    /// Transforms an object into a json object
    fn to_string_object(&self) -> DubpBlockV10Stringified {
        DubpBlockV10Stringified {
            version: self.content.version as u64,
            nonce: self.nonce,
            number: u64::from(self.content.number.0),
            pow_min: self.content.pow_min as u64,
            time: self.content.time,
            median_time: self.content.median_time,
            members_count: self.content.members_count as u64,
            monetary_mass: self.content.monetary_mass,
            unit_base: self.content.unit_base as u64,
            issuers_count: self.content.issuers_count as u64,
            issuers_frame: self.content.issuers_frame as u64,
            issuers_frame_var: self.content.issuers_frame_var as i64,
            currency: self.content.currency.to_string(),
            issuer: self.content.issuer.to_string(),
            signature: self.signature.to_string(),
            hash: Some(self.hash.to_string()),
            parameters: self
                .content
                .parameters
                .map(|parameters| parameters.to_string()),
            previous_hash: if self.content.number.0 == 0 {
                None
            } else {
                Some(self.content.previous_hash.to_string())
            },
            previous_issuer: if self.content.number.0 == 0 {
                None
            } else {
                Some(self.content.previous_issuer.to_string())
            },
            inner_hash: self.inner_hash.map(|hash| hash.to_string()),
            dividend: self.content.dividend.map(|d| d as u64),
            identities: self
                .content
                .identities
                .iter()
                .map(|doc| doc.to_compact_document().as_compact_text())
                .collect(),
            joiners: self
                .content
                .joiners
                .iter()
                .map(|doc| doc.to_compact_document().as_compact_text())
                .collect(),
            actives: self
                .content
                .actives
                .iter()
                .map(|doc| doc.to_compact_document().as_compact_text())
                .collect(),
            leavers: self
                .content
                .leavers
                .iter()
                .map(|doc| doc.to_compact_document().as_compact_text())
                .collect(),
            revoked: self
                .content
                .revoked
                .iter()
                .map(|doc| doc.to_compact_document().as_compact_text())
                .collect(),
            excluded: self
                .content
                .excluded
                .iter()
                .map(ToString::to_string)
                .collect(),
            certifications: self
                .content
                .certifications
                .iter()
                .map(|doc| doc.to_compact_document().as_compact_text())
                .collect(),
            transactions: self
                .content
                .transactions
                .iter()
                .map(|tx_doc| tx_doc.to_string_object())
                .collect(),
        }
    }
}

impl FromStringObject for DubpBlockV10 {
    fn from_string_object(stringified: &DubpBlockV10Stringified) -> Result<Self, TextParseError> {
        let str_identities: Vec<_> = stringified.identities.iter().map(|x| &**x).collect();
        let str_joiners: Vec<_> = stringified.joiners.iter().map(|x| &**x).collect();
        let str_actives: Vec<_> = stringified.actives.iter().map(|x| &**x).collect();
        let str_leavers: Vec<_> = stringified.leavers.iter().map(|x| &**x).collect();
        let str_revoked: Vec<_> = stringified.revoked.iter().map(|x| &**x).collect();
        let str_certs: Vec<_> = stringified.certifications.iter().map(|x| &**x).collect();
        Ok(DubpBlockV10 {
            content: DubpBlockV10Content {
                version: stringified.version as usize,
                number: BlockNumber(stringified.number as u32),
                pow_min: stringified.pow_min as usize,
                time: stringified.time,
                median_time: stringified.median_time,
                members_count: stringified.members_count as usize,
                monetary_mass: stringified.monetary_mass,
                unit_base: stringified.unit_base as usize,
                issuers_count: stringified.issuers_count as usize,
                issuers_frame: stringified.issuers_frame as usize,
                issuers_frame_var: stringified.issuers_frame_var as isize,
                currency: CurrencyName(stringified.currency.clone()),
                issuer: ed25519::PublicKey::from_base58(&stringified.issuer).map_err(|error| {
                    TextParseError::BaseConversionError {
                        field: "block.issuer",
                        error,
                    }
                })?,
                parameters: None,
                previous_hash: if let Some(ref previous_hash) = stringified.previous_hash {
                    if !previous_hash.is_empty() {
                        Hash::from_hex(previous_hash).map_err(|error| {
                            TextParseError::BaseConversionError {
                                field: "block.previous_hash",
                                error,
                            }
                        })?
                    } else {
                        Hash::default()
                    }
                } else {
                    Hash::default()
                },
                previous_issuer: if let Some(ref previous_issuer) = stringified.previous_issuer {
                    if !previous_issuer.is_empty() {
                        ed25519::PublicKey::from_base58(previous_issuer).map_err(|error| {
                            TextParseError::BaseConversionError {
                                field: "block.previous_issuer",
                                error,
                            }
                        })?
                    } else {
                        ed25519::PublicKey::default()
                    }
                } else {
                    ed25519::PublicKey::default()
                },
                dividend: stringified.dividend.map(|dividend| dividend as usize),
                identities: parse_compact_identities(&stringified.currency, &str_identities)
                    .map_err(|error| TextParseError::CompactDoc {
                        field: "block.identities",
                        error,
                    })?,
                joiners: parse_compact_memberships(
                    &stringified.currency,
                    MembershipType::In(),
                    &str_joiners,
                )
                .map_err(|error| TextParseError::CompactDoc {
                    field: "block.joiners",
                    error,
                })?,
                actives: parse_compact_memberships(
                    &stringified.currency,
                    MembershipType::In(),
                    &str_actives,
                )
                .map_err(|error| TextParseError::CompactDoc {
                    field: "block.actives",
                    error,
                })?,
                leavers: parse_compact_memberships(
                    &stringified.currency,
                    MembershipType::Out(),
                    &str_leavers,
                )
                .map_err(|error| TextParseError::CompactDoc {
                    field: "block.leavers",
                    error,
                })?,
                revoked: parse_compact_revocations(&str_revoked).map_err(|error| {
                    TextParseError::CompactDoc {
                        field: "block.revoked",
                        error,
                    }
                })?,
                excluded: stringified
                    .excluded
                    .iter()
                    .map(|pubkey| ed25519::PublicKey::from_base58(pubkey))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| TextParseError::BaseConversionError {
                        field: "block.excluded",
                        error,
                    })?,
                certifications: parse_compact_certifications(&str_certs).map_err(|error| {
                    TextParseError::CompactDoc {
                        field: "block.certifications",
                        error,
                    }
                })?,
                transactions: stringified
                    .transactions
                    .iter()
                    .map(|tx| TransactionDocumentV10::from_string_object(tx))
                    .collect::<Result<Vec<_>, _>>()?,
            },
            inner_hash: Some(
                Hash::from_hex(stringified.inner_hash.as_ref().ok_or_else(|| {
                    TextParseError::InvalidInnerFormat("Block without inner_hash".to_owned())
                })?)
                .map_err(|error| TextParseError::BaseConversionError {
                    field: "block.inner_hash",
                    error,
                })?,
            ),
            nonce: stringified.nonce,
            signature: ed25519::Signature::from_base64(&stringified.signature).map_err(
                |error| TextParseError::BaseConversionError {
                    field: "block.signature",
                    error,
                },
            )?,
            hash: BlockHash(
                Hash::from_hex(stringified.hash.as_ref().ok_or_else(|| {
                    TextParseError::InvalidInnerFormat("Block without hash".to_owned())
                })?)
                .map_err(|error| TextParseError::BaseConversionError {
                    field: "block.hash",
                    error,
                })?,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;
    use dubp_documents::certification::CertificationDocument;
    use dubp_documents::membership::MembershipDocument;
    use dubp_documents::transaction::TransactionDocument;
    use pretty_assertions::assert_eq;
    use unwrap::unwrap;

    #[test]
    fn test_default_block_v10() {
        let mut default_block = DubpBlockV10::default();

        let mut default_stringified_block = default_block.to_string_object();
        default_stringified_block.currency = String::with_capacity(0);
        default_stringified_block.issuer = String::with_capacity(0);
        default_stringified_block.signature = String::with_capacity(0);
        default_stringified_block.hash = None;
        assert_eq!(
            default_stringified_block,
            DubpBlockV10Stringified::default()
        );

        assert_eq!(default_block.common_time(), 0);
        assert_eq!(default_block.current_frame_size(), 0);
        assert_eq!(default_block.issuers_count(), 0);
        assert_eq!(default_block.members_count(), 0);
        assert_eq!(default_block.number(), BlockNumber(0));
        assert_eq!(default_block.pow_min(), 0);
        assert_eq!(default_block.previous_blockstamp(), Blockstamp::default());
        assert_eq!(default_block.previous_hash(), Hash::default());

        // Inner hash
        assert_eq!(
            Err(VerifyBlockHashError::MissingHash {
                block_number: BlockNumber(0)
            }),
            default_block.verify_inner_hash()
        );
        default_block.inner_hash = Some(Hash::default());
        assert_eq!(
            Err(VerifyBlockHashError::InvalidHash {
                block_number: BlockNumber(0),
                actual_hash: Hash::default(),
                expected_hash: default_block.compute_inner_hash(),
            }),
            default_block.verify_inner_hash()
        );

        // Signature
        assert_eq!(default_block.signature, ed25519::Signature::default());
        assert_eq!(Err(SigError::InvalidSig), default_block.verify_signature());
        let signator = unwrap!(ed25519::Ed25519KeyPair::generate_random()).generate_signator();
        default_block.content.issuer = signator.public_key();
        unwrap!(default_block.sign(&signator));
        assert_eq!(Ok(()), default_block.verify_signature());

        // Hash
        assert_eq!(BlockHash(Hash::default()), default_block.hash());
        assert_eq!(
            Err(VerifyBlockHashError::InvalidHash {
                block_number: BlockNumber(0),
                actual_hash: Hash::default(),
                expected_hash: default_block.compute_hash().0,
            }),
            default_block.verify_hash()
        );
    }

    #[test]
    fn generate_and_verify_empty_block() {
        let block_content = DubpBlockV10Content {
            version: 10,
            number: BlockNumber(174_260),
            pow_min: 68,
            time: 1_525_296_873,
            median_time: 1_525_292_577,
            members_count: 33,
            monetary_mass: 15_633_687,
            unit_base: 0,
            issuers_count: 8,
            issuers_frame: 41,
            issuers_frame_var: 0,
            currency: CurrencyName(String::from("g1-test")),
            issuer: pk("39Fnossy1GrndwCnAXGDw3K5UYXhNXAFQe7yhYZp8ELP"),
            parameters: None,
            previous_hash: unwrap!(Hash::from_hex(
                "0000A7D4361B9EBF4CE974A521149A73E8A5DE9B73907AB3BC918726AED7D40A"
            )),
            previous_issuer: pk("EPKuZA1Ek5y8S1AjAmAPtGrVCMFqUGzUEAa7Ei62CY2L"),
            dividend: None,
            identities: Vec::new(),
            joiners: Vec::new(),
            actives: Vec::new(),
            leavers: Vec::new(),
            revoked: Vec::new(),
            excluded: Vec::new(),
            certifications: Vec::new(),
            transactions: Vec::new(),
        };
        let mut block = DubpBlockV10Builder::new(block_content).build_unchecked(DubpBlockV10AfterPowData {
            nonce: 100_010_200_000_006_940,
            signature: unwrap!(ed25519::Signature::from_base64("lqXrNOopjM39oM7hgB7Vq13uIohdCuLlhh/q8RVVEZ5UVASphow/GXikCdhbWID19Bn0XrXzTbt/R7akbE9xAg==")),
            hash: BlockHash::default(),
        });
        // test inner_hash computation
        println!("{}", block.generate_compact_inner_text());
        assert!(block.verify_inner_hash().is_ok());
        assert_eq!(
            unwrap!(block.inner_hash).to_hex(),
            "58E4865A47A46E0DF1449AABC449B5406A12047C413D61B5E17F86BE6641E7B0"
        );
        // Test signature validity
        assert!(block.verify_signature().is_ok());
        // Test hash computation
        let computed_hash = block.compute_hash();
        block.hash = computed_hash;
        assert!(block.verify_hash().is_ok());
        assert_eq!(
            block.hash.0.to_hex(),
            "00002EE584F36C15D3EB21AAC78E0896C75EF9070E73B4EC33BFA2C3D561EEB2"
        );
    }

    #[test]
    fn generate_and_verify_block() {
        let cert1 = unwrap!(CertificationDocument::parse_from_raw_text("Version: 10
Type: Certification
Currency: g1
Issuer: 6TAzLWuNcSqgNDNpAutrKpPXcGJwy1ZEMeVvZSZNs2e3
IdtyIssuer: CYPsYTdt87Tx6cCiZs9KD4jqPgYxbcVEqVZpRgJ9jjoV
IdtyUniqueID: PascaleM
IdtyTimestamp: 97401-0000003821911909F98519CC773D2D3E5CFE3D5DBB39F4F4FF33B96B4D41800E
IdtySignature: QncUVXxZ2NfARjdJOn6luILvDuG1NuK9qSoaU4CST2Ij8z7oeVtEgryHl+EXOjSe6XniALsCT0gU8wtadcA/Cw==
CertTimestamp: 106669-000003682E6FE38C44433DCE92E8B2A26C69B6D7867A2BAED231E788DDEF4251
UmseG2XKNwKcY8RFi6gUCT91udGnnNmSh7se10J1jeRVlwf+O2Tyb2Cccot9Dt7BO4+Kx2P6vFJB3oVGGHMxBA=="));
        let CertificationDocument::V10(cert1) = cert1;

        let TransactionDocument::V10(tx1) = unwrap!(TransactionDocument::parse_from_raw_text("Version: 10
Type: Transaction
Currency: g1
Blockstamp: 107982-000001242F6DA51C06A915A96C58BAA37AB3D1EB51F6E1C630C707845ACF764B
Locktime: 0
Issuers:
8dkCwvAqSczUjKsoVMDPVbQ3i6bBQeBQYawL87kqTSQ3
Inputs:
1002:0:D:8dkCwvAqSczUjKsoVMDPVbQ3i6bBQeBQYawL87kqTSQ3:106345
Unlocks:
0:SIG(0)
Outputs:
1002:0:SIG(CitdnuQgZ45tNFCagay7Wh12gwwHM8VLej1sWmfHWnQX)
Comment: DU symbolique pour demander le codage de nouvelles fonctionnalites cf. https://forum.monnaie-libre.fr/t/creer-de-nouvelles-fonctionnalites-dans-cesium-les-autres-applications/2025  Merci
T0LlCcbIn7xDFws48H8LboN6NxxwNXXTovG4PROLf7tkUAueHFWjfwZFKQXeZEHxfaL1eYs3QspGtLWUHPRVCQ=="));

        let TransactionDocument::V10(tx2) = unwrap!(TransactionDocument::parse_from_raw_text("Version: 10
Type: Transaction
Currency: g1
Blockstamp: 107982-000001242F6DA51C06A915A96C58BAA37AB3D1EB51F6E1C630C707845ACF764B
Locktime: 0
Issuers:
8dkCwvAqSczUjKsoVMDPVbQ3i6bBQeBQYawL87kqTSQ3
Inputs:
1002:0:D:8dkCwvAqSczUjKsoVMDPVbQ3i6bBQeBQYawL87kqTSQ3:106614
Unlocks:
0:SIG(0)
Outputs:
1002:0:SIG(78ZwwgpgdH5uLZLbThUQH7LKwPgjMunYfLiCfUCySkM8)
Comment: DU symbolique pour demander le codage de nouvelles fonctionnalites cf. https://forum.monnaie-libre.fr/t/creer-de-nouvelles-fonctionnalites-dans-cesium-les-autres-applications/2025  Merci
a9PHPuSfw7jW8FRQHXFsGi/bnLjbtDnTYvEVgUC9u0WlR7GVofa+Xb+l5iy6NwuEXiwvueAkf08wPVY8xrNcCg=="));

        let block_content = DubpBlockV10Content {
            version: 10,
            number: BlockNumber(107_984),
            pow_min: 88,
            time: 1_522_685_861,
            median_time: 1_522_683_184,
            members_count: 896,
            monetary_mass: 140_469_765,
            unit_base: 0,
            issuers_count: 42,
            issuers_frame: 211,
            issuers_frame_var: 0,
            currency: CurrencyName(String::from("g1")),
            issuer: pk("DA4PYtXdvQqk1nCaprXH52iMsK5Ahxs1nRWbWKLhpVkQ"),
            parameters: None,
            previous_hash: unwrap!(Hash::from_hex(
                "000001144968D0C3516BE6225E4662F182E28956AF46DD7FB228E3D0F9413FEB"
            )),
            previous_issuer: pk("D3krfq6J9AmfpKnS3gQVYoy7NzGCc61vokteTS8LJ4YH"),
            dividend: None,
            identities: Vec::new(),
            joiners: Vec::new(),
            actives: Vec::new(),
            leavers: Vec::new(),
            revoked: Vec::new(),
            excluded: Vec::new(),
            certifications: vec![TextDocumentFormat::Complete(cert1)],
            transactions: vec![tx1, tx2],
        };
        let mut block = DubpBlockV10Builder::new(block_content).build_unchecked(DubpBlockV10AfterPowData {
            nonce: 10_300_000_018_323,
            signature: unwrap!(ed25519::Signature::from_base64("92id58VmkhgVNee4LDqBGSm8u/ooHzAD67JM6fhAE/CV8LCz7XrMF1DvRl+eRpmlaVkp6I+Iy8gmZ1WUM5C8BA==")),
            hash: BlockHash::default(),
        });
        // test inner_hash computation
        println!("{}", block.generate_compact_inner_text());
        assert!(block.verify_inner_hash().is_ok());

        assert_eq!(
            unwrap!(block.inner_hash).to_hex(),
            "C8AB69E33ECE2612EADC7AB30D069B1F1A3D8C95EBBFD50DE583AC8E3666CCA1"
        );
        // test generate_compact_inner_text()
        assert_eq!(
            block.generate_compact_inner_text(),
            "Version: 10\nType: Block\nCurrency: g1\nNumber: 107984\nPoWMin: 88\nTime: 1522685861\nMedianTime: 1522683184\nUnitBase: 0\nIssuer: DA4PYtXdvQqk1nCaprXH52iMsK5Ahxs1nRWbWKLhpVkQ\nIssuersFrame: 211\nIssuersFrameVar: 0\nDifferentIssuersCount: 42\nPreviousHash: 000001144968D0C3516BE6225E4662F182E28956AF46DD7FB228E3D0F9413FEB\nPreviousIssuer: D3krfq6J9AmfpKnS3gQVYoy7NzGCc61vokteTS8LJ4YH\nMembersCount: 896\nIdentities:\nJoiners:\nActives:\nLeavers:\nRevoked:\nExcluded:\nCertifications:\n6TAzLWuNcSqgNDNpAutrKpPXcGJwy1ZEMeVvZSZNs2e3:CYPsYTdt87Tx6cCiZs9KD4jqPgYxbcVEqVZpRgJ9jjoV:106669:UmseG2XKNwKcY8RFi6gUCT91udGnnNmSh7se10J1jeRVlwf+O2Tyb2Cccot9Dt7BO4+Kx2P6vFJB3oVGGHMxBA==\nTransactions:\nTX:10:1:1:1:1:1:0\n107982-000001242F6DA51C06A915A96C58BAA37AB3D1EB51F6E1C630C707845ACF764B\n8dkCwvAqSczUjKsoVMDPVbQ3i6bBQeBQYawL87kqTSQ3\n1002:0:D:8dkCwvAqSczUjKsoVMDPVbQ3i6bBQeBQYawL87kqTSQ3:106345\n0:SIG(0)\n1002:0:SIG(CitdnuQgZ45tNFCagay7Wh12gwwHM8VLej1sWmfHWnQX)\nDU symbolique pour demander le codage de nouvelles fonctionnalites cf. https://forum.monnaie-libre.fr/t/creer-de-nouvelles-fonctionnalites-dans-cesium-les-autres-applications/2025  Merci\nT0LlCcbIn7xDFws48H8LboN6NxxwNXXTovG4PROLf7tkUAueHFWjfwZFKQXeZEHxfaL1eYs3QspGtLWUHPRVCQ==\nTX:10:1:1:1:1:1:0\n107982-000001242F6DA51C06A915A96C58BAA37AB3D1EB51F6E1C630C707845ACF764B\n8dkCwvAqSczUjKsoVMDPVbQ3i6bBQeBQYawL87kqTSQ3\n1002:0:D:8dkCwvAqSczUjKsoVMDPVbQ3i6bBQeBQYawL87kqTSQ3:106614\n0:SIG(0)\n1002:0:SIG(78ZwwgpgdH5uLZLbThUQH7LKwPgjMunYfLiCfUCySkM8)\nDU symbolique pour demander le codage de nouvelles fonctionnalites cf. https://forum.monnaie-libre.fr/t/creer-de-nouvelles-fonctionnalites-dans-cesium-les-autres-applications/2025  Merci\na9PHPuSfw7jW8FRQHXFsGi/bnLjbtDnTYvEVgUC9u0WlR7GVofa+Xb+l5iy6NwuEXiwvueAkf08wPVY8xrNcCg==\n"
        );
        // Test signature validity
        assert!(block.verify_signature().is_ok());
        // Test hash computation
        block.hash = block.compute_hash();
        assert!(block.verify_hash().is_ok());
        assert_eq!(
            block.hash.0.to_hex(),
            "000004F8B84A3590243BA562E5F2BA379F55A0B387C5D6FAC1022DFF7FFE6014"
        );

        // Test reduce factor
        let block_size = unwrap!(bincode::serialize(&block)).len();
        block.reduce();
        let block_reduced_size = unwrap!(bincode::serialize(&block)).len();
        assert!(block_reduced_size < block_size);
        println!(
            "block reduction: {} octets -> {} octets",
            block_size, block_reduced_size
        );
    }

    #[test]
    fn generate_and_verify_block_2() {
        let ms1 = unwrap!(MembershipDocument::parse_from_raw_text(
            "Version: 10
Type: Membership
Currency: g1
Issuer: 4VZkro3N7VonygybESHngKUABA6gSrbW77Ktb94zE969
Block: 165645-000002D30130881939961A38D51CA233B3C696AA604439036DB1AAA4ED5046D2
Membership: IN
UserID: piaaf31
CertTS: 74077-0000022816648B2F7801E059F67CCD0C023FF0ED84459D52C70494D74DDCC6F6
gvaZ1QnJf8FjjRDJ0cYusgpBgQ8r0NqEz39BooH6DtIrgX+WTeXuLSnjZDl35VCBjokvyjry+v0OkTT8FKpABA==",
        ));
        let MembershipDocument::V10(ms1) = ms1;

        let TransactionDocument::V10(tx1) = unwrap!(TransactionDocument::parse_from_raw_text(
            "Version: 10
Type: Transaction
Currency: g1
Blockstamp: 165645-000002D30130881939961A38D51CA233B3C696AA604439036DB1AAA4ED5046D2
Locktime: 0
Issuers:
51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2
Inputs:
1004:0:D:51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2:163766
1004:0:D:51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2:164040
1004:0:D:51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2:164320
1004:0:D:51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2:164584
1004:0:D:51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2:164849
1004:0:D:51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2:165118
1004:0:D:51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2:165389
Unlocks:
0:SIG(0)
1:SIG(0)
2:SIG(0)
3:SIG(0)
4:SIG(0)
5:SIG(0)
6:SIG(0)
Outputs:
7000:0:SIG(98wxzS683Tc1WWm1YxpL5WpxS7wBa1mZBccKSsYpaant)
28:0:SIG(51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2)
Comment: Panier mixte plus 40 pommes merci
7o/yIh0BNSAv5pNmHz04uUBl8TuP2s4HRFMtKeGFQfXNYJPUyJTP/dj6hdrgKtJkm5dCfbxT4KRy6wJf+dj1Cw==",
        ));

        let TransactionDocument::V10(tx2) = unwrap!(TransactionDocument::parse_from_raw_text(
            "Version: 10
Type: Transaction
Currency: g1
Blockstamp: 165645-000002D30130881939961A38D51CA233B3C696AA604439036DB1AAA4ED5046D2
Locktime: 0
Issuers:
3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX
Inputs:
1002:0:D:3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX:148827
1002:0:D:3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX:149100
1002:0:D:3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX:149370
1002:0:D:3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX:149664
1002:0:D:3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX:149943
1002:0:D:3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX:150222
Unlocks:
0:SIG(0)
1:SIG(0)
2:SIG(0)
3:SIG(0)
4:SIG(0)
5:SIG(0)
Outputs:
6000:0:SIG(AopwTfXhj8VqZReFJYGGWnoWnXNj3RgaqFcGGywXpZrD)
12:0:SIG(3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX)
Comment: En reglement de tes bons bocaux de fruits et legumes
nxr4exGrt16jteN9ZX3XZPP9l+X0OUbZ1o/QjE1hbWQNtVU3HhH9SJoEvNj2iVl3gCRr9u2OA9uj9vCyUDyjAg==
",
        ));

        let block_content = DubpBlockV10Content {
            version: 10,
            number: BlockNumber(165_647),
            pow_min: 90,
            time: 1_540_633_175,
            median_time: 1_540_627_811,
            members_count: 1402,
            monetary_mass: 386_008_811,
            unit_base: 0,
            issuers_count: 37,
            issuers_frame: 186,
            issuers_frame_var: 0,
            currency: CurrencyName(String::from("g1")),
            issuer: pk("A4pc9Uuk4NXkWG8CibicjjPpEPdiup1mhjMoRWUZsonq"),
            parameters: None,
            previous_hash: unwrap!(Hash::from_hex(
                "000003E78FA4133F2C13B416F330C8DFB5A41EB87E37190615DB334F2C914A51"
            )),
            previous_issuer: pk("8NmGZmGjL1LUgJQRg282yQF7KTdQuRNAg8QfSa2qvd65"),
            dividend: None,
            identities: vec![],
            joiners: vec![],
            actives: vec![ms1],
            leavers: vec![],
            revoked: vec![],
            excluded: vec![],
            certifications: vec![],
            transactions: vec![tx1, tx2],
        };
        let mut block = DubpBlockV10Builder::new(block_content).build_unchecked(DubpBlockV10AfterPowData {
            nonce: 10_300_000_090_296,
            signature: unwrap!(ed25519::Signature::from_base64("2Z/+9ADdZvHXs19YR8+qDzgfl8WJlBG5PcbFvBG9TOuUJbjAdxhcgxrFrSRIABGWcCrIgLkB805fZVLP8jOjBA==")),
            hash: BlockHash::default(),
        });
        // test inner_hash computation
        println!("{}", block.generate_compact_inner_text());
        assert!(block.verify_inner_hash().is_ok());
        assert_eq!(
            unwrap!(block.inner_hash).to_hex(),
            "3B49ECC1475549CFD94CA7B399311548A0FD0EC93C8EDD5670DAA5A958A41846"
        );
        // test generate_compact_inner_text()
        let block_compact_text = block.generate_compact_inner_text();
        assert_eq!(
            block_compact_text,
            "Version: 10\nType: Block\nCurrency: g1\nNumber: 165647\nPoWMin: 90\nTime: 1540633175\nMedianTime: 1540627811\nUnitBase: 0\nIssuer: A4pc9Uuk4NXkWG8CibicjjPpEPdiup1mhjMoRWUZsonq\nIssuersFrame: 186\nIssuersFrameVar: 0\nDifferentIssuersCount: 37\nPreviousHash: 000003E78FA4133F2C13B416F330C8DFB5A41EB87E37190615DB334F2C914A51\nPreviousIssuer: 8NmGZmGjL1LUgJQRg282yQF7KTdQuRNAg8QfSa2qvd65\nMembersCount: 1402\nIdentities:\nJoiners:\nActives:\n4VZkro3N7VonygybESHngKUABA6gSrbW77Ktb94zE969:gvaZ1QnJf8FjjRDJ0cYusgpBgQ8r0NqEz39BooH6DtIrgX+WTeXuLSnjZDl35VCBjokvyjry+v0OkTT8FKpABA==:165645-000002D30130881939961A38D51CA233B3C696AA604439036DB1AAA4ED5046D2:74077-0000022816648B2F7801E059F67CCD0C023FF0ED84459D52C70494D74DDCC6F6:piaaf31\nLeavers:\nRevoked:\nExcluded:\nCertifications:\nTransactions:\nTX:10:1:7:7:2:1:0\n165645-000002D30130881939961A38D51CA233B3C696AA604439036DB1AAA4ED5046D2\n51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2\n1004:0:D:51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2:163766\n1004:0:D:51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2:164040\n1004:0:D:51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2:164320\n1004:0:D:51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2:164584\n1004:0:D:51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2:164849\n1004:0:D:51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2:165118\n1004:0:D:51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2:165389\n0:SIG(0)\n1:SIG(0)\n2:SIG(0)\n3:SIG(0)\n4:SIG(0)\n5:SIG(0)\n6:SIG(0)\n7000:0:SIG(98wxzS683Tc1WWm1YxpL5WpxS7wBa1mZBccKSsYpaant)\n28:0:SIG(51EFVNZwpfmTXU7BSLpeh3PZFgfdmm5hq5MzCDopdH2)\nPanier mixte plus 40 pommes merci\n7o/yIh0BNSAv5pNmHz04uUBl8TuP2s4HRFMtKeGFQfXNYJPUyJTP/dj6hdrgKtJkm5dCfbxT4KRy6wJf+dj1Cw==\nTX:10:1:6:6:2:1:0\n165645-000002D30130881939961A38D51CA233B3C696AA604439036DB1AAA4ED5046D2\n3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX\n1002:0:D:3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX:148827\n1002:0:D:3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX:149100\n1002:0:D:3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX:149370\n1002:0:D:3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX:149664\n1002:0:D:3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX:149943\n1002:0:D:3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX:150222\n0:SIG(0)\n1:SIG(0)\n2:SIG(0)\n3:SIG(0)\n4:SIG(0)\n5:SIG(0)\n6000:0:SIG(AopwTfXhj8VqZReFJYGGWnoWnXNj3RgaqFcGGywXpZrD)\n12:0:SIG(3Uwq4qNp2A97P1XQueEBCxmnvgtAKMdfrEq6VB7Ph2qX)\nEn reglement de tes bons bocaux de fruits et legumes\nnxr4exGrt16jteN9ZX3XZPP9l+X0OUbZ1o/QjE1hbWQNtVU3HhH9SJoEvNj2iVl3gCRr9u2OA9uj9vCyUDyjAg==\n"
        );
        // Test signature validity
        assert!(block.verify_signature().is_ok());
        // Test hash computation
        block.hash = block.compute_hash();
        assert!(block.verify_hash().is_ok());
        assert_eq!(
            block.hash.0.to_hex(),
            "000002026E32A3D649B34968AAF9D03C4F19A5954229C54A801BBB1CD216B230"
        );
    }
}
