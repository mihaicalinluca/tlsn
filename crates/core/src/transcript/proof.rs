//! Transcript proofs.

use rangeset::ToRangeSet;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt};

use crate::{
    attestation::Body,
    index::Index,
    transcript::{
        commit::{TranscriptCommitmentKind, MAX_TOTAL_COMMITTED_DATA},
        encoding::{EncodingProof, EncodingProofError, EncodingTree},
        hash::{PlaintextHashProof, PlaintextHashProofError, PlaintextHashSecret},
        Direction, Idx, PartialTranscript, Transcript,
    },
    CryptoProvider,
};

/// Default commitment kinds in order of preference for building transcript
/// proofs.
const DEFAULT_COMMITMENT_KINDS: &[TranscriptCommitmentKind] = &[TranscriptCommitmentKind::Encoding];

/// Proof of the contents of a transcript.
#[derive(Clone, Serialize, Deserialize)]
pub struct TranscriptProof {
    encoding_proof: Option<EncodingProof>,
    hash_proofs: Vec<PlaintextHashProof>,
}

opaque_debug::implement!(TranscriptProof);

impl TranscriptProof {
    /// Verifies the proof.
    ///
    /// Returns a partial transcript of authenticated data.
    ///
    /// # Arguments
    ///
    /// * `provider` - The crypto provider to use for verification.
    /// * `attestation_body` - The attestation body to verify against.
    pub fn verify_with_provider(
        self,
        provider: &CryptoProvider,
        attestation_body: &Body,
    ) -> Result<PartialTranscript, TranscriptProofError> {
        let info = attestation_body.connection_info();

        let mut transcript = PartialTranscript::new(
            info.transcript_length.sent as usize,
            info.transcript_length.received as usize,
        );

        // Verify encoding proof.
        if let Some(proof) = self.encoding_proof {
            let commitment = attestation_body.encoding_commitment().ok_or_else(|| {
                TranscriptProofError::new(
                    ErrorKind::Encoding,
                    "contains an encoding proof but attestation is missing encoding commitment",
                )
            })?;
            let seq = proof.verify_with_provider(provider, &info.transcript_length, commitment)?;
            transcript.union_transcript(&seq);
        }

        // Verify hash openings.
        let mut total_opened = 0u128;

        for proof in self.hash_proofs {
            let commitment = attestation_body
                .plaintext_hashes()
                .get_by_field_id(proof.commitment_id())
                .map(|field| &field.data)
                .ok_or_else(|| {
                    TranscriptProofError::new(
                        ErrorKind::Hash,
                        format!("contains a hash opening but attestation is missing corresponding commitment (id: {})", proof.commitment_id()),
                    )
                })?;

            // Make sure the amount of data being proved is bounded.
            total_opened += commitment.idx.len() as u128;
            if total_opened > MAX_TOTAL_COMMITTED_DATA as u128 {
                return Err(TranscriptProofError::new(
                    ErrorKind::Hash,
                    "exceeded maximum allowed data",
                ))?;
            }

            let (direction, seq) = proof.verify(&provider.hash, commitment)?;
            transcript.union_subsequence(direction, &seq);
        }

        Ok(transcript)
    }
}

/// Error for [`TranscriptProof`].
#[derive(Debug, thiserror::Error)]
pub struct TranscriptProofError {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl TranscriptProofError {
    fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }
}

#[derive(Debug)]
enum ErrorKind {
    Encoding,
    Hash,
}

impl fmt::Display for TranscriptProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("transcript proof error: ")?;

        match self.kind {
            ErrorKind::Encoding => f.write_str("encoding error")?,
            ErrorKind::Hash => f.write_str("hash error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

impl From<EncodingProofError> for TranscriptProofError {
    fn from(e: EncodingProofError) -> Self {
        TranscriptProofError::new(ErrorKind::Encoding, e)
    }
}

impl From<PlaintextHashProofError> for TranscriptProofError {
    fn from(e: PlaintextHashProofError) -> Self {
        TranscriptProofError::new(ErrorKind::Hash, e)
    }
}

/// Union of committed ranges of all commitment kinds.
#[derive(Debug)]
struct CommittedIdx {
    sent: Idx,
    recv: Idx,
}

impl CommittedIdx {
    fn new(
        encoding_tree: Option<&EncodingTree>,
        plaintext_hashes: &Index<PlaintextHashSecret>,
    ) -> Self {
        let mut sent = plaintext_hashes.idx(Direction::Sent).clone();
        let mut recv = plaintext_hashes.idx(Direction::Received).clone();

        if let Some(tree) = encoding_tree {
            sent.union_mut(tree.idx(Direction::Sent));
            recv.union_mut(tree.idx(Direction::Received));
        }

        Self { sent, recv }
    }

    fn idx(&self, direction: &Direction) -> &Idx {
        match direction {
            Direction::Sent => &self.sent,
            Direction::Received => &self.recv,
        }
    }
}

/// Union of ranges to reveal.
#[derive(Clone, Debug, PartialEq)]
struct QueryIdx {
    sent: Idx,
    recv: Idx,
}

impl QueryIdx {
    fn new() -> Self {
        Self {
            sent: Idx::empty(),
            recv: Idx::empty(),
        }
    }

    fn union(&mut self, direction: &Direction, other: &Idx) {
        match direction {
            Direction::Sent => self.sent.union_mut(other),
            Direction::Received => self.recv.union_mut(other),
        }
    }
}

impl std::fmt::Display for QueryIdx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sent: {}, received: {}", self.sent, self.recv)
    }
}

/// Builder for [`TranscriptProof`].
#[derive(Debug)]
pub struct TranscriptProofBuilder<'a> {
    /// Commitment kinds in order of preference for building transcript proofs.
    commitment_kinds: Vec<TranscriptCommitmentKind>,
    transcript: &'a Transcript,
    encoding_tree: Option<&'a EncodingTree>,
    #[allow(dead_code)]
    plaintext_hashes: &'a Index<PlaintextHashSecret>,
    committed_idx: CommittedIdx,
    query_idx: QueryIdx,
}

impl<'a> TranscriptProofBuilder<'a> {
    /// Creates a new proof config builder.
    pub(crate) fn new(
        transcript: &'a Transcript,
        encoding_tree: Option<&'a EncodingTree>,
        plaintext_hashes: &'a Index<PlaintextHashSecret>,
    ) -> Self {
        Self {
            commitment_kinds: DEFAULT_COMMITMENT_KINDS.to_vec(),
            transcript,
            encoding_tree,
            plaintext_hashes,
            committed_idx: CommittedIdx::new(encoding_tree, plaintext_hashes),
            query_idx: QueryIdx::new(),
        }
    }

    /// Sets the commitment kinds in order of preference for building transcript
    /// proofs, i.e. the first one is the most preferred.
    pub fn commitment_kinds(&mut self, kinds: &[TranscriptCommitmentKind]) -> &mut Self {
        if !kinds.is_empty() {
            // Removes duplicates from `kinds` while preserving its order.
            let mut seen = HashSet::new();
            self.commitment_kinds = kinds
                .iter()
                .filter(|&kind| seen.insert(kind))
                .cloned()
                .collect();
        }
        self
    }

    /// Reveals the given ranges in the transcript.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges to reveal.
    /// * `direction` - The direction of the transcript.
    pub fn reveal(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
        direction: Direction,
    ) -> Result<&mut Self, TranscriptProofBuilderError> {
        let idx = Idx::new(ranges.to_range_set());

        if idx.end() > self.transcript.len_of_direction(direction) {
            return Err(TranscriptProofBuilderError::new(
                BuilderErrorKind::Index,
                format!(
                    "range is out of bounds of the transcript ({}): {} > {}",
                    direction,
                    idx.end(),
                    self.transcript.len_of_direction(direction)
                ),
            ));
        }

        if idx.is_subset(self.committed_idx.idx(&direction)) {
            self.query_idx.union(&direction, &idx);
        } else {
            let missing = idx.difference(self.committed_idx.idx(&direction));
            return Err(TranscriptProofBuilderError::new(
                BuilderErrorKind::MissingCommitment,
                format!("commitment is missing for ranges in {direction} transcript: {missing}"),
            ));
        }
        Ok(self)
    }

    /// Reveals the given ranges in the sent transcript.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges to reveal.
    pub fn reveal_sent(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, TranscriptProofBuilderError> {
        self.reveal(ranges, Direction::Sent)
    }

    /// Reveals the given ranges in the received transcript.
    ///
    /// # Arguments
    ///
    /// * `ranges` - The ranges to reveal.
    pub fn reveal_recv(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, TranscriptProofBuilderError> {
        self.reveal(ranges, Direction::Received)
    }

    /// Builds the transcript proof.
    pub fn build(self) -> Result<TranscriptProof, TranscriptProofBuilderError> {
        let mut transcript_proof = TranscriptProof {
            encoding_proof: None,
            hash_proofs: Vec::new(),
        };

        // For encoding commitments
        if self
            .commitment_kinds
            .contains(&TranscriptCommitmentKind::Encoding)
        {
            if let Some(encoding_tree) = self.encoding_tree {
                // Get all available indices from the encoding tree
                let dir_idxs = encoding_tree.transcript_indices().collect::<Vec<_>>();

                // If there are indices, generate a proof
                if !dir_idxs.is_empty() {
                    transcript_proof.encoding_proof = Some(
                        encoding_tree
                            .proof(self.transcript, dir_idxs.into_iter())
                            .expect("tree should contain all its indices"),
                    );
                }
            }
        }

        Ok(transcript_proof)
    }
}

/// Error for [`TranscriptProofBuilder`].
#[derive(Debug, thiserror::Error)]
pub struct TranscriptProofBuilderError {
    kind: BuilderErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl TranscriptProofBuilderError {
    fn new<E>(kind: BuilderErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }
}

#[derive(Debug, PartialEq)]
enum BuilderErrorKind {
    Index,
    MissingCommitment,
}

impl fmt::Display for TranscriptProofBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("transcript proof builder error: ")?;

        match &self.kind {
            BuilderErrorKind::Index => f.write_str("index error")?,
            BuilderErrorKind::MissingCommitment => f.write_str("commitment error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}
