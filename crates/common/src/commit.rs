//! Plaintext commitment and proof of encryption.

use mpz_memory_core::binary::Binary;
use mpz_vm_core::Vm;
use tlsn_core::transcript::{Transcript, TranscriptCommitConfig, TranscriptCommitConfigBuilder};

use crate::{transcript::Record, zk_aes::AesCtr};

/// Commits the plaintext of the provided records, returning a proof of
/// encryption.
///
/// Writes the plaintext VM reference to the provided records.
pub fn commit_records<'record>(
    _vm: &mut dyn Vm<Binary>,
    aes: &mut AesCtr,
    records: impl IntoIterator<Item = &'record mut Record>,
) -> Result<RecordProof, RecordProofError> {
    let mut ciphertexts = Vec::new();
    for record in records {
        if record.plaintext_ref.is_some() {
            return Err(ErrorRepr::PlaintextRefAlreadySet.into());
        }

        let ciphertext = aes.encrypt(&record.ciphertext);

        ciphertexts.push((ciphertext, record.ciphertext.clone()));
    }

    Ok(RecordProof { ciphertexts })
}

/// Commits the entire transcript for both sent and received data
/// This bypasses selective disclosure by including everything
pub fn commit_entire_transcript(transcript: &Transcript) -> TranscriptCommitConfig {
    // Print the actual transcript data with more descriptive information
    if std::env::var("VERBOSE").is_ok_and(|e| e.to_string() == "true") {
        println!(
            "[PROVER COMMIT] OUTGOING TLS DATA (Client to Server): {:02x?}",
            transcript.sent()
        );
    } else {
        println!("[PROVER COMMIT] OUTGOING TLS DATA (Client to Server) - hidden",);
    }
    println!("   ^ This is the data sent FROM the client TO the server during the TLS session");
    println!("   ^ Size: {} bytes", transcript.sent().len());

    if std::env::var("VERBOSE").is_ok_and(|e| e.to_string() == "true") {
        println!(
            "[PROVER COMMIT] INCOMING TLS DATA (Server to Client): {:02x?}",
            transcript.received()
        );
    } else {
        println!("[PROVER COMMIT] INCOMING TLS DATA (Server to Client) - hidden",);
    }
    println!("   ^ This is the data received BY the client FROM the server during the TLS session");
    println!("   ^ Size: {} bytes", transcript.received().len());
    println!("   ^ This contains the HTTP response we're proving");

    println!(
        "[PROVER COMMIT] Creating commitment for entire transcript without selective disclosure"
    );

    let mut builder = TranscriptCommitConfigBuilder::new(transcript);

    // Commit the entire sent data
    if transcript.sent().len() > 0 {
        builder.commit_sent(&(0..transcript.sent().len())).unwrap();
    }

    // Commit the entire received data
    if transcript.received().len() > 0 {
        builder
            .commit_recv(&(0..transcript.received().len()))
            .unwrap();
    }

    builder.build().unwrap()
}

/// Proof of encryption.
#[derive(Debug)]
#[must_use]
#[allow(clippy::type_complexity)]
pub struct RecordProof {
    ciphertexts: Vec<(Vec<u8>, Vec<u8>)>,
}

impl RecordProof {
    /// Verifies the proof.
    pub fn verify(self) -> Result<(), RecordProofError> {
        let Self { ciphertexts } = self;

        for (ciphertext, expected) in ciphertexts {
            if ciphertext != expected {
                return Err(ErrorRepr::InvalidCiphertext.into());
            }
        }

        Ok(())
    }
}

/// Error for [`RecordProof`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct RecordProofError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("record proof error: {0}")]
enum ErrorRepr {
    #[error("plaintext reference is already set")]
    PlaintextRefAlreadySet,
    #[error("ciphertext does not match expected")]
    InvalidCiphertext,
}
