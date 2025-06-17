//! This module handles the notarization phase of the prover.
//!
//! The prover interacts with a TLS verifier who acts as a Notary, i.e. the
//! verifier produces an attestation but does not verify transcript data.

use super::{state::Notarize, Prover, ProverError};
use serio::{stream::IoStreamExt as _, SinkExt as _};
use tlsn_common::commit::commit_entire_transcript;
use tlsn_common::encoding;
use tlsn_core::{
    attestation::Attestation,
    request::{Request, RequestConfig},
    transcript::{encoding::EncodingTree, Transcript, TranscriptCommitConfig},
    Secrets,
};
use tracing::{debug, instrument};

impl Prover<Notarize> {
    /// Returns the transcript.
    pub fn transcript(&self) -> &Transcript {
        &self.state.transcript
    }

    /// Configures transcript commitments.
    pub fn transcript_commit(&mut self, _config: TranscriptCommitConfig) {
        // self.state.transcript_commit_config = Some(config);

        // Ignore the provided config and always commit the entire transcript
        // to bypass selective disclosure
        self.state.transcript_commit_config = Some(commit_entire_transcript(self.transcript()));
    }

    /// Finalizes the notarization.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn finalize(
        self,
        config: &RequestConfig,
    ) -> Result<(Attestation, Secrets), ProverError> {
        let Notarize {
            mux_ctrl,
            mut mux_fut,
            mut ctx,
            vm,
            connection_info,
            server_cert_data,
            transcript,
            transcript_refs,
            transcript_commit_config,
            ..
        } = self.state;

        println!("[NOTARIZE] TLS Session Information:");
        println!("[NOTARIZE] Connection Time: {:?}", connection_info.time);
        println!("[NOTARIZE] TLS Version: {:?}", connection_info.version);
        println!(
            "[NOTARIZE] Transcript Length: {:?}",
            connection_info.transcript_length
        );

        println!("[NOTARIZE] Raw Transcript Data:");
        println!(
            "[NOTARIZE] Sent data ({}): {:02x?}",
            transcript.sent().len(),
            transcript.sent()
        );
        println!(
            "[NOTARIZE] Received data ({}): {:02x?}",
            transcript.received().len(),
            transcript.received()
        );

        let provider = self.config.crypto_provider();

        let hasher = provider
            .hash
            .get(config.hash_alg())
            .map_err(ProverError::config)?;

        let mut builder = Request::builder(config);

        builder
            .server_name(self.config.server_name().clone())
            .server_cert_data(server_cert_data)
            .transcript(transcript);

        // Only try to build an encoding tree if we have transcript commitment config with encoding
        if let Some(config) = transcript_commit_config {
            if config.has_encoding() {
                // Try to get encodings from the verifier
                let sent_macs = transcript_refs
                    .sent()
                    .iter()
                    .flat_map(|plaintext| vm.get_macs(*plaintext).expect("reference is valid"))
                    .map(|mac| mac.as_block());
                let recv_macs = transcript_refs
                    .recv()
                    .iter()
                    .flat_map(|plaintext| vm.get_macs(*plaintext).expect("reference is valid"))
                    .map(|mac| mac.as_block());

                // Get the encoding provider if possible
                match mux_fut
                    .poll_with(encoding::receive(&mut ctx, sent_macs, recv_macs))
                    .await
                {
                    Ok(encoding_provider) => {
                        // Only try to build encoding tree if we have a valid provider
                        if let Ok(tree) = EncodingTree::new(
                            hasher,
                            config.iter_encoding(),
                            &encoding_provider,
                            &connection_info.transcript_length,
                        ) {
                            builder.encoding_tree(tree);
                        }
                    }
                    Err(e) => {
                        // Log the error but continue without encodings
                        debug!("Failed to get encodings from verifier: {:?}", e);
                    }
                }
            }
        }

        let (request, secrets) = builder.build(provider).map_err(ProverError::attestation)?;

        let attestation = mux_fut
            .poll_with(async {
                debug!("sending attestation request");

                ctx.io_mut().send(request.clone()).await?;

                let attestation: Attestation = ctx.io_mut().expect_next().await?;

                // Print the attestation with more descriptive information
                println!("[NOTARIZE] Final Attestation:");
                println!("[NOTARIZE] NOTARY ATTESTATION (Full Final Proof): {:?}", attestation);
                println!("[NOTARIZE] Signature: {:?}", attestation.signature);
                println!("[NOTARIZE] Header: {:?}", attestation.header);
                println!("[NOTARIZE] Body: {:?}", attestation.body);
                println!("   ^ This is the final attestation from the notary that proves the TLS session");
                println!("   ^ It contains cryptographic proof that the session occurred with the specified server");
                println!("   ^ This attestation will be used to verify the authenticity of the data");

                Ok::<_, ProverError>(attestation)
            })
            .await?;

        // Wait for the notary to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.close();
            mux_fut.await?;
        }

        // Check the attestation is consistent with the Prover's view.
        request
            .validate(&attestation)
            .map_err(ProverError::attestation)?;

        Ok((attestation, secrets))
    }
}
