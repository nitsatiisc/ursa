use cl::verifier::extension::verify_non_mem_witness;
use super::*;

impl Prover {
    /// ----------------------------------------------------------------------------------------------
    /// Functions to support additional revocation schemes in prover interface
    ///
    ///

    /// Generic credential blinding function
    pub fn blind_credential_secrets_generic(
        credential_pub_key: &GenCredentialPublicKey,
        credential_key_correctness_proof: &CredentialKeyCorrectnessProof,
        credential_values: &CredentialValues,
        credential_nonce: &Nonce,
    ) -> Result<
        (
            BlindedCredentialSecrets,
            CredentialSecretsBlindingFactors,
            BlindedCredentialSecretsCorrectnessProof,
        ),
        UrsaCryptoError,
    > {
        trace!(
            "Prover::blind_credential_secrets: >>> credential_pub_key: {:?}, \
             credential_key_correctness_proof: {:?}, \
             credential_values: {:?}, \
             credential_nonce: {:?}",
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce
        );

        match credential_pub_key {
            GenCredentialPublicKey::CKS(cred_pub_key_cks) => {
                Prover::blind_credential_secrets(cred_pub_key_cks, credential_key_correctness_proof, credential_values, credential_nonce)
            },
            GenCredentialPublicKey::VA(cred_pub_key_va) => {
                Prover::blind_credential_secrets_va(cred_pub_key_va, credential_key_correctness_proof, credential_values, credential_nonce)
            },
            _=> Err(err_msg(UrsaCryptoErrorKind::InvalidStructure, "Unrecognized revocation scheme"))
        }
    }

    /// Generic process signature
    pub fn process_credential_signature_generic(
        credential_signature: &mut GenCredentialSignature,
        credential_values: &CredentialValues,
        signature_correctness_proof: &SignatureCorrectnessProof,
        credential_secrets_blinding_factors: &CredentialSecretsBlindingFactors,
        credential_pub_key: &GenCredentialPublicKey,
        nonce: &Nonce,
        rev_key_pub: Option<&GenRevocationKeyPublic>,
        rev_reg: Option<&GenRevocationRegistry>,
        witness: Option<&GenWitness>,
    ) -> UrsaCryptoResult<()>
    {
        if let (
            GenCredentialSignature::CKS(mut cred_sig_cks),
            GenCredentialPublicKey::CKS(cred_pub_key_cks),
            GenRevocationKeyPublic::CKS(rev_key_pub_cks),
            GenRevocationRegistry::CKS(rev_reg_cks),

        ) = (
            credential_signature.try_clone()?,
            credential_pub_key,
            rev_key_pub.unwrap(),
            rev_reg.unwrap(),
        ) {
            Prover::process_credential_signature(
                &mut cred_sig_cks,
                credential_values,
                signature_correctness_proof,
                credential_secrets_blinding_factors,
                cred_pub_key_cks,
                nonce,
                Some(rev_key_pub_cks),
                Some(rev_reg_cks),
                Some(&witness.unwrap().clone().unwrap_cks().unwrap().clone()) // Clone to allow usage of unwrap_cks()
            ).unwrap();

            *credential_signature = GenCredentialSignature::CKS(cred_sig_cks);
            return Ok(());
        }

        if let (
            GenCredentialSignature::VA(mut cred_sig_va),
            GenCredentialPublicKey::VA(cred_pub_key_va),
            GenRevocationKeyPublic::VA(rev_key_pub_va),
            GenRevocationRegistry::VA(rev_reg_va),
        ) = (
            credential_signature.try_clone()?,
            credential_pub_key,
            rev_key_pub.unwrap(),
            rev_reg.unwrap(),
        ) {
            Prover::process_credential_signature_va(
                &mut cred_sig_va,
                credential_values,
                signature_correctness_proof,
                credential_secrets_blinding_factors,
                cred_pub_key_va,
                nonce,
                Some(rev_key_pub_va),
                Some(rev_reg_va),
                None
            ).unwrap();

            *credential_signature = GenCredentialSignature::VA(cred_sig_va);
            return Ok(());
        }

        Err(err_msg(UrsaCryptoErrorKind::InvalidStructure, "Unsupported revocation scheme"))
    }

    /// Blinding of credential secrets for VA revocation scheme
    pub fn blind_credential_secrets_va(
        credential_pub_key: &CredentialPublicKeyVA,
        credential_key_correctness_proof: &CredentialKeyCorrectnessProof,
        credential_values: &CredentialValues,
        credential_nonce: &Nonce,
    ) -> Result<
        (
            BlindedCredentialSecrets,
            CredentialSecretsBlindingFactors,
            BlindedCredentialSecretsCorrectnessProof,
        ),
        UrsaCryptoError,
    > {
        trace!(
            "Prover::blind_credential_secrets: >>> credential_pub_key: {:?}, \
             credential_key_correctness_proof: {:?}, \
             credential_values: {:?}, \
             credential_nonce: {:?}",
            credential_pub_key,
            credential_key_correctness_proof,
            credential_values,
            credential_nonce
        );
        Prover::_check_credential_key_correctness_proof(
            &credential_pub_key.p_key,
            credential_key_correctness_proof,
        )?;

        let blinded_primary_credential_secrets =
            Prover::_generate_blinded_primary_credential_secrets_factors(
                &credential_pub_key.p_key,
                credential_values,
            )?;

        /*
        // do not need this for VA revocation scheme
        let blinded_revocation_credential_secrets = match credential_pub_key.r_key {
            Some(ref r_pk) => Some(Prover::_generate_blinded_revocation_credential_secrets(
                r_pk,
            )?),
            _ => None,
        };
        */

        let blinded_credential_secrets_correctness_proof =
            Prover::_new_blinded_credential_secrets_correctness_proof(
                &credential_pub_key.p_key,
                &blinded_primary_credential_secrets,
                credential_nonce,
                credential_values,
            )?;

        let blinded_credential_secrets = BlindedCredentialSecrets {
            u: blinded_primary_credential_secrets.u,
            ur: PointG1::new_inf().ok(),
            hidden_attributes: blinded_primary_credential_secrets.hidden_attributes,
            committed_attributes: blinded_primary_credential_secrets.committed_attributes,
        };

        let credential_secrets_blinding_factors = CredentialSecretsBlindingFactors {
            v_prime: blinded_primary_credential_secrets.v_prime,
            vr_prime: GroupOrderElement::new().ok(),
        };

        trace!(
            "Prover::blind_credential_secrets: <<< blinded_credential_secrets: {:?}, \
             credential_secrets_blinding_factors: {:?}, \
             blinded_credential_secrets_correctness_proof: {:?},",
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof
        );

        Ok((
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ))
    }

    pub fn process_credential_signature_va(
        credential_signature: &mut CredentialSignatureVA,
        credential_values: &CredentialValues,
        signature_correctness_proof: &SignatureCorrectnessProof,
        credential_secrets_blinding_factors: &CredentialSecretsBlindingFactors,
        credential_pub_key: &CredentialPublicKeyVA,
        nonce: &Nonce,
        rev_key_pub: Option<&RevocationKeyPublicVA>,
        rev_reg: Option<&RevocationRegistryVA>,
        witness: Option<&WitnessVA>,
    ) -> UrsaCryptoResult<()> {
        trace!(
            "Prover::process_credential_signature: >>> credential_signature: {:?}, \
             credential_values: {:?}, \
             signature_correctness_proof: {:?}, \
             credential_secrets_blinding_factors: {:?}, \
             credential_pub_key: {:?}, \
             nonce: {:?}, \
             rev_key_pub: {:?}, \
             rev_reg: {:?}, \
             witness: {:?}",
            credential_signature,
            credential_values,
            signature_correctness_proof,
            credential_secrets_blinding_factors,
            credential_pub_key,
            nonce,
            rev_key_pub,
            rev_reg,
            witness
        );

        Prover::_process_primary_credential(
            &mut credential_signature.p_credential,
            &credential_secrets_blinding_factors.v_prime,
        )?;

        Prover::_check_signature_correctness_proof(
            &credential_signature.p_credential,
            credential_values,
            signature_correctness_proof,
            &credential_pub_key.p_key,
            nonce,
        )?;

        trace!("Prover::process_credential_signature: <<<");

        Ok(())
    }
}

impl ProofBuilder {

    /// Generic function to append a generic proof request
    /// The proof request can correspond to any of the supported
    /// revocation schemes. The function determines the type based
    /// on the credential signature and delegates to the appropriate
    /// specific function.
    pub fn add_sub_proof_request_generic(
        &mut self,
        sub_proof_request: &SubProofRequest,
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        credential_signature: &GenCredentialSignature,
        credential_values: &CredentialValues,
        credential_pub_key: &GenCredentialPublicKey,
        rev_reg: Option<&GenRevocationRegistry>,
        witness: Option<&GenWitness>,
    ) -> UrsaCryptoResult<()> {

        if let (
            GenCredentialSignature::CKS(ref cred_signature_cks),
            GenCredentialPublicKey::CKS(ref cred_pub_key_cks),
        ) = (
            credential_signature,
            credential_pub_key
        ) {
            let mut rev_reg_cks: Option<&RevocationRegistry> = None;
            let mut witness_cks: Option<&Witness> = None;

            if rev_reg.is_some() {
                if let GenRevocationRegistry::CKS(ref registry_cks) = rev_reg.unwrap() {
                    rev_reg_cks = Some(registry_cks);
                }
            }

            if witness.is_some() {
                if let GenWitness::CKS(ref witness_cks_ref) = witness.unwrap() {
                    witness_cks = Some(witness_cks_ref);
                }
            }

            return ProofBuilder::add_sub_proof_request_cks(
                self,
                sub_proof_request,
                credential_schema,
                non_credential_schema,
                cred_signature_cks,
                credential_values,
                cred_pub_key_cks,
                rev_reg_cks,
                witness_cks);
        }

        if let (
            GenCredentialSignature::VA(ref cred_signature_va),
            GenCredentialPublicKey::VA(ref cred_pub_key_va),
        ) = (
            credential_signature,
            credential_pub_key
        ) {
            let mut rev_reg_va: Option<&RevocationRegistryVA> = None;
            if rev_reg.is_some() {
                if let GenRevocationRegistry::VA(ref registry_va) = rev_reg.unwrap() {
                    rev_reg_va = Some(registry_va);
                }
            }

            return ProofBuilder::add_sub_proof_request_va(
                self,
                sub_proof_request,
                credential_schema,
                non_credential_schema,
                cred_signature_va,
                credential_values,
                cred_pub_key_va,
                rev_reg_va);
        }

        Err(err_msg(UrsaCryptoErrorKind::InvalidStructure, "Unsupported Revocation Type"))
    }

    /// The generic finalize proof function. It determines the type of each
    /// subproof, and appropriately calls the specific finalize function.
    pub fn finalize_generic(&self, nonce: &Nonce) -> UrsaCryptoResult<GenProof> {
        trace!("ProofBuilder::finalize: >>> nonce: {:?}", nonce);

        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&self.tau_list);
        values.extend_from_slice(&self.c_list);

        values.push(nonce.to_bytes()?);

        // In the anoncreds whitepaper, `challenge` is denoted by `c_h`
        let challenge = get_hash_as_int(&values)?;

        let mut proofs: Vec<GenSubProof> = Vec::new();

        for init_proof in self.gen_init_proofs.iter() {
            let mut non_revoc_proof: Option<GenNonRevocProof> = None;
            if let Some(ref non_revoc_init_proof) = init_proof.non_revoc_init_proof {
                if let GenNonRevocInitProof::VA(non_revoc_init_proof_va) = non_revoc_init_proof {
                    non_revoc_proof = Some(ProofBuilder::_finalize_non_revocation_proof_va(
                        non_revoc_init_proof_va,
                        &challenge,
                    )?);
                }

                if let GenNonRevocInitProof::CKS(ref non_revok_init_proof_cks) = non_revoc_init_proof {
                    non_revoc_proof = Some(
                        GenNonRevocProof::CKS(ProofBuilder::_finalize_non_revocation_proof(
                            non_revok_init_proof_cks,
                            &challenge
                        )?));
                }
            }

            let primary_proof = ProofBuilder::_finalize_primary_proof(
                &init_proof.primary_init_proof,
                &challenge,
                &init_proof.credential_schema,
                &init_proof.non_credential_schema,
                &init_proof.credential_values,
                &init_proof.sub_proof_request,
            )?;

            let proof = GenSubProof {
                primary_proof,
                non_revoc_proof,
            };
            proofs.push(proof);
        }

        let aggregated_proof = AggregatedProof {
            c_hash: challenge,
            c_list: self.c_list.clone(),
        };

        let proof = GenProof {
            proofs,
            aggregated_proof,
        };

        trace!("ProofBuilder::finalize: <<< proof: {:?}", proof);

        Ok(proof)
    }

    /// Add subproof request for CKS based credential
    pub fn add_sub_proof_request_cks(
        &mut self,
        sub_proof_request: &SubProofRequest,
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        credential_signature: &CredentialSignature,
        credential_values: &CredentialValues,
        credential_pub_key: &CredentialPublicKey,
        rev_reg: Option<&RevocationRegistry>,
        witness: Option<&Witness>,
    ) -> UrsaCryptoResult<()> {
        trace!(
            "ProofBuilder::add_sub_proof_request: >>> sub_proof_request: {:?}, \
             credential_schema: {:?}, \
             non_credential_schema: {:?}, \
             credential_signature: {:?}, \
             credential_values: {:?}, \
             credential_pub_key: {:?}, \
             rev_reg: {:?}, \
             witness: {:?}",
            sub_proof_request,
            credential_schema,
            non_credential_schema,
            credential_signature,
            credential_values,
            credential_pub_key,
            rev_reg,
            witness
        );
        ProofBuilder::_check_add_sub_proof_request_params_consistency(
            credential_values,
            sub_proof_request,
            credential_schema,
            non_credential_schema,
        )?;

        let mut non_revoc_init_proof = None;
        let mut m2_tilde: Option<BigNumber> = None;

        if let (&Some(ref r_cred), &Some(r_reg), &Some(ref r_pub_key), &Some(witness)) = (
            &credential_signature.r_credential,
            &rev_reg,
            &credential_pub_key.r_key,
            &witness,
        ) {
            let proof =
                ProofBuilder::_init_non_revocation_proof(r_cred, r_reg, r_pub_key, witness)?;

            self.c_list.extend_from_slice(&proof.as_c_list()?);
            self.tau_list.extend_from_slice(&proof.as_tau_list()?);
            m2_tilde = Some(group_element_to_bignum(&proof.tau_list_params.m2)?);
            non_revoc_init_proof = Some(GenNonRevocInitProof::CKS(proof));
        }

        let primary_init_proof = ProofBuilder::_init_primary_proof(
            &self.common_attributes,
            &credential_pub_key.p_key,
            &credential_signature.p_credential,
            credential_values,
            credential_schema,
            non_credential_schema,
            sub_proof_request,
            m2_tilde,
        )?;

        self.c_list
            .extend_from_slice(&primary_init_proof.as_c_list()?);
        self.tau_list
            .extend_from_slice(&primary_init_proof.as_tau_list()?);

        let init_proof = GenInitProof {
            primary_init_proof,
            non_revoc_init_proof,
            credential_values: credential_values.try_clone()?,
            sub_proof_request: sub_proof_request.clone(),
            credential_schema: credential_schema.clone(),
            non_credential_schema: non_credential_schema.clone(),
        };
        self.gen_init_proofs.push(init_proof);

        trace!("ProofBuilder::add_sub_proof_request: <<<");

        Ok(())
    }

    /// Add subproof request for VA based credential
    pub fn add_sub_proof_request_va(
        &mut self,
        sub_proof_request: &SubProofRequest,
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        credential_signature: &CredentialSignatureVA,
        credential_values: &CredentialValues,
        credential_pub_key: &CredentialPublicKeyVA,
        rev_reg: Option<&RevocationRegistryVA>,
    ) -> UrsaCryptoResult<()> {

        ProofBuilder::_check_add_sub_proof_request_params_consistency(
            credential_values,
            sub_proof_request,
            credential_schema,
            non_credential_schema,
        )?;

        let mut non_revoc_init_proof = None;
        let mut m2_tilde: Option<BigNumber> = None;

        if let (&Some(ref r_cred), &Some(r_reg), &Some(ref r_pub_key)) = (
            &credential_signature.r_credential,
            &rev_reg,
            &credential_pub_key.r_key,
        ) {

            let proof =
                ProofBuilder::_init_non_revocation_proof_va(r_cred, r_reg, r_pub_key)?;

            self.c_list.extend_from_slice(&proof.as_c_list()?);
            self.tau_list.extend_from_slice(&proof.as_tau_list()?);
            //m2_tilde = Some(BigNumber::from_dec("1")?);
            m2_tilde = BigNumber::from_hex(FieldElement::random().to_hex().as_str()).ok();
            non_revoc_init_proof = Some(GenNonRevocInitProof::VA(proof));
        }

        let primary_init_proof = ProofBuilder::_init_primary_proof(
            &self.common_attributes,
            &credential_pub_key.p_key,
            &credential_signature.p_credential,
            credential_values,
            credential_schema,
            non_credential_schema,
            sub_proof_request,
            m2_tilde,
        )?;

        self.c_list
            .extend_from_slice(&primary_init_proof.as_c_list()?);
        self.tau_list
            .extend_from_slice(&primary_init_proof.as_tau_list()?);

        let init_proof = GenInitProof {
            primary_init_proof,
            non_revoc_init_proof,
            credential_values: credential_values.try_clone()?,
            sub_proof_request: sub_proof_request.clone(),
            credential_schema: credential_schema.clone(),
            non_credential_schema: non_credential_schema.clone(),
        };
        self.gen_init_proofs.push(init_proof);

        trace!("ProofBuilder::add_sub_proof_request: <<<");

        Ok(())
    }

    /// initialize non-revocation proof for VA accumulator
    ///
    fn  _init_non_revocation_proof_va(
        r_cred: &NonRevocationCredentialSignatureVA,
        rev_reg: &RevocationRegistryVA,
        cred_rev_pub_key: &CredentialRevocationPublicKeyVA,
    ) -> UrsaCryptoResult<NonRevocInitProofVA> {
        trace!("ProofBuilder::_init_non_revocation_proof: >>> r_cred: {:?}, rev_reg: {:?}, cred_rev_pub_key: {:?}",
               r_cred, rev_reg, cred_rev_pub_key);

        // create params for C values
        let mut c_list_params = NonRevocProofXListVA {
            u: FieldElement::random(),
            v: FieldElement::zero(),      // adjust later to u^-1
            t: FieldElement::random(),
            d: FieldElement::from(r_cred.witness.d.clone()),
            d_dash: FieldElement::random(),     // adjust later to d+vt
            x: FieldElement::zero(),            // adjust later to -d
            beta: FieldElement::zero(),         // adjust later to x^-1
            y: r_cred.m2.clone(),
            r_u: FieldElement::random(),
            r_v: FieldElement::random(),
            r_t: FieldElement::random(),
            r_dash: FieldElement::random(),
            r_x: FieldElement::random(),
            r_beta: FieldElement::random()
        };

        c_list_params.x = c_list_params.d.clone().negation();
        c_list_params.v = c_list_params.u.clone().inverse();
        c_list_params.d_dash = c_list_params.d.clone() + (c_list_params.v.clone() * c_list_params.t.clone());
        c_list_params.beta = c_list_params.x.clone().inverse();
        c_list_params.r_t = c_list_params.r_x.clone() + c_list_params.r_dash.clone() -
            (c_list_params.t.clone() * c_list_params.r_v.clone());
        c_list_params.r_u = (c_list_params.u.clone() * c_list_params.r_v.clone()).negation();
        c_list_params.r_beta = (c_list_params.beta.clone() * c_list_params.r_x.clone()).negation();

        // compute C values
        let b = rev_reg.accum.clone() + (c_list_params.x.clone() * cred_rev_pub_key.p.clone());
        let c_dash = c_list_params.u.clone() * r_cred.witness.C.clone();
        let d_t = (c_list_params.u.clone() * b.clone()) - (c_list_params.t.clone() *cred_rev_pub_key.p.clone());
        let c_bar = (c_list_params.u.clone() * b.clone()) - (c_list_params.y.clone() * c_dash.clone());
        let c_v = (c_list_params.v.clone() * cred_rev_pub_key.x.clone()) + (c_list_params.r_v.clone()*cred_rev_pub_key.y.clone());
        let c_x = (c_list_params.x.clone() * cred_rev_pub_key.x.clone()) + (c_list_params.r_x.clone() * cred_rev_pub_key.y.clone());
        let c_d_dash = (c_list_params.d_dash.clone() * cred_rev_pub_key.x.clone()) + (c_list_params.r_dash.clone() * cred_rev_pub_key.y.clone());


        let mut c_list = NonRevocProofCListVA { c_dash, d_t, c_bar, c_v, c_x, c_d_dash };

        // sample params for T values
        let mut tau_list_params = NonRevocProofXListVA {
            u: FieldElement::random(),
            v: FieldElement::random(),
            t: FieldElement::random(),
            d: FieldElement::random(),
            d_dash: FieldElement::random(),
            x: FieldElement::random(),
            beta: FieldElement::random(),
            y: FieldElement::random(),
            r_u: FieldElement::random(),
            r_v: FieldElement::random(),
            r_t: FieldElement::random(),
            r_dash: FieldElement::random(),
            r_x: FieldElement::random(),
            r_beta: FieldElement::random()
        };

        // create T list values.
        let t1 = tau_list_params.t.clone() * cred_rev_pub_key.p.clone() + tau_list_params.y.clone() * c_list.c_dash.clone();
        let t2 = tau_list_params.d_dash.clone() * cred_rev_pub_key.p.clone() + tau_list_params.v.clone() * c_list.d_t.clone();
        let t3 = tau_list_params.v.clone()*cred_rev_pub_key.x.clone() + tau_list_params.r_v.clone()*cred_rev_pub_key.y.clone();
        let t4 = tau_list_params.d_dash.clone()*cred_rev_pub_key.x.clone() + tau_list_params.r_dash.clone()*cred_rev_pub_key.y.clone();
        let t5 = tau_list_params.x.clone()*cred_rev_pub_key.x.clone() + tau_list_params.r_x.clone()*cred_rev_pub_key.y.clone();
        let t6 = tau_list_params.t.clone()*c_list.c_v.clone() + tau_list_params.r_t.clone()*cred_rev_pub_key.y.clone();
        let t7 = tau_list_params.u.clone()*c_list.c_v.clone() + tau_list_params.r_u.clone()*cred_rev_pub_key.y.clone();
        let t8 = tau_list_params.beta.clone()*c_list.c_x.clone() + tau_list_params.r_beta.clone()*cred_rev_pub_key.y.clone();


        let tau_list = NonRevocProofTauListVA {t1, t2, t3, t4, t5, t6, t7, t8};

        let r_init_proof = NonRevocInitProofVA {
            c_list_params,
            tau_list_params,
            c_list,
            tau_list,
        };

        Ok(r_init_proof)
    }

    /// Finalization for VA accumulator based revocation proof
    fn _finalize_non_revocation_proof_va(
        init_proof: &NonRevocInitProofVA,
        c_h: &BigNumber,
    ) -> UrsaCryptoResult<GenNonRevocProof> {
        trace!(
            "ProofBuilder::_finalize_non_revocation_proof: >>> init_proof: {:?}, c_h: {:?}",
            init_proof,
            c_h
        );

        //@todo: Check if the challenge has fewer bytes than FieldElement_SIZE
        //let ch_num_z = FieldElement::from_bytes(&c_h.to_bytes()?).unwrap();
        let ch_num_z = bignum_to_field_element(c_h).unwrap();

        let mut x_list: Vec<FieldElement> = Vec::new();

        let u_hat = init_proof.tau_list_params.u.clone() + ch_num_z.clone() * init_proof.c_list_params.u.clone();
        let v_hat = init_proof.tau_list_params.v.clone() + ch_num_z.clone() * init_proof.c_list_params.v.clone();
        let t_hat = init_proof.tau_list_params.t.clone() + ch_num_z.clone() * init_proof.c_list_params.t.clone();
        let d_hat = init_proof.tau_list_params.d.clone() + ch_num_z.clone() * init_proof.c_list_params.d.clone();
        let d_dash_hat = init_proof.tau_list_params.d_dash.clone() + ch_num_z.clone() * init_proof.c_list_params.d_dash.clone();
        let x_hat = init_proof.tau_list_params.x.clone() + ch_num_z.clone() * init_proof.c_list_params.x.clone();
        let beta_hat = init_proof.tau_list_params.beta.clone() + ch_num_z.clone() * init_proof.c_list_params.beta.clone();
        let y_hat = init_proof.tau_list_params.y.clone() - ch_num_z.clone() * init_proof.c_list_params.y.clone();
        let r_u_hat = init_proof.tau_list_params.r_u.clone() + ch_num_z.clone() * init_proof.c_list_params.r_u.clone();
        let r_v_hat = init_proof.tau_list_params.r_v.clone() + ch_num_z.clone() * init_proof.c_list_params.r_v.clone();
        let r_t_hat = init_proof.tau_list_params.r_t.clone() + ch_num_z.clone() * init_proof.c_list_params.r_t.clone();
        let r_dash_hat = init_proof.tau_list_params.r_dash.clone() + ch_num_z.clone() * init_proof.c_list_params.r_dash.clone();
        let r_x_hat = init_proof.tau_list_params.r_x.clone() + ch_num_z.clone() * init_proof.c_list_params.r_x.clone();
        let r_beta_hat = init_proof.tau_list_params.r_beta.clone() + ch_num_z.clone() * init_proof.c_list_params.r_beta.clone();



        x_list.extend_from_slice(&[u_hat, v_hat, t_hat, d_hat, d_dash_hat, x_hat, beta_hat, y_hat, r_u_hat,
            r_v_hat, r_t_hat, r_dash_hat, r_x_hat, r_beta_hat]);

        let non_revoc_proof = NonRevocProofVA {
            x_list: NonRevocProofXListVA::from_list(x_list.as_slice()),
            c_list: init_proof.c_list.clone(),
        };

        trace!(
            "ProofBuilder::_finalize_non_revocation_proof: <<< non_revoc_proof: {:?}",
            non_revoc_proof
        );

        Ok(GenNonRevocProof::VA(non_revoc_proof))
    }

}