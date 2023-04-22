use super::*;

impl ProofVerifier {
    /// Generalized function to support multiple revocation types
    /// This adds a generic credential as part of subproof request
    ///
    pub fn add_sub_proof_request_va(
        &mut self,
        sub_proof_request: &SubProofRequest,
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        credential_pub_key: &CredentialPublicKeyVA,
        rev_key_pub: Option<&RevocationKeyPublicVA>,
        rev_reg: Option<&RevocationRegistryVA>,
    ) -> UrsaCryptoResult<()> {
        ProofVerifier::_check_add_sub_proof_request_params_consistency(
            sub_proof_request,
            credential_schema,
        )?;

        let gen_rev_key_pub = match rev_key_pub.is_some() {
            true => Some(GenRevocationKeyPublic::VA(rev_key_pub.map(Clone::clone).unwrap())),
            false => None
        };

        let gen_rev_reg = match rev_reg.is_some() {
            true => Some(GenRevocationRegistry::VA(rev_reg.map(Clone::clone).unwrap())),
            false => None
        };

        self.gen_credentials.push(GenVerifiableCredential {
            pub_key: GenCredentialPublicKey::VA(credential_pub_key.try_clone()?),
            sub_proof_request: sub_proof_request.clone(),
            credential_schema: credential_schema.clone(),
            non_credential_schema: non_credential_schema.clone(),
            rev_key_pub: gen_rev_key_pub,
            rev_reg: gen_rev_reg,
        });

        Ok(())
    }

    /// Add a subproof request for cks credential
    /// wrapped in a generic credential.
    pub fn add_sub_proof_request_cks(
        &mut self,
        sub_proof_request: &SubProofRequest,
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        credential_pub_key: &CredentialPublicKey,
        rev_key_pub: Option<&RevocationKeyPublic>,
        rev_reg: Option<&RevocationRegistry>,
    ) -> UrsaCryptoResult<()> {
        ProofVerifier::_check_add_sub_proof_request_params_consistency(
            sub_proof_request,
            credential_schema,
        )?;

        let gen_rev_key_pub = match rev_key_pub.is_some() {
            true => Some(GenRevocationKeyPublic::CKS(rev_key_pub.map(Clone::clone).unwrap())),
            false => None
        };

        let gen_rev_reg = match rev_reg.is_some() {
            true => Some(GenRevocationRegistry::CKS(rev_reg.map(Clone::clone).unwrap())),
            false => None
        };

        self.gen_credentials.push(GenVerifiableCredential {
            pub_key: GenCredentialPublicKey::CKS(credential_pub_key.try_clone()?),
            sub_proof_request: sub_proof_request.clone(),
            credential_schema: credential_schema.clone(),
            non_credential_schema: non_credential_schema.clone(),
            rev_key_pub: gen_rev_key_pub,
            rev_reg: gen_rev_reg,
        });

        Ok(())
    }

    /// Add a subproof request for cks credential
    /// wrapped in a generic credential.
    pub fn add_sub_proof_request_generic(
        &mut self,
        sub_proof_request: &SubProofRequest,
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        credential_pub_key: &GenCredentialPublicKey,
        rev_key_pub: Option<&GenRevocationKeyPublic>,
        rev_reg: Option<&GenRevocationRegistry>,
    ) -> UrsaCryptoResult<()> {
        ProofVerifier::_check_add_sub_proof_request_params_consistency(
            sub_proof_request,
            credential_schema,
        )?;

        if let GenCredentialPublicKey::CKS(ref credential_public_key_cks) = credential_pub_key {
            let mut rev_public_key_cks: Option<&RevocationKeyPublic> = None;
            if rev_key_pub.is_some() {
                if let GenRevocationKeyPublic::CKS(ref rev_key_pub_cks) = rev_key_pub.unwrap() {
                    rev_public_key_cks = Some(rev_key_pub_cks);
                }
            }

            let mut rev_registry_cks: Option<&RevocationRegistry> = None;
            if rev_reg.is_some() {
                if let GenRevocationRegistry::CKS(ref rev_reg_cks) = rev_reg.unwrap() {
                    rev_registry_cks = Some(rev_reg_cks);
                }
            }

            return ProofVerifier::add_sub_proof_request_cks(
                self,
                sub_proof_request,
                credential_schema,
                non_credential_schema,
                credential_public_key_cks,
                rev_public_key_cks,
                rev_registry_cks
            );
        }

        if let GenCredentialPublicKey::VA(ref credential_public_key_va) = credential_pub_key {
            let mut rev_public_key_va: Option<&RevocationKeyPublicVA> = None;
            if rev_key_pub.is_some() {
                if let GenRevocationKeyPublic::VA(ref rev_key_pub_va) = rev_key_pub.unwrap() {
                    rev_public_key_va = Some(rev_key_pub_va);
                }
            }

            let mut rev_registry_va: Option<&RevocationRegistryVA> = None;
            if rev_reg.is_some() {
                if let GenRevocationRegistry::VA(ref rev_reg_va) = rev_reg.unwrap() {
                    rev_registry_va = Some(rev_reg_va);
                }
            }

            return ProofVerifier::add_sub_proof_request_va(
                self,
                sub_proof_request,
                credential_schema,
                non_credential_schema,
                credential_public_key_va,
                rev_public_key_va,
                rev_registry_va
            );
        }

        Err(err_msg(UrsaCryptoErrorKind::InvalidStructure, "Unsupported Revocation Type"))
    }

    /// Generic Verification Function
    ///
    ///
    pub fn verify_generic(&mut self, proof: &GenProof, nonce: &Nonce) -> UrsaCryptoResult<bool> {


        //ProofVerifier::_check_verify_params_consistency(&self.credentials, proof)?;

        let mut tau_list: Vec<Vec<u8>> = Vec::new();

        for idx in 0..proof.proofs.len() {
            let proof_item = &proof.proofs[idx];
            let credential = &self.gen_credentials[idx];
            let cred_primary_key = match &credential.pub_key {
                GenCredentialPublicKey::CKS(cred_pub_key_cks) => { &cred_pub_key_cks.p_key }
                GenCredentialPublicKey::VA(cred_pub_key_va) => { &cred_pub_key_va.p_key  }
            };



            if proof_item.non_revoc_proof.is_some() {
                if let (
                    Some(GenNonRevocProof::CKS(non_revoc_proof_cks)),
                    GenCredentialPublicKey::CKS(ref cred_public_key),
                    Some(GenRevocationKeyPublic::CKS(rev_pub_key_cks)),
                    Some(GenRevocationRegistry::CKS(rev_reg_cks))
                ) = (
                    proof_item.non_revoc_proof.as_ref(),
                    &credential.pub_key,
                    credential.rev_key_pub.as_ref(),
                    credential.rev_reg.as_ref()
                ) {
                    tau_list.extend_from_slice(
                        &ProofVerifier::_verify_non_revocation_proof(
                            cred_public_key.r_key.as_ref().unwrap(),
                            rev_reg_cks,
                            rev_pub_key_cks,
                            &proof.aggregated_proof.c_hash,
                            non_revoc_proof_cks,
                        )?.as_slice()?);
                }

                if let (
                    Some(GenNonRevocProof::VA(non_revoc_proof_va)),
                    GenCredentialPublicKey::VA(ref cred_public_key),
                    Some(GenRevocationKeyPublic::VA(rev_pub_key_va)),
                    Some(GenRevocationRegistry::VA(rev_reg_va))
                ) = (
                    proof_item.non_revoc_proof.as_ref(),
                    &credential.pub_key,
                    credential.rev_key_pub.as_ref(),
                    credential.rev_reg.as_ref()
                ) {
                    tau_list.extend_from_slice(
                        &ProofVerifier::_verify_non_revocation_proof_va(
                            cred_public_key.r_key.as_ref().unwrap(),
                            rev_reg_va,
                            rev_pub_key_va,
                            &proof.aggregated_proof.c_hash,
                            non_revoc_proof_va,
                        )?.as_slice()?);
                }


            } // end of revocation if block

            // Check that `m_hat`s of all common attributes are same. Also `m_hat` for each common attribute must be present in each sub proof
            let attr_names: Vec<String> = self
                .common_attributes
                .keys()
                .map(|s| s.to_string())
                .collect();
            for attr_name in attr_names {
                if proof_item.primary_proof.eq_proof.m.contains_key(&attr_name) {
                    let m_hat = &proof_item.primary_proof.eq_proof.m[&attr_name];
                    match self.common_attributes.entry(attr_name.clone()) {
                        Entry::Occupied(mut entry) => {
                            let x = entry.get_mut();
                            match x {
                                Some(v) => {
                                    if v != m_hat {
                                        return Err(err_msg(
                                            UrsaCryptoErrorKind::ProofRejected,
                                            format!("Blinded value for common attribute '{}' different across sub proofs", attr_name),
                                        ));
                                    }
                                }
                                // For first subproof
                                None => {
                                    *x = Some(m_hat.try_clone()?);
                                }
                            }
                        }
                        // Vacant is not possible because `attr_names` is constructed from keys of `self.common_attributes`
                        Entry::Vacant(_) => (),
                    }
                } else {
                    // `m_hat` for common attribute not present in sub proof
                    return Err(err_msg(
                        UrsaCryptoErrorKind::ProofRejected,
                        format!(
                            "Blinded value for common attribute '{}' not found in proof.m",
                            attr_name
                        ),
                    ));
                }
            }
            tau_list.append_vec(&ProofVerifier::_verify_primary_proof(
                cred_primary_key,
                &proof.aggregated_proof.c_hash,
                &proof_item.primary_proof,
                &credential.credential_schema,
                &credential.non_credential_schema,
                &credential.sub_proof_request,
            )?)?;
        }

        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&tau_list);
        values.extend_from_slice(&proof.aggregated_proof.c_list);

        values.push(nonce.to_bytes()?);



        let c_hver = get_hash_as_int(&values)?;

        info!(target: "anoncreds_service", "Verifier verify proof -> done");

        let valid = c_hver == proof.aggregated_proof.c_hash;

        trace!("ProofVerifier::verify: <<< valid: {:?}", valid);

        Ok(valid)
    }

    /// Add json proof request
    pub fn add_sub_proof_request_json(&mut self, request_json: &SubproofRequestSchema) -> Result<(), Box<dyn std::error::Error>> {
        let sub_proof_request_val:Value = serde_json::from_str(request_json.sub_proof_request.as_str()).unwrap();
        let credential_schema_val: Value = serde_json::from_str(request_json.credential_schema.as_str()).unwrap();
        let non_credential_schema_val: Value = serde_json::from_str(request_json.non_credential_schema.as_str()).unwrap();
        let credential_public_key_val: Value = serde_json::from_str(request_json.credential_public_key.as_str()).unwrap();
        let registry_public_key_val: Value = serde_json::from_str(request_json.registry_public_key.as_str()).unwrap();
        let revocation_registry_val: Value = serde_json::from_str(request_json.revocation_registry.as_str()).unwrap();


        // try to guess the type of credential public key and proceed thereafter
        let credential_public_key: Result<GenCredentialPublicKey, serde_json::error::Error> = serde_json::from_value(credential_public_key_val.clone());
        if credential_public_key.is_ok() {
            // new type public key, proceed to deserialize other types
            let sub_proof_request: SubProofRequest = serde_json::from_value(sub_proof_request_val)?;
            let credential_schema: CredentialSchema = serde_json::from_value(credential_schema_val)?;
            let non_credential_schema: NonCredentialSchema = serde_json::from_value(non_credential_schema_val)?;
            let registry_public_key: Option<GenRevocationKeyPublic> = serde_json::from_value(registry_public_key_val)?;
            let revocation_registry: Option<GenRevocationRegistry> = serde_json::from_value(revocation_registry_val)?;

            ProofVerifier::add_sub_proof_request_generic(
                self,
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &credential_public_key.unwrap(),
                registry_public_key.as_ref(),
                revocation_registry.as_ref()
            ).unwrap();

            return Ok(());

        } else {
            // old type, proceed to deserialize other types
            let credential_public_key: CredentialPublicKey = serde_json::from_value(credential_public_key_val).unwrap();
            let sub_proof_request: SubProofRequest = serde_json::from_value(sub_proof_request_val)?;
            let credential_schema: CredentialSchema = serde_json::from_value(credential_schema_val)?;
            let non_credential_schema: NonCredentialSchema = serde_json::from_value(non_credential_schema_val)?;
            let registry_public_key: Option<RevocationKeyPublic> = serde_json::from_value(registry_public_key_val)?;
            let revocation_registry: Option<RevocationRegistry> = serde_json::from_value(revocation_registry_val)?;
            ProofVerifier::add_sub_proof_request(
                self,
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &credential_public_key,
                registry_public_key.as_ref(),
                revocation_registry.as_ref()
            ).unwrap();

            return Ok(());

        }

    }

    /// Verify from stringified objects
    ///
    pub fn verify_json(&mut self, proof_json: &ProofSchema) -> Result<bool, Box<dyn std::error::Error>>{

        let proof: Result<GenProof, serde_json::error::Error> = serde_json::from_str(proof_json.proof.clone().as_str());
        let nonce: Nonce = serde_json::from_str(proof_json.nonce.clone().as_str()).unwrap();
        if proof.is_ok() {
            return Ok(ProofVerifier::verify_generic(self, &proof.unwrap(), &nonce).unwrap());
        } else {
            let proof: Proof = serde_json::from_str(proof_json.proof.as_str()).unwrap();
            return Ok(ProofVerifier::verify(self, &proof, &nonce).unwrap());
        }

        Ok(false)
    }

}




