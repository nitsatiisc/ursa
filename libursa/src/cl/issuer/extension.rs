use super::*;

impl Issuer {
    /// This extension module contains extensions to the issuer module to support
    /// VA-accumulator based revocation, and to implement a generic interface
    /// providing unified access to both the CKS and VA based revocation.
    /// The generic functions mimic the signature of existing functions as much as possible.

    /// Generic function to create new credential definition.
    /// Delegates to the appropriate credential definition function based on the
    /// requested revocation scheme.
    pub fn new_credential_def_generic(
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        support_revocation: bool,
        revocation_method: RevocationMethod
    ) -> UrsaCryptoResult<(
        GenCredentialPublicKey,
        GenCredentialPrivateKey,
        CredentialKeyCorrectnessProof
    )> {

        match revocation_method {
            RevocationMethod::CKS => {
                let (credential_public_key, credential_private_key, credential_correctness_proof) =
                    Issuer::new_credential_def(credential_schema, non_credential_schema,support_revocation)?;
                Ok((GenCredentialPublicKey::CKS(credential_public_key), GenCredentialPrivateKey::CKS(credential_private_key), credential_correctness_proof))
            },
            RevocationMethod::VA => {
                let (credential_public_key, credential_private_key, credential_correctness_proof) =
                    Issuer::new_credential_def_va(credential_schema, non_credential_schema, support_revocation)?;
                Ok((GenCredentialPublicKey::VA(credential_public_key), GenCredentialPrivateKey::VA(credential_private_key), credential_correctness_proof))
            },
            _ => {
                Err(err_msg(UrsaCryptoErrorKind::InvalidStructure, "Invalid revocation type"))
            }
        }
    }

    /// Generic function to create new revocation registry
    /// Delegates to appropriate revocation scheme based on
    /// the type of credential_public_key.
    pub fn new_revocation_registry_generic(
        cred_pub_key: &GenCredentialPublicKey,
        max_cred_num: u32,
        issuance_by_default: bool,
        max_batch_size: u32
    ) -> UrsaCryptoResult<(
        GenRevocationKeyPublic,
        GenRevocationKeyPrivate,
        GenRevocationRegistry,
        AuxiliaryParams,
    )> {

        match cred_pub_key {
            GenCredentialPublicKey::CKS(cred_pub_key_cks) => {
                let (reg_key_public, reg_key_private, rev_reg, aux_params) =
                    Issuer::new_revocation_registry_def(
                        &cred_pub_key_cks,
                        max_cred_num,
                        issuance_by_default
                    )?;
                Ok((GenRevocationKeyPublic::CKS(reg_key_public),
                    GenRevocationKeyPrivate::CKS(reg_key_private),
                    GenRevocationRegistry::CKS(rev_reg),
                    AuxiliaryParams::CKS(aux_params)))
            },
            GenCredentialPublicKey::VA(cred_pub_key_va) => {
                let (reg_key_public, reg_key_private, rev_reg, aux_params) =
                    Issuer::new_revocation_registry_def_va(
                        &cred_pub_key_va,
                        max_cred_num,
                        max_batch_size
                    )?;
                Ok((GenRevocationKeyPublic::VA(reg_key_public),
                    GenRevocationKeyPrivate::VA(reg_key_private),
                    GenRevocationRegistry::VA(rev_reg),
                    AuxiliaryParams::VA(aux_params)
                ))
            },
            _ => Err(err_msg(UrsaCryptoErrorKind::InvalidStructure, "Invalid Credential Public Key"))
        }
    }

    /// Create credential definition for VA revocation scheme.
    pub fn new_credential_def_va(
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        support_revocation: bool
    ) -> UrsaCryptoResult<(
        CredentialPublicKeyVA,
        CredentialPrivateKeyVA,
        CredentialKeyCorrectnessProof
    )> {

        let (p_pub_key, p_priv_key, p_key_meta) =
            Issuer::_new_credential_primary_keys(credential_schema, non_credential_schema)?;

        // change this to generate VA keys
        let r_pub_key: Option<CredentialRevocationPublicKeyVA> = if support_revocation {
            Some(Issuer::_new_credential_revocation_keys_va()?)
        } else {
            None
        };

        let cred_key_correctness_proof = Issuer::_new_credential_key_correctness_proof(
            &p_pub_key,
            &p_priv_key,
            &p_key_meta,
        )?;

        let cred_pub_key = CredentialPublicKeyVA {
            p_key: p_pub_key,
            r_key: r_pub_key,
        };
        let cred_priv_key = CredentialPrivateKeyVA {
            p_key: p_priv_key
        };

        Ok((cred_pub_key, cred_priv_key, cred_key_correctness_proof))
    }

    pub fn sign_credential_with_revoc_generic<RTA>(
        prover_id: &str,
        blinded_credential_secrets: &BlindedCredentialSecrets,
        blinded_credential_secrets_correctness_proof: &BlindedCredentialSecretsCorrectnessProof,
        credential_nonce: &Nonce,
        credential_issuance_nonce: &Nonce,
        credential_values: &CredentialValues,
        credential_pub_key: &GenCredentialPublicKey,
        credential_priv_key: &GenCredentialPrivateKey,
        rev_idx: u32,
        max_cred_num: u32,
        issuance_by_default: bool,
        rev_reg:&mut GenRevocationRegistry,
        reg_priv_key: &GenRevocationKeyPrivate,
        rev_tails_accessor: &RTA,
    ) -> UrsaCryptoResult<(
        GenCredentialSignature,
        SignatureCorrectnessProof,
        Option<GenRevocationRegistryDelta>
    )>
        where RTA: RevocationTailsAccessor
    {
        if let (
            GenCredentialPublicKey::CKS(cred_pub_key),
            GenCredentialPrivateKey::CKS(cred_priv_key),
            GenRevocationRegistry::CKS(ref mut revoc_reg),
            GenRevocationKeyPrivate::CKS(rev_private_key)
        ) = (credential_pub_key, credential_priv_key, rev_reg.clone(), reg_priv_key) {
            // delegate to CKS function
            if let Ok((cred_signature, signature_correctness_proof, rev_reg_delta)) = Issuer::sign_credential_with_revoc(
                prover_id,
                blinded_credential_secrets,
                blinded_credential_secrets_correctness_proof,
                credential_nonce,
                credential_issuance_nonce,
                credential_values,
                cred_pub_key,
                cred_priv_key,
                rev_idx,
                max_cred_num,
                issuance_by_default,
                revoc_reg,
                rev_private_key,
                rev_tails_accessor
            ) {
                //rev_reg.clone_from(&GenRevocationRegistry::CKS(revoc_reg));

                return if rev_reg_delta.is_some() {
                    Ok((
                        GenCredentialSignature::CKS(cred_signature),
                        signature_correctness_proof,
                        Some(GenRevocationRegistryDelta::CKS(rev_reg_delta.unwrap())
                        )))
                } else {
                    Ok((
                        GenCredentialSignature::CKS(cred_signature),
                        signature_correctness_proof,
                        None,
                    ))
                }
            }

        }

        if let (
            GenCredentialPublicKey::VA(cred_pub_key),
            GenCredentialPrivateKey::VA(cred_priv_key),
            GenRevocationRegistry::VA(ref mut revoc_reg),
            GenRevocationKeyPrivate::VA(rev_private_key)
        ) = (credential_pub_key, credential_priv_key, rev_reg.clone(), reg_priv_key) {
            // delegat to VA function
            if let Ok((cred_signature, signature_correctness_proof, rev_reg_delta)) = Issuer::sign_credential_with_revoc_va(
                prover_id,
                blinded_credential_secrets,
                blinded_credential_secrets_correctness_proof,
                credential_nonce,
                credential_issuance_nonce,
                credential_values,
                cred_pub_key,
                cred_priv_key,
                rev_idx,
                max_cred_num,
                issuance_by_default,
                revoc_reg,
                rev_private_key
            ) {
                //rev_reg.clone_from(&GenRevocationRegistry::VA(revoc_reg));
                return Ok((GenCredentialSignature::VA(cred_signature), signature_correctness_proof, None));
            }
        }

        Err(err_msg(UrsaCryptoErrorKind::InvalidStructure, "Not implemented"))
    }


    pub fn sign_credential_with_revoc_va(
        prover_id: &str,
        blinded_credential_secrets: &BlindedCredentialSecrets,
        blinded_credential_secrets_correctness_proof: &BlindedCredentialSecretsCorrectnessProof,
        credential_nonce: &Nonce,
        credential_issuance_nonce: &Nonce,
        credential_values: &CredentialValues,
        credential_pub_key: &CredentialPublicKeyVA,
        credential_priv_key: &CredentialPrivateKeyVA,
        rev_idx: u32,
        max_cred_num: u32,
        issuance_by_default: bool,
        rev_reg: &RevocationRegistryVA,
        rev_key_priv: &RevocationKeyPrivateVA,
    ) -> UrsaCryptoResult<(
        CredentialSignatureVA,
        SignatureCorrectnessProof,
        Option<RevocationRegistryDeltaVA>,
    )>

    {
        trace!("Issuer::sign_credential: >>> prover_id: {:?}, blinded_credential_secrets: {:?}, blinded_credential_secrets_correctness_proof: {:?},\
        credential_nonce: {:?}, credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}, \
        rev_idx: {:?}, max_cred_num: {:?}, rev_reg: {:?}, rev_key_priv: {:?}",
               prover_id, blinded_credential_secrets, blinded_credential_secrets_correctness_proof, credential_nonce, secret!(credential_values), credential_issuance_nonce,
               credential_pub_key, secret!(credential_priv_key), secret!(rev_idx), max_cred_num, rev_reg, secret!(rev_key_priv));

        Issuer::_check_blinded_credential_secrets_correctness_proof(
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
            &credential_pub_key.p_key,
        )?;

        // In the anoncreds whitepaper, `credential context` is denoted by `m2`
        let cred_context = Issuer::_gen_credential_context(prover_id, Some(rev_idx))?;

        let (p_cred, q) = Issuer::_new_primary_credential_generic(
            &cred_context,
            &credential_pub_key.p_key,
            &credential_priv_key.p_key,
            blinded_credential_secrets,
            credential_values,
        )?;


        let va_registry = VARegistry::new(&rev_reg);

        let r_cred = Issuer::_new_non_revocation_credential_va(
            rev_idx,
            &credential_pub_key.r_key.clone().unwrap(),
            &rev_key_priv,
            &va_registry
        );


        let cred_signature = CredentialSignatureVA {
            p_credential: p_cred,
            r_credential: r_cred.ok(),
        };

        let signature_correctness_proof = Issuer::_new_signature_correctness_proof(
            &credential_pub_key.p_key,
            &credential_priv_key.p_key,
            &cred_signature.p_credential,
            &q,
            credential_issuance_nonce,
        )?;

        trace!("Issuer::sign_credential: <<< cred_signature: {:?}, signature_correctness_proof: {:?}",
               secret!(&cred_signature), signature_correctness_proof);


        Ok((cred_signature, signature_correctness_proof, None))
    }


    fn _new_primary_credential_generic(
        credential_context: &BigNumber,
        cred_pub_key: &CredentialPrimaryPublicKey,
        cred_priv_key: &CredentialPrimaryPrivateKey,
        blinded_credential_secrets: &BlindedCredentialSecrets,
        cred_values: &CredentialValues,
    ) -> UrsaCryptoResult<(PrimaryCredentialSignature, BigNumber)> {
        trace!("Issuer::_new_primary_credential: >>> credential_context: {:?}, cred_pub_key: {:?}, cred_priv_key: {:?}, blinded_ms: {:?},\
         cred_values: {:?}", secret!(credential_context), cred_pub_key, secret!(cred_priv_key), blinded_credential_secrets, secret!(cred_values));

        let v = generate_v_prime_prime()?;

        let e = generate_prime_in_range(&LARGE_E_START_VALUE, &LARGE_E_END_RANGE_VALUE)?;
        let (a, q) = Issuer::_sign_primary_credential_generic(
            cred_pub_key,
            cred_priv_key,
            credential_context,
            cred_values,
            &v,
            blinded_credential_secrets,
            &e,
        )?;

        let pr_cred_sig = PrimaryCredentialSignature {
            m_2: credential_context.try_clone()?,
            a,
            e,
            v,
        };

        trace!(
            "Issuer::_new_primary_credential: <<< pr_cred_sig: {:?}, q: {:?}",
            secret!(&pr_cred_sig),
            secret!(&q)
        );

        Ok((pr_cred_sig, q))
    }

    fn _sign_primary_credential_generic(
        p_pub_key: &CredentialPrimaryPublicKey,
        p_priv_key: &CredentialPrimaryPrivateKey,
        cred_context: &BigNumber,
        cred_values: &CredentialValues,
        v: &BigNumber,
        blinded_cred_secrets: &BlindedCredentialSecrets,
        e: &BigNumber,
    ) -> UrsaCryptoResult<(BigNumber, BigNumber)> {


        //let p_pub_key = &cred_pub_key.p_key;
        //let p_priv_key = &cred_priv_key.p_key;

        let mut context = BigNumber::new_context()?;

        let mut rx = p_pub_key.s.mod_exp(v, &p_pub_key.n, Some(&mut context))?;

        if blinded_cred_secrets.u != BigNumber::from_u32(0)? {
            rx = rx.mod_mul(&blinded_cred_secrets.u, &p_pub_key.n, Some(&mut context))?;
        }

        rx = rx.mod_mul(
            &p_pub_key
                .rctxt
                .mod_exp(cred_context, &p_pub_key.n, Some(&mut context))?,
            &p_pub_key.n,
            Some(&mut context),
        )?;

        for (key, attr) in cred_values
            .attrs_values
            .iter()
            .filter(|&(_, v)| v.is_known())
        {
            let pk_r = p_pub_key.r.get(key).ok_or_else(|| {
                err_msg(
                    UrsaCryptoErrorKind::InvalidStructure,
                    format!("Value by key '{}' not found in pk.r", key),
                )
            })?;

            rx = pk_r
                .mod_exp(attr.value(), &p_pub_key.n, Some(&mut context))?
                .mod_mul(&rx, &p_pub_key.n, Some(&mut context))?;
        }

        let q = p_pub_key.z.mod_div(&rx, &p_pub_key.n, Some(&mut context))?;

        let n = p_priv_key.p.mul(&p_priv_key.q, Some(&mut context))?;
        let e_inverse = e.inverse(&n, Some(&mut context))?;

        let a = q.mod_exp(&e_inverse, &p_pub_key.n, Some(&mut context))?;

        trace!(
            "Issuer::_sign_primary_credential: <<< a: {:?}, q: {:?}",
            secret!(&a),
            secret!(&q)
        );

        Ok((a, q))
    }


    /// Create revocation public key for VA accumulator scheme.
    fn _new_credential_revocation_keys_va() -> UrsaCryptoResult<CredentialRevocationPublicKeyVA>
    {
        Ok(CredentialRevocationPublicKeyVA {
            p: G1::random(),
            p_tilde: G2::random(),
            x: G1::random(),
            y: G1::random(),
            z: G1::random(),
            k: G1::random()
        })
    }


    /// Create a new revocation registry definition for VA accumulator
    pub fn new_revocation_registry_def_va(
        cred_pub_key:&CredentialPublicKeyVA,
        max_cred_num:u32,
        max_batch_size:u32
    ) -> UrsaCryptoResult<(
        RevocationKeyPublicVA,
        RevocationKeyPrivateVA,
        RevocationRegistryVA,
        FieldElementVector
    )> {
        // Create private key
        let alpha = FieldElement::random();
        let mut v0: Vec<FieldElement> = Vec::new();
        for i in 0..max_cred_num {
            v0.push(FieldElement::random());
        }
        let rev_priv_key = RevocationKeyPrivateVA { alpha: alpha.clone(), v0: v0.clone() };

        let q_tilde = alpha * cred_pub_key.r_key.clone().unwrap().p_tilde;
        let rev_pub_key = RevocationKeyPublicVA { q_tilde: q_tilde.clone() };

        let mut faccum = FieldElement::one();
        for elem in rev_priv_key.v0.iter() {
            faccum = faccum * elem;
        }

        let accum = faccum * cred_pub_key.r_key.clone().unwrap().p;
        let rev_reg = RevocationRegistryVA { accum: accum.clone(), revoked: HashSet::new() };
        let evaluation_domain = FieldElementVector::random(max_batch_size as usize + 1);


        Ok((rev_pub_key, rev_priv_key, rev_reg, evaluation_domain))
    }

    pub fn _new_non_revocation_credential_va(
        rev_idx: u32,
        rev_pub_key:&CredentialRevocationPublicKeyVA,
        reg_priv_key:&RevocationKeyPrivateVA,
        va_registry: &VARegistry,
    ) -> UrsaCryptoResult<NonRevocationCredentialSignatureVA> {

        if va_registry.revoked.contains(&rev_idx) {
            return Err(err_msg(UrsaCryptoErrorKind::CredentialRevoked, "Credential Revoked"));
        }

        let cred_context = FieldElement::from(rev_idx);

        let mut d = FieldElement::one();

        for idx in va_registry.revoked.iter() {
            let y = FieldElement::from(idx.clone());
            d = d.clone() * (y - cred_context.clone());
        }

        for elem in reg_priv_key.v0.iter() {
            d = d.clone() * (elem - cred_context.clone());
        }

        let inv = (reg_priv_key.alpha.clone() + cred_context.clone()).inverse();
        let d_dash = d.clone() * inv.clone();

        let c = (inv.clone() * va_registry.accum.clone()) - (d_dash * rev_pub_key.p.clone());

        Ok(NonRevocationCredentialSignatureVA {
            witness: WitnessVA {accum: va_registry.accum.clone(), d:d.clone(), C:c.clone()},
            i: rev_idx,
            m2: cred_context.clone() })

    }


    pub fn update_revocation_registry_va(
        rev_reg: &mut RevocationRegistryVA,
        reg_priv_key: &RevocationKeyPrivateVA,
        evaluation_domain: &FieldElementVector,
        revoked: BTreeSet<u32>,
    ) -> UrsaCryptoResult<RevocationRegistryDeltaVA>
    {

        let mut va_registry = VARegistry::new(rev_reg);
        let revoke_delta = va_registry.revoke(
            reg_priv_key,
            &evaluation_domain,
            &Vec::<u32>::from_iter(revoked.into_iter()),
        );

        if revoke_delta.is_ok() {
            rev_reg.accum = va_registry.accum.clone();
            rev_reg.revoked = va_registry.revoked.clone();
        }

        revoke_delta
    }


}


