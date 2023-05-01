extern crate ursa;
extern crate time_graph;
extern crate serde;
extern crate serde_json;
extern crate amcl_wrapper;
extern crate num_traits;
//extern crate js_sys;

mod my_benchmarks {
    use std::collections::{BTreeSet, HashSet};
    use std::convert::TryInto;
    use std::error::Error;
    use ursa::cl::issuer::Issuer;
    use ursa::cl::prover::Prover;
    use ursa::cl::verifier::Verifier;
    use ursa::cl::*;
    use serde::{Deserialize, Serialize};

    use std::time::{Duration, Instant};
    use std::fs::File;
    use std::io;
    use std::io::prelude::*;
    use std::ops::Index;
    use ursa::bn::BigNumber;
    use ursa::pair::{GroupOrderElement, PointG1};

    use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
    use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
    use amcl_wrapper::group_elem_g1::{G1, G1Vector, G1LookupTable};
    use amcl_wrapper::group_elem_g2::{G2, G2Vector, G2LookupTable};
    use amcl_wrapper::extension_field_gt::GT;
    //use js_sys::Math::max;
    use num_traits::ToPrimitive;
    //use ursa::cl::issuer::mocks::credential_values;
    use ursa::errors::{UrsaCryptoError, UrsaCryptoErrorKind, UrsaCryptoResult};
    //use ursa::ffi::cl::issuer::mocks::_credential_signature;


    pub fn get_credential_schema() -> CredentialSchema {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        credential_schema_builder.finalize().unwrap()
    }

    fn write_file(filename: &String, contents: &String) -> std::io::Result<()> {
        let mut file = File::create(filename)?;
        file.write_all(contents.as_bytes())?;
        println!("Finish writing... {}", filename);
        return Ok(());
    }

    fn read_file(filename: &String, mut contents:&mut String) -> std::io::Result<()> {
        let mut input = File::open(filename)?;
        *contents = String::from("");
        input.read_to_string(&mut contents)?;
        //println!("Read: {}", contents);
        Ok(())
    }

    fn get_non_credential_schema() -> NonCredentialSchema {
        let mut non_credential_schema_builder =
            Issuer::new_non_credential_schema_builder().unwrap();
        non_credential_schema_builder
            .add_attr("master_secret")
            .unwrap();
        non_credential_schema_builder.finalize().unwrap()
    }

    fn get_credential_values(master_secret: &MasterSecret) -> CredentialValues {
        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder
            .add_value_hidden("master_secret", &BigNumber::from_dec("1000").unwrap())
            .unwrap();
        credential_values_builder
            .add_dec_known("name", "1139481716457488690172217916278103335")
            .unwrap();
        credential_values_builder
            .add_dec_known(
                "sex",
                "5944657099558967239210949258394887428692050081607692519917050011144233115103",
            )
            .unwrap();
        credential_values_builder
            .add_dec_known("age", "28")
            .unwrap();
        credential_values_builder
            .add_dec_known("height", "175")
            .unwrap();
        credential_values_builder.finalize().unwrap()
    }

    fn get_sub_proof_request() -> SubProofRequest {
        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder.finalize().unwrap()
    }

    type ProverData = (u32, CredentialValues, CredentialSignature, Witness);
    type ProverDataVA = (u32, CredentialValues, CredentialSignatureVA);


    #[time_graph::instrument]
    fn load_setup_from_files(generate_new_setup: bool, max_cred_num: u32) -> Option<(
        CredentialPublicKey,
        CredentialPrivateKey,
        CredentialKeyCorrectnessProof,
        RevocationKeyPublic,
        RevocationKeyPrivate,
        RevocationRegistry,
        SimpleTailsAccessor
    )>
    {
        let mut credential_pub_key: Option<CredentialPublicKey> = None;
        let mut credential_priv_key: Option<CredentialPrivateKey> = None;
        let mut credential_key_correctness_proof: Option<CredentialKeyCorrectnessProof> = None;
        let mut revocation_pub_key: Option<RevocationKeyPublic> = None;
        let mut revocation_priv_key: Option<RevocationKeyPrivate> = None;
        let mut revocation_reg: Option<RevocationRegistry> = None;
        let mut simple_tails_accessor: Option<SimpleTailsAccessor> = None;


        if generate_new_setup == true {
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

            credential_pub_key = Some(cred_pub_key);
            credential_priv_key = Some(cred_priv_key);
            credential_key_correctness_proof = Some(cred_key_correctness_proof);


            // 3. Issuer creates revocation registry
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key.as_ref().unwrap(),
                    max_cred_num,
                    false
                ).unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
            revocation_pub_key = Some(rev_key_pub);
            revocation_priv_key = Some(rev_key_priv);
            revocation_reg = Some(rev_reg);
            simple_tails_accessor = Some(simple_tail_accessor);

            // serialize the objects to respective files.
            let cred_pub_key = serde_json::to_string::<CredentialPublicKey>(&credential_pub_key.as_ref().unwrap()).ok();
            let cred_priv_key = serde_json::to_string(&credential_priv_key.as_ref().unwrap()).ok();
            let cred_key_correctness_proof = serde_json::to_string(&credential_key_correctness_proof.as_ref().unwrap()).ok();
            let rev_pub_key = serde_json::to_string(&revocation_pub_key.as_ref().unwrap()).ok();
            let rev_priv_key = serde_json::to_string(&revocation_priv_key.as_ref().unwrap()).ok();
            let rev_reg = serde_json::to_string(&revocation_reg.as_ref().unwrap()).ok();
            let simple_tail_accessor = serde_json::to_string(&simple_tails_accessor.as_ref().unwrap()).ok();

            write_file(&String::from("cred-pub-key.dat"), &cred_pub_key.unwrap()).ok();
            write_file(&String::from("cred-priv-key.dat"), &cred_priv_key.unwrap()).ok();
            write_file(&String::from("cred-key-correctness-proof.dat"), &cred_key_correctness_proof.unwrap()).ok();
            write_file(&String::from("rev-pub-key.dat"), &rev_pub_key.unwrap()).ok();
            write_file(&String::from("rev-priv-key.dat"), &rev_priv_key.unwrap()).ok();
            write_file(&String::from("rev-reg.dat"), &rev_reg.unwrap()).ok();
            write_file(&String::from("simple-tail-accessor.dat"), &simple_tail_accessor.unwrap()).ok();
        } else {
            // load from the files
            let mut cred_pub_key = &mut String::from("");
            let mut cred_priv_key= &mut String::from("");
            let mut cred_key_correctness_proof = &mut String::from("");
            let mut rev_pub_key= &mut String::from("");
            let mut rev_priv_key = &mut String::from("");
            let mut rev_reg = &mut String::from("");
            let mut simple_tail_accessor = &mut String::from("");

            read_file(&String::from("cred-pub-key.dat"), cred_pub_key).ok();
            read_file(&String::from("cred-priv-key.dat"), cred_priv_key).ok();
            read_file(&String::from("cred-key-correctness-proof.dat"), cred_key_correctness_proof).ok();
            read_file(&String::from("rev-pub-key.dat"), rev_pub_key).ok();
            read_file(&String::from("rev-priv-key.dat"), rev_priv_key).ok();
            read_file(&String::from("rev-reg.dat"), rev_reg).ok();
            read_file(&String::from("simple-tail-accessor.dat"), simple_tail_accessor).ok();

            //println!("cred_pub_key: {:?}\n", cred_pub_key);
            credential_pub_key = serde_json::from_str(cred_pub_key.as_str()).ok();
            //rintln!("Read credential public key {:?}", credential_pub_key);
            credential_priv_key = serde_json::from_str(cred_priv_key.as_str()).ok();
            credential_key_correctness_proof = serde_json::from_str(cred_key_correctness_proof.as_str()).ok();
            revocation_pub_key = serde_json::from_str(rev_pub_key.as_str()).ok();
            revocation_priv_key = serde_json::from_str(rev_priv_key.as_str()).ok();
            revocation_reg = serde_json::from_str(rev_reg.as_str()).ok();
            simple_tails_accessor = serde_json::from_str(simple_tail_accessor.as_str()).ok();

        }

        return Some((
            credential_pub_key.unwrap(),
            credential_priv_key.unwrap(),
            credential_key_correctness_proof.unwrap(),
            revocation_pub_key.unwrap(),
            revocation_priv_key.unwrap(),
            revocation_reg.unwrap(),
            simple_tails_accessor.unwrap()
        ));

    }

    fn setup_cred_and_issue(
        max_cred_num: u32,
        issuance_by_default: bool,
        pre_issued_credentials: u32,  // pre-issue these credentials
        num_fresh_credentials: u32    // issue following fresh credentials
    ) -> (
        CredentialSchema,
        NonCredentialSchema,
        CredentialPublicKey,
        RevocationKeyPublic,
        RevocationRegistry,
        RevocationRegistryDelta,
        SimpleTailsAccessor,
        Vec<ProverData>,
    ) {
        let credential_schema = get_credential_schema();
        let non_credential_schema = get_non_credential_schema();

        /*
        // 2. Issuer creates credential definition(with revocation keys)
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

        // 3. Issuer creates revocation registry
        let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
            Issuer::new_revocation_registry_def(
                &credential_pub_key,
                max_cred_num,
                issuance_by_default,
            )
                .unwrap();

        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
        */
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof,
        rev_key_pub, rev_key_priv, mut rev_reg, simple_tail_accessor) =
            load_setup_from_files(true, max_cred_num).unwrap();

        let mut issued: HashSet<u32> = HashSet::new();
        let mut revoked: HashSet<u32> = HashSet::new();
        let mut issued_btree: BTreeSet<u32> = BTreeSet::new();
        let mut revoked_btree: BTreeSet<u32> = BTreeSet::new();
        // pre-fill the issued set

        for i in 1..=pre_issued_credentials {
            issued.insert(i);
            issued_btree.insert(i);
        }

        Issuer::update_revocation_registry(&mut rev_reg, max_cred_num, issued_btree, revoked_btree, &simple_tail_accessor).unwrap();

        let mut prover_data: Vec<ProverData> = vec![];

        let rev_reg_init : Option<&RevocationRegistry> = None;
        let mut rev_reg_delta: Option<RevocationRegistryDelta> = Some(RevocationRegistryDelta::from_parts(
            rev_reg_init,
             &rev_reg,
              &issued,
            &revoked
        ));

        let start = Instant::now();
        for i in 0..num_fresh_credentials {
            let credential_values = get_credential_values(&Prover::new_master_secret().unwrap());

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let blinding_correctness_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &blinding_correctness_nonce,
            )
                .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let signature_correctness_nonce = new_nonce().unwrap();

            // 8. Issuer creates and sign credential values
            let rev_idx = i + 1 + pre_issued_credentials;
            let (mut credential_signature, signature_correctness_proof, rr_delta) =
                Issuer::sign_credential_with_revoc(
                    &rev_idx.to_string(),
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &blinding_correctness_nonce,
                    &signature_correctness_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                    &simple_tail_accessor,
                ).unwrap();



            let mut new_delta = rev_reg_delta.unwrap();
            new_delta.merge(&rr_delta.unwrap()).unwrap();
            rev_reg_delta = Some(new_delta);


            let unwrapped_delta = rev_reg_delta.unwrap();
            // 9. Prover creates witness
            let witness = Witness::new(
                rev_idx,
                max_cred_num,
                issuance_by_default,
                &unwrapped_delta,
                &simple_tail_accessor,
            ).unwrap();
            println!("Issued: {}", unwrapped_delta.issued.len());
            rev_reg_delta = Some(unwrapped_delta);

            // 10. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &signature_correctness_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
                .unwrap();

            prover_data.push((rev_idx, credential_values, credential_signature, witness))
        }

        println!(
            "Issuance time for {} is {:?}",
            num_fresh_credentials,
            start.elapsed()
        );

        (
            credential_schema,
            non_credential_schema,
            credential_pub_key,
            rev_key_pub,
            rev_reg,
            rev_reg_delta.unwrap(),
            simple_tail_accessor,
            prover_data,
        )
    }

    fn gen_proofs(
        max_cred_num: u32,
        issuance_by_default: bool,
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        credential_pub_key: &CredentialPublicKey,
        sub_proof_request: &SubProofRequest,
        nonces: &[Nonce],
        rev_reg: &RevocationRegistry,
        rev_reg_delta: &RevocationRegistryDelta,
        simple_tail_accessor: &SimpleTailsAccessor,
        prover_data: &mut [ProverData],
    ) -> Vec<Proof> {
        let mut proofs = Vec::with_capacity(nonces.len());
        let mut total_witness_gen = Duration::new(0, 0);
        let mut total_proving = Duration::new(0, 0);
        for i in 0..nonces.len() {
            let (rev_idx, ref credential_values, ref credential_signature, ref mut _witness) =
                prover_data[i as usize];

            let mut start = Instant::now();
            let witness = Witness::new(
                rev_idx,
                max_cred_num,
                issuance_by_default,
                rev_reg_delta,
                simple_tail_accessor,
            )
                .unwrap();
            //witness.update(rev_idx, max_cred_num, rev_reg_delta, simple_tail_accessor).unwrap();
            total_witness_gen += start.elapsed();

            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();

            start = Instant::now();
            proof_builder
                .add_sub_proof_request(
                    sub_proof_request,
                    credential_schema,
                    non_credential_schema,
                    credential_signature,
                    credential_values,
                    credential_pub_key,
                    Some(rev_reg),
                    Some(&witness),
                )
                .unwrap();
            proofs.push(proof_builder.finalize(&nonces[i as usize]).unwrap());
            total_proving += start.elapsed();
        }

        println!(
            "Total witness gen time for {} is {:?}",
            nonces.len(),
            total_witness_gen
        );
        println!(
            "Total proving time for {} is {:?}",
            nonces.len(),
            total_proving
        );
        proofs
    }

    fn gen_proofs_va(
        max_cred_num: u32,
        issuance_by_default: bool,
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        credential_pub_key: &CredentialPublicKeyVA,
        sub_proof_request: &SubProofRequest,
        nonces: &[Nonce],
        rev_reg: &RevocationRegistryVA,
        prover_data: &mut [ProverDataVA],
    ) -> Vec<GenProof> {
        let mut proofs = Vec::with_capacity(nonces.len());
        let mut total_witness_gen = Duration::new(0, 0);
        let mut total_proving = Duration::new(0, 0);
        for i in 0..nonces.len() {
            let (rev_idx, ref credential_values, ref credential_signature) =
                prover_data[i as usize];

            let mut start = Instant::now();

            //witness.update(rev_idx, max_cred_num, rev_reg_delta, simple_tail_accessor).unwrap();
            total_witness_gen += start.elapsed();

            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();

            start = Instant::now();
            proof_builder
                .add_sub_proof_request_va(
                    sub_proof_request,
                    credential_schema,
                    non_credential_schema,
                    credential_signature,
                    credential_values,
                    credential_pub_key,
                    Some(rev_reg),
                ).unwrap();
            proofs.push(proof_builder.finalize_generic(&nonces[i as usize]).unwrap());
            total_proving += start.elapsed();
        }

        println!(
            "Total witness gen time for {} is {:?}",
            nonces.len(),
            total_witness_gen
        );
        println!(
            "Total proving time for {} is {:?}",
            nonces.len(),
            total_proving
        );
        proofs
    }

    #[cfg(test)]
    mod tests {
        use std::io;
        use super::*;

        #[test]
        fn bench() {
            let max_cred_num = 1000000;
            let pre_issued_credentials: u32 = 900000;
            let num_proofs_to_do = 10;
            let issuance_by_default = false;
            time_graph::enable_data_collection(true);

            let sub_proof_request = get_sub_proof_request();
            let (
                credential_schema,
                non_credential_schema,
                credential_pub_key,
                rev_key_pub,
                rev_reg,
                rev_reg_delta,
                simple_tail_accessor,
                mut prover_data,
            ) = setup_cred_and_issue(max_cred_num, issuance_by_default, pre_issued_credentials, num_proofs_to_do);

            let nonces: Vec<_> = (0..num_proofs_to_do)
                .map(|_| new_nonce().unwrap())
                .collect();

            let mut start = Instant::now();
            let proofs = gen_proofs(
                max_cred_num,
                issuance_by_default,
                &credential_schema,
                &non_credential_schema,
                &credential_pub_key,
                &sub_proof_request,
                &nonces,
                &rev_reg,
                &rev_reg_delta,
                &simple_tail_accessor,
                &mut prover_data,
            );
            println!(
                "Proof gen time for {} is {:?}",
                num_proofs_to_do,
                start.elapsed()
            );

            start = Instant::now();
            for i in 0..num_proofs_to_do {
                let idx = i as usize;
                let mut verifier = Verifier::new_proof_verifier().unwrap();
                verifier
                    .add_sub_proof_request(
                        &sub_proof_request,
                        &credential_schema,
                        &non_credential_schema,
                        &credential_pub_key,
                        Some(&rev_key_pub),
                        Some(&rev_reg),
                    )
                    .unwrap();
                assert!(verifier.verify(&proofs[idx], &nonces[idx]).unwrap());
            }
            println!(
                "Verif time for {} is {:?}",
                num_proofs_to_do,
                start.elapsed()
            );

            let graph = time_graph::get_full_graph();

            println!("{}", graph.as_dot());

            println!("{}", graph.as_table());

            #[cfg(feature = "table")]
            println!("{}", graph.as_short_table());
            io::stdout().flush().unwrap();
        }
    }

    #[test]
    fn check_revoke_update_cks()
    {
        // Basic testing and benchmarking setup
        let credential_schema = get_credential_schema();
        let non_credential_schema = get_non_credential_schema();
        let max_cred_num = 30000u32;
        let num_cred_issue = 2000u32;
        let batch_size = 1000u32;  // batch size for revocations
        let pre_issued_credentials = 90000u32;

        time_graph::enable_data_collection(true);
        // set up the credential specific keys
        let mut start = Instant::now();
        let (cred_pub_key, cred_priv_key, cred_correctness_proof) =
            Issuer::new_credential_def_generic(
                &credential_schema,
                &non_credential_schema,
                true,
                RevocationMethod::CKS
            ).unwrap();
        println!("Creating Credential Setup took {:?}", start.elapsed());

        // set up revocation registry
        let mut start = Instant::now();
        let (reg_pub_key, reg_priv_key, rev_reg, aux_params) =
            Issuer::new_revocation_registry_generic(
                &cred_pub_key,
                max_cred_num,
                true,
                batch_size
            ).unwrap();
        println!("Creating revocation registry took {:?}", start.elapsed());

        // CKS specific stuff
        if let (
            GenRevocationRegistry::CKS(mut rev_reg_cks),
            GenRevocationKeyPublic::CKS(reg_pub_key),
            GenRevocationKeyPrivate::CKS(reg_priv_key),
            AuxiliaryParams::CKS(mut rev_tails_generator),
            GenCredentialPublicKey::CKS(cred_pub_key),
            GenCredentialPrivateKey::CKS(cred_priv_key)
        ) = (
            rev_reg,
            reg_pub_key,
            reg_priv_key,
            aux_params,
            cred_pub_key,
            cred_priv_key,
            )
        {

            // generate tails file
            let mut start = Instant::now();
            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
            println!("Creating tails file took {:?}", start.elapsed());

            // Pre-issue credentials (part of rev registry creation)


            let issued = (1..max_cred_num).into_iter().collect::<HashSet<u32>>();
            let revoked: HashSet<u32> = HashSet::new();


            let mut start = Instant::now();
            //let mut rev_reg_delta = Issuer::update_revocation_registry(&mut rev_reg_cks, max_cred_num, issued_btree, revoked_btree, &simple_tail_accessor).unwrap();
            let mut rev_reg_delta = RevocationRegistryDelta::from_parts(
                None,
                &rev_reg_cks,
                &issued,
                &revoked
            );

            println!("Pre-issuing {} credentials took {:?}", pre_issued_credentials, start.elapsed());

            // Issue credentials
            let mut start = Instant::now();
            let mut prover_data: Vec<ProverData> = Vec::new();
            let credential_values = get_credential_values(&Prover::new_master_secret().unwrap());
            for i in 0..num_cred_issue {
                // 1. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
                let blinding_correctness_nonce = new_nonce().unwrap();

                // 2. Prover blinds master secret
                let (
                    blinded_credential_secrets,
                    credential_secrets_blinding_factors,
                    blinded_credential_secrets_correctness_proof,
                ) = Prover::blind_credential_secrets(
                    &cred_pub_key,
                    &cred_correctness_proof,
                    &credential_values,
                    &blinding_correctness_nonce,
                ).unwrap();

                // 3. Prover creates nonce used by Issuer to create correctness proof for signature
                let signature_correctness_nonce = new_nonce().unwrap();
                let rev_idx =  i + 1;

                let (mut credential_signature, signature_correctness_proof, rr_delta) =
                    Issuer::sign_credential_with_revoc(
                        &rev_idx.to_string(),
                        &blinded_credential_secrets,
                        &blinded_credential_secrets_correctness_proof,
                        &blinding_correctness_nonce,
                        &signature_correctness_nonce,
                        &credential_values,
                        &cred_pub_key,
                        &cred_priv_key,
                        rev_idx,
                        max_cred_num,
                        true,
                        &mut rev_reg_cks,
                        &reg_priv_key,
                        &simple_tail_accessor,
                    ).unwrap();

                // 4. apply the delta to witness and registry
                // Nothing to do here for issuance_by_default

                // 5. Holder updates witness
                let witness = Witness::new(
                    rev_idx,
                    max_cred_num,
                    true,
                    &rev_reg_delta,
                    &simple_tail_accessor,
                ).unwrap();
                //println!("Issued: {}", rev_reg_delta.issued.len());
                //rev_reg_delta = Some(unwrapped_delta);

                // 6. Holder processes credential signature
                Prover::process_credential_signature(
                    &mut credential_signature,
                    &credential_values,
                    &signature_correctness_proof,
                    &credential_secrets_blinding_factors,
                    &cred_pub_key,
                    &signature_correctness_nonce,
                    Some(&reg_pub_key),
                    Some(&rev_reg_cks),
                    Some(&witness),
                ).unwrap();
                prover_data.push((rev_idx, credential_values.try_clone().unwrap(), credential_signature, witness));
            }
            println!("Issuing {} credentials took {:?}", num_cred_issue, start.elapsed());


            // Revoke credentials
            let mut revoked_ids: BTreeSet<u32> = BTreeSet::new();
            for i in 1..=batch_size {
                revoked_ids.insert(i);
            }

            let mut start = Instant::now();
            let revoke_delta = Issuer::update_revocation_registry(
                &mut rev_reg_cks,
                max_cred_num,
                BTreeSet::new(),
                revoked_ids,
                &simple_tail_accessor
            ).unwrap();
            println!("Time to revoke {} credentials {:?}", batch_size, start.elapsed());

            // revoke credentials batch 1

            // revoke credentials batch 2

            // Holders merge batch 1 and batch 2

            // Holders update their witnesses to current accumulator
            println!("Applying updates to the witness");
            let mut start = Instant::now();
            let rev_idx = batch_size + 1;
                prover_data[(rev_idx - 1) as usize].3.update(
                    rev_idx,
                    max_cred_num,
                    &revoke_delta,
                    &simple_tail_accessor).unwrap();

            println!("Time to update witness {:?}", start.elapsed());
        }

        let graph = time_graph::get_full_graph();

        println!("{}", graph.as_dot());

        println!("{}", graph.as_table());

        #[cfg(feature = "table")]
        println!("{}", graph.as_short_table());
        io::stdout().flush().unwrap();
    }


    #[test]
    fn check_revoke_update_va()
    {
        // Basic testing and benchmarking setup
        let credential_schema = get_credential_schema();
        let non_credential_schema = get_non_credential_schema();
        let max_cred_num =1000000u32;
        let num_cred_issue = 2000u32;
        let batch_size = 100u32;  // batch size for revocations

        // set up evaluation domain of size batch_size + 1
        let mut evaluation_domain: Vec<FieldElement> = Vec::new();
        for i in 0..=batch_size {
            evaluation_domain.push(FieldElement::random());
        }
        let evaluation_domain = FieldElementVector::from(evaluation_domain);


        // get credential definition
        let (cred_pub_key, cred_priv_key, cred_signature_correctness_proof) = Issuer::new_credential_def_va(
            &credential_schema,
            &non_credential_schema,
            true
        ).ok().unwrap();



        // create a registry definition
        let mut start = Instant::now();
        let (reg_pub_key, reg_priv_key, mut rev_reg, edomain) =
            Issuer::new_revocation_registry_def_va(&cred_pub_key, max_cred_num, batch_size).ok().unwrap();
        println!("Created Revocation Registry {:?} in time {:?}", rev_reg, start.elapsed());
        let mut va_registry = VARegistry::new(&rev_reg);

        // Issue sample credentials
        let mut signatures: Vec<NonRevocationCredentialSignatureVA> = Vec::new();

        let mut start = Instant::now();
        for rev_idx in 1..=num_cred_issue {
            let non_rev_cred = Issuer::_new_non_revocation_credential_va(
                rev_idx, // keep credential ids disjoint from interpolation domain
                &cred_pub_key.get_revocation_key().unwrap().unwrap(),
                &reg_priv_key,
                &va_registry
            ).ok().unwrap();

            signatures.push(non_rev_cred.to_owned());

        }
        println!("Issuing credentials took {:?}", start.elapsed());

        println!("Preparing to revoke {} credentials", batch_size);
        let revoked: Vec<u32> = (1..=batch_size).collect();
        let mut start = Instant::now();
        let mut rev_reg_delta = va_registry.revoke(
            &cred_pub_key.get_revocation_key().unwrap().unwrap(),
            &reg_priv_key,
            &evaluation_domain,
            &revoked
        ).unwrap();
        println!("Update for revoking {} credentials took {:?}", batch_size, start.elapsed());

        // we batch 10 updates
        let mut start = Instant::now();
        for i in 1..10 {
            let revoked: Vec<u32> = ((i*batch_size+1)..=((i+1)*batch_size)).collect();
            let revoke_delta = va_registry.revoke(
                &cred_pub_key.get_revocation_key().unwrap().unwrap(),
                &reg_priv_key,
                &evaluation_domain,
                &revoked
            ).unwrap();
            rev_reg_delta.merge(&revoke_delta).unwrap();
        }
        println!("Computing updates for {} batches took {:?}", 10, start.elapsed());
        /*
        println!("Preparing to revoke {} credentials", batch_size);
        let revoked: Vec<u32> = ((batch_size+1)..=(2*batch_size)).collect();
        let mut start = Instant::now();
        let rev_reg_delta_2 = va_registry.revoke(
            &cred_pub_key.get_revocation_key().unwrap().unwrap(),
            &reg_priv_key,
            &evaluation_domain,
            &revoked
        ).unwrap();
        println!("Update for revoking {} credentials took {:?}", batch_size, start.elapsed());

        // merge the deltas
        rev_reg_delta.merge(&rev_reg_delta_2).unwrap();
        rev_reg = RevocationRegistryVA::from_delta(&rev_reg_delta);
        */
        // update the credential for rev_idx = 2*batch_size + 1

        // update witness and verify with new accumulator again
        rev_reg = RevocationRegistryVA::from_delta(&rev_reg_delta);

        let rev_idx = 1000 + 1;
        let idx = rev_idx.to_usize().unwrap() - 1;
        let cred_context = signatures.index(idx).m2.clone();
        let ldomain = LagrangianDomain::from_parts(&evaluation_domain, &cred_context).unwrap();

        let mut start = Instant::now();
        signatures[idx].witness.update(&rev_reg_delta, &ldomain).unwrap();
        println!("Time to update the witness in batch {:?}", start.elapsed());


        // verify the updated credential
        let check = Verifier::verify_non_mem_witness(
            &cred_pub_key.get_revocation_key().unwrap().unwrap(),
            &reg_pub_key,
            &rev_reg,
            &signatures.index(idx).witness,
            rev_idx
        );

        match check {
            true => { println!("Credential {} verified OK", rev_idx); }
            false => { println!("Credential {} verified FAIL", rev_idx); }
        }
    }

    #[test]
    fn check_generic_sign_credential_with_cks()
    {
        // Basic testing and benchmarking setup
        let credential_schema = get_credential_schema();
        let non_credential_schema = get_non_credential_schema();
        let max_cred_num = 100u32;
        let num_cred_issue = 2000u32;
        let batch_size = 10u32;  // batch size for revocations
        let pre_issued_credentials = 90000u32;

        time_graph::enable_data_collection(true);
        // set up the credential specific keys
        let mut start = Instant::now();
        let (cred_pub_key, cred_priv_key, cred_correctness_proof) =
            Issuer::new_credential_def_generic(
                &credential_schema,
                &non_credential_schema,
                true,
                RevocationMethod::CKS
            ).unwrap();
        println!("Creating Credential Setup took {:?}", start.elapsed());

        // set up revocation registry
        let mut start = Instant::now();
        let (reg_pub_key, reg_priv_key, mut rev_reg, aux_params) =
            Issuer::new_revocation_registry_generic(
                &cred_pub_key,
                max_cred_num,
                false,
                batch_size
            ).unwrap();
        println!("Creating revocation registry took {:?}", start.elapsed());
        println!("Initial Registry: {:?}", rev_reg);

        //let mut reg_delta = RevocationRegistryDelta::from_parts()

        let mut simple_tails_accessor: UrsaCryptoResult<SimpleTailsAccessor> =
            UrsaCryptoResult::Err(UrsaCryptoError::from_msg(UrsaCryptoErrorKind::InvalidStructure, ""));

        if let(AuxiliaryParams::CKS(mut rev_tails_generator)) = aux_params {
            println!("Generating tails file");
            simple_tails_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator);
        }

        // Credential Issuance
        // 1. Prover chooses attributes
        let prover_id = "prover";
        let credential_values =get_credential_values(&Prover::new_master_secret().unwrap());
        let blinding_correctness_nonce = new_nonce().unwrap();

        // 2. Prover blinds master secret
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets_generic(
            &cred_pub_key,
            &cred_correctness_proof,
            &credential_values,
            &blinding_correctness_nonce,
        ).unwrap();

        // 3. Prover creates nonce used by Issuer to create correctness proof for signature
        let signature_correctness_nonce = new_nonce().unwrap();
        let rev_idx =  1;

        let (mut cred_signature, cred_signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc_generic(
                prover_id,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &blinding_correctness_nonce,
                &signature_correctness_nonce,
                &credential_values,
                &cred_pub_key,
                &cred_priv_key,
                rev_idx,
                max_cred_num,
                false,
                &mut rev_reg,
                &reg_priv_key,
                simple_tails_accessor.as_ref().unwrap(),
            ).unwrap();

        println!("Updated registry: {:?}", rev_reg);

        // 4. Witness management is CKS specific
        let mut witness = Witness::new(
            rev_idx,
            max_cred_num,
            false,
            &rev_reg_delta.unwrap().unwrap_cks().unwrap(),
            simple_tails_accessor.as_ref().unwrap(),
        ).unwrap();

        // 5. process credential signature
        Prover::process_credential_signature_generic(
            &mut cred_signature,
            &credential_values,
            &cred_signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &signature_correctness_nonce,
            Some(&reg_pub_key),
            Some(&rev_reg),
            Some(&GenWitness::CKS(witness))
        ).unwrap();

    }

    #[test]
    fn check_generate_proof_va()
    {
        // Basic testing and benchmarking setup
        let credential_schema = get_credential_schema();
        let non_credential_schema = get_non_credential_schema();
        let max_cred_num = 100u32;
        let num_cred_issue = 10u32;
        let batch_size = 10u32;  // batch size for revocations
        let pre_issued_credentials = 90000u32;
        let sub_proof_request = get_sub_proof_request();
        time_graph::enable_data_collection(true);
        // set up the credential specific keys
        let mut start = Instant::now();
        let (cred_pub_key, cred_priv_key, cred_correctness_proof) =
            Issuer::new_credential_def_generic(
                &credential_schema,
                &non_credential_schema,
                true,
                RevocationMethod::VA
            ).unwrap();
        println!("Creating Credential Setup took {:?}", start.elapsed());

        // set up revocation registry
        let mut start = Instant::now();
        let (reg_pub_key, reg_priv_key, mut rev_reg, aux_params) =
            Issuer::new_revocation_registry_generic(
                &cred_pub_key,
                max_cred_num,
                false,
                batch_size
            ).unwrap();
        println!("Creating revocation registry took {:?}", start.elapsed());
        println!("Initial Registry: {:?}", rev_reg);

        //let mut reg_delta = RevocationRegistryDelta::from_parts()

        let mut evaluation_domain: Option<FieldElementVector> = None;

        if let(AuxiliaryParams::VA(edomain)) = aux_params {
            println!("Extracting evaluation domain");
            evaluation_domain = Some(edomain);
        }

        // Credential Issuance
        // 1. Prover chooses attributes
        let prover_id = "prover";
        let credential_values =get_credential_values(&Prover::new_master_secret().unwrap());
        let blinding_correctness_nonce = new_nonce().unwrap();

        // 2. Prover blinds master secret
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets_generic(
            &cred_pub_key,
            &cred_correctness_proof,
            &credential_values,
            &blinding_correctness_nonce,
        ).unwrap();

        // 3. Prover creates nonce used by Issuer to create correctness proof for signature
        let signature_correctness_nonce = new_nonce().unwrap();
        let rev_idx =  1;

        let (mut cred_signature, cred_signature_correctness_proof, rev_reg_delta) =
            Issuer::sign_credential_with_revoc_generic(
                prover_id,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &blinding_correctness_nonce,
                &signature_correctness_nonce,
                &credential_values,
                &cred_pub_key,
                &cred_priv_key,
                rev_idx,
                max_cred_num,
                false,
                &mut rev_reg,
                &reg_priv_key,
                &NoOpRevocationTailsAccessor::new()
            ).unwrap();

        println!("Updated registry: {:?}", rev_reg);

        // 4. Witness management is CKS specific, not needed in VA
        let mut witness: Option<WitnessVA> = None;
        if let GenCredentialSignature::VA(ref cred_signature_va) = &cred_signature {
            witness = Some(cred_signature_va.r_credential.as_ref().unwrap().witness.clone());
        }


        /*
        let mut witness = Witness::new(
            rev_idx,
            max_cred_num,
            false,
            &rev_reg_delta.unwrap().unwrap_cks().unwrap(),
            simple_tails_accessor.as_ref().unwrap(),
        ).unwrap();
        */
        // 5. process credential signature
        Prover::process_credential_signature_generic(
            &mut cred_signature,
            &credential_values,
            &cred_signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &signature_correctness_nonce,
            Some(&reg_pub_key),
            Some(&rev_reg),
            Some(&GenWitness::VA(witness.clone().unwrap().clone()))
            ).unwrap();



        // verify the updated credential
        let mut check = false;
        let mut prover_data: Vec<ProverDataVA> = Vec::new();
        let mut nonces: Vec<Nonce> = Vec::new();

        if let (
            GenCredentialPublicKey::VA(ref cred_pub_key_va),
            GenRevocationKeyPublic::VA(ref reg_pub_key_va), GenRevocationRegistry::VA(ref rev_reg_va),
                GenCredentialSignature::VA(ref cred_signature_va)) =
            (&cred_pub_key, &reg_pub_key, &rev_reg, &cred_signature) {
            check = Verifier::verify_non_mem_witness(
                &cred_pub_key_va.get_revocation_key().unwrap().unwrap(),
                reg_pub_key_va,
                rev_reg_va,
                &witness.unwrap(),
                rev_idx
            );
            prover_data.push((rev_idx, credential_values.try_clone().unwrap(), cred_signature_va.try_clone().unwrap()));

            // generate proof
            nonces.push(new_nonce().unwrap());
            let proofs = gen_proofs_va(
                max_cred_num,
                false,
                &credential_schema,
                &non_credential_schema,
                &cred_pub_key_va,
                &sub_proof_request,
                &nonces,
                &rev_reg_va,
                &mut prover_data
            );

            let mut verifier = Verifier::new_proof_verifier().unwrap();
            verifier
                .add_sub_proof_request_va(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    cred_pub_key_va,
                    Some(reg_pub_key_va),
                    Some(rev_reg_va),
                )
                .unwrap();
            println!("Result: {}", verifier.verify_generic(&proofs[0], &nonces[0]).unwrap());

            println!("Proofs: {:?}", proofs);
        }

        match check {
            true => { println!("Credential {} verified OK", rev_idx); }
            false => { println!("Credential {} verified FAIL", rev_idx); }
        }




    }


    #[test]
    fn bench_ff()
    {
        // create a vector of 100000 random field elements
        let mut start = Instant::now();
        let mut f: Vec<FieldElement> = Vec::new();

        for i in 0u32..100000 {
            f.push(FieldElement::random());
        }
        println!("Generating random vector took {:?}", start.elapsed());

        let mut product = FieldElement::one();
        let mut start = Instant::now();
        for i in 0..f.len() {
            product = f.get(i).unwrap() * product;
        }
        println!("Multiplying 100000 field elements took {:?}", start.elapsed());

    }

    #[test]
    fn bench_ff_ursa()
    {
        // create a vector of 100000 random field elements
        let mut start = Instant::now();
        let mut f: Vec<GroupOrderElement> = Vec::new();

        for i in 0u32..100000 {
            f.push(GroupOrderElement::new().unwrap());
        }
        println!("Generating random vector took {:?}", start.elapsed());

        let mut product = GroupOrderElement::from_string("1").unwrap();
        let mut start = Instant::now();
        for i in 0..f.len() {
            product = f.get(i).unwrap().mul_mod(&product).unwrap();
        }
        println!("Multiplying 100000 field elements took {:?}", start.elapsed());

    }

    #[test]
    fn bench_group_add_ursa()
    {
        // create a vector of 100000 random group elements
        let mut start = Instant::now();
        let mut f: Vec<PointG1> = Vec::new();

        for i in 0u32..100000 {
            f.push(PointG1::new().unwrap());
        }
        println!("Generating random vector took {:?}", start.elapsed());

        let mut product = PointG1::new_inf().unwrap();
        let mut start = Instant::now();
        for i in 0..f.len() {
            product = f.get(i).unwrap().add(&product).unwrap();
        }
        println!("Adding 100000 field elements took {:?}", start.elapsed());

    }

    #[test]
    fn bench_group_scalar_product()
    {
        let mut start = Instant::now();
        let fvec = FieldElementVector::random(100000);
        let gvec = G1Vector::random(100000);
        println!("Time to create field and group elements {:?}", start.elapsed());

        let mut start = Instant::now();
        let ip = gvec.multi_scalar_mul_var_time(fvec.iter());
        println!("Time for inner product {:?}", start.elapsed());

        let mut start = Instant::now();
        let mut gsum = G1::identity();
        for i in 0..gvec.len() {
            gsum = gsum + gvec.index(i);
        }
        println!("Time for 10000 additions {:?}", start.elapsed());
    }


}