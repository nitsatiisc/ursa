extern crate ursa;
extern crate time_graph;
extern crate serde;
extern crate serde_json;
extern crate amcl_wrapper;
extern crate num_traits;
//extern crate js_sys;

mod test_generic {

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
    //use js_sys::Atomics::sub;
    //use js_sys::Math::max;
    use num_traits::ToPrimitive;
    use serde_json::Value;
    //use ursa::cl::issuer::mocks::credential_values;
    use ursa::errors::{UrsaCryptoError, UrsaCryptoErrorKind, UrsaCryptoResult};
    //use ursa::ffi::cl::issuer::mocks::_credential_signature;


    /// -----------------------------------------------------------------------
    ///                            Utility Functions                          /
    /// -----------------------------------------------------------------------

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

    /// Functions to serialize and deserialize objects
    fn read_object<'a, T: serde::Deserialize<'a>>(contents: &'a str) -> Option<T> {
        let obj = serde_json::from_str(contents).ok();
        obj
    }

    fn write_object<T: serde::Serialize>(filename: &str, obj: &Option<T>) -> std::io::Result<()> {
        let contents = serde_json::to_string_pretty(obj).unwrap();
        write_file(&String::from(filename), &contents)
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
    type GenProverData = (u32, CredentialValues, GenCredentialSignature, Option<GenWitness>);

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

    fn gen_proofs_generic(
        credential_schema: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        credential_pub_key: &GenCredentialPublicKey,
        sub_proof_request: &SubProofRequest,
        nonces: &[Nonce],
        rev_reg: &GenRevocationRegistry,
        prover_data: &mut [GenProverData],
    ) -> Vec<GenProof> {
        let mut proofs = Vec::with_capacity(nonces.len());
        let mut total_witness_gen = Duration::new(0, 0);
        let mut total_proving = Duration::new(0, 0);
        for i in 0..nonces.len() {
            let (
                rev_idx,
                ref credential_values,
                ref credential_signature,
                ref witness
            ) = prover_data[i as usize];
            let mut start = Instant::now();

            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();

            start = Instant::now();
            proof_builder
                .add_sub_proof_request_generic(
                    sub_proof_request,
                    &credential_schema,
                    non_credential_schema,
                    credential_signature,
                    credential_values,
                    &credential_pub_key,
                    Some(&rev_reg),
                    witness.as_ref()
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
        use std::iter::FromIterator;
        use ursa::cl::CredentialKeyCorrectnessProof;
        use super::*;

        #[test]
        fn test_credential_setup_read_write_cks()
        {
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 100u32;
            let issuance_by_default = true;
            let max_batch_size = 10u32;

            // 1. Create credential definition
            let (credential_public_key, credential_private_key,
                credential_key_correctness_proof) =
                Issuer::new_credential_def_generic(
                    &credential_schema,
                    &non_credential_schema,
                    true,
                    RevocationMethod::CKS
                ).unwrap();

            // 2. Create Registry Definition
            let (registry_public_key, registry_private_key, mut rev_registry, mut aux_params) =
                Issuer::new_revocation_registry_generic(
                    &credential_public_key,
                    max_cred_num,
                    issuance_by_default,
                    max_batch_size,
                ).unwrap();

            let simple_tails_accessor = aux_params.unwrap_cks().unwrap();

            // Serialize the objects into files
            let (
                res_cred_pub,
                res_cred_priv,
                res_correctness_proof,
                res_reg_pub,
                res_reg_priv,
                res_rev_reg,
                res_aux_params
            ) = (
                write_object("cred-pub-key.dat", &Some(credential_public_key)),
                write_object("cred-priv-key.dat", &Some(credential_private_key)),
                write_object("correctness-proof.dat", &Some(credential_key_correctness_proof)),
                write_object("reg-pub-key.dat", &Some(registry_public_key)),
                write_object("reg-priv-key.dat", &Some(registry_private_key)),
                write_object("rev-reg.dat", &Some(rev_registry)),
                write_object("simple-tails-accessor.dat", &Some(simple_tails_accessor))
            );

            // Check read credential primary key
            let mut contents = String::new();
            read_file(&String::from("cred-pub-key.dat"), &mut contents).unwrap();
            let credential_public_key: Option<GenCredentialPublicKey> = read_object(contents.as_str());
            assert!(credential_public_key.is_some());

            // Check read credential private key
            let mut contents = String::new();
            read_file(&String::from("cred-priv-key.dat"), &mut contents).unwrap();
            let credential_private_key: Option<GenCredentialPrivateKey> = read_object(contents.as_str());
            assert!(credential_private_key.is_some());

            // Check read correctness proof
            let mut contents = String::new();
            read_file(&String::from("correctness-proof.dat"), &mut contents).unwrap();
            let credential_key_correctness_proof: Option<CredentialKeyCorrectnessProof> = read_object(contents.as_str());
            assert!(credential_key_correctness_proof.is_some());

            // Check read Registry Public Key
            let mut contents = String::new();
            read_file(&String::from("reg-pub-key.dat"), &mut contents).unwrap();
            let reg_pub_key: Option<GenRevocationKeyPublic> = read_object(contents.as_str());
            assert!(reg_pub_key.is_some());

            // Check read Registry Private Key
            let mut contents = String::new();
            read_file(&String::from("reg-priv-key.dat"), &mut contents).unwrap();
            let reg_priv_key: Option<GenRevocationKeyPrivate> = read_object(contents.as_str());
            assert!(reg_priv_key.is_some());

            // Check read tails file
            let mut contents = String::new();
            read_file(&String::from("simple-tails-accessor.dat"), &mut contents).unwrap();
            let simple_tails_accessor: Option<SimpleTailsAccessor> = read_object(contents.as_str());
            assert!(simple_tails_accessor.is_some());
        }

        #[test]
        fn test_credential_setup_read_write_va()
        {
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 100u32;
            let issuance_by_default = true;
            let max_batch_size = 10u32;

            // 1. Create credential definition
            let (credential_public_key, credential_private_key,
                credential_key_correctness_proof) =
                Issuer::new_credential_def_generic(
                    &credential_schema,
                    &non_credential_schema,
                    true,
                    RevocationMethod::VA
                ).unwrap();

            // 2. Create Registry Definition
            let (registry_public_key, registry_private_key, mut rev_registry, mut aux_params) =
                Issuer::new_revocation_registry_generic(
                    &credential_public_key,
                    max_cred_num,
                    issuance_by_default,
                    max_batch_size,
                ).unwrap();

            let simple_tails_accessor = aux_params.unwrap_va();

            // Serialize the objects into files
            let (
                res_cred_pub,
                res_cred_priv,
                res_correctness_proof,
                res_reg_pub,
                res_reg_priv,
                res_rev_reg,
                res_aux_params
            ) = (
                write_object("cred-pub-key.dat", &Some(credential_public_key)),
                write_object("cred-priv-key.dat", &Some(credential_private_key)),
                write_object("correctness-proof.dat", &Some(credential_key_correctness_proof)),
                write_object("reg-pub-key.dat", &Some(registry_public_key)),
                write_object("reg-priv-key.dat", &Some(registry_private_key)),
                write_object("rev-reg.dat", &Some(rev_registry)),
                write_object("simple-tails-accessor.dat", &simple_tails_accessor)
            );

            // Check read credential primary key
            let mut contents = String::new();
            read_file(&String::from("cred-pub-key.dat"), &mut contents).unwrap();
            let credential_public_key: Option<GenCredentialPublicKey> = read_object(contents.as_str());
            assert!(credential_public_key.is_some());

            // Check read credential private key
            let mut contents = String::new();
            read_file(&String::from("cred-priv-key.dat"), &mut contents).unwrap();
            let credential_private_key: Option<GenCredentialPrivateKey> = read_object(contents.as_str());
            assert!(credential_private_key.is_some());

            // Check read correctness proof
            let mut contents = String::new();
            read_file(&String::from("correctness-proof.dat"), &mut contents).unwrap();
            let credential_key_correctness_proof: Option<CredentialKeyCorrectnessProof> = read_object(contents.as_str());
            assert!(credential_key_correctness_proof.is_some());

            // Check read Registry Public Key
            let mut contents = String::new();
            read_file(&String::from("reg-pub-key.dat"), &mut contents).unwrap();
            let reg_pub_key: Option<GenRevocationKeyPublic> = read_object(contents.as_str());
            assert!(reg_pub_key.is_some());

            // Check read Registry Private Key
            let mut contents = String::new();
            read_file(&String::from("reg-priv-key.dat"), &mut contents).unwrap();
            let reg_priv_key: Option<GenRevocationKeyPrivate> = read_object(contents.as_str());
            assert!(reg_priv_key.is_some());

            // Check read tails file
            let mut contents = String::new();
            read_file(&String::from("simple-tails-accessor.dat"), &mut contents).unwrap();
            let simple_tails_accessor: Option<SimpleTailsAccessor> = read_object(contents.as_str());
            assert!(simple_tails_accessor.is_some());
        }

        fn test_generic_proof_cks()
        {
            // Basic testing and benchmarking setup
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 100u32;
            let issuance_by_default = true;
            let max_batch_size = 10u32;
            let num_signatures = 10u32;

            // 1. Create credential definition
            let (credential_public_key, credential_private_key,
                credential_key_correctness_proof) =
                Issuer::new_credential_def_generic(
                    &credential_schema,
                    &non_credential_schema,
                    true,
                    RevocationMethod::CKS
                ).unwrap();

            // 2. Create Registry Definition
            let (registry_public_key, registry_private_key, mut rev_registry, mut aux_params) =
                Issuer::new_revocation_registry_generic(
                    &credential_public_key,
                    max_cred_num,
                    issuance_by_default,
                    max_batch_size,
                ).unwrap();

            let simple_tails_accessor = aux_params.unwrap_cks().unwrap();
            let mut rev_reg_delta_init_cks = RevocationRegistryDelta::from_parts(
                None,
                rev_registry.unwrap_cks().unwrap(),
                &HashSet::<u32>::from_iter((1..=max_cred_num).into_iter()),
                &HashSet::<u32>::new()
            );

            // 3. Issue credentials
            let mut prover_data: Vec<GenProverData> = Vec::new();
            for rev_idx in 1..=num_signatures {
                // 3.0 Holder chooses credential values
                let credential_values = get_credential_values(&Prover::new_master_secret().unwrap());
                let credential_blinding_nonce = new_nonce().unwrap();
                // 3.1 Holder blinds secret values
                let (
                    blinded_credential_secrets,
                    credential_secrets_blinding_factors,
                    credential_blinding_correctness_proof
                ) = Prover::blind_credential_secrets_generic(
                    &credential_public_key,
                    &credential_key_correctness_proof,
                    &credential_values,
                    &credential_blinding_nonce,
                ).unwrap();

                // 3.2 Holder requests a signature
                let credential_nonce = new_nonce().unwrap();
                let (mut credential_signature, credential_signature_correctness_proof, rev_reg_delta) =
                    Issuer::sign_credential_with_revoc_generic(
                        &rev_idx.to_string(),
                        &blinded_credential_secrets,
                        &credential_blinding_correctness_proof,
                        &credential_blinding_nonce,
                        &credential_nonce,
                        &credential_values,
                        &credential_public_key,
                        &credential_private_key,
                        rev_idx,
                        max_cred_num,
                        issuance_by_default,
                        &mut rev_registry,
                        &registry_private_key,
                        &simple_tails_accessor
                    ).unwrap();

                // 3.3 Calculate witness (this specific to revocation scheme)
                let mut witness = Witness::new(
                    rev_idx,
                    max_cred_num,
                    false,
                    &rev_reg_delta_init_cks,
                    &simple_tails_accessor,
                ).unwrap();
                // wrap the witness into a generic witness
                let mut witness = GenWitness::CKS(witness);

                // 3.4 Post process the credential
                Prover::process_credential_signature_generic(
                    &mut credential_signature,
                    &credential_values,
                    &credential_signature_correctness_proof,
                    &credential_secrets_blinding_factors,
                    &credential_public_key,
                    &credential_nonce,
                    Some(&registry_public_key),
                    Some(&rev_registry),
                    Some(&witness)
                ).unwrap();

                prover_data.push((rev_idx, credential_values, credential_signature, Some(witness)));
            }

            // 5. Create proof presentation
            let mut nonces: Vec<Nonce> = Vec::new();
            for i in 1..=num_signatures {
                nonces.push(new_nonce().unwrap());
            }

            let sub_proof_request = get_sub_proof_request();
            let proofs = gen_proofs_generic(
                &credential_schema,
                &non_credential_schema,
                &credential_public_key,
                &sub_proof_request,
                &nonces,
                &rev_registry,
                &mut prover_data
            );

            let mut verifier = Verifier::new_proof_verifier().unwrap();
            verifier
                .add_sub_proof_request_generic(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_public_key,
                    Some(&registry_public_key),
                    Some(&rev_registry)
                ).unwrap();

            for i in 0..proofs.len() {
                println!("Verification result for proof {} is {}", i,
                         verifier.verify_generic(&proofs[i], &nonces[i]).unwrap());
            }
        }

        #[test]
        fn test_generic_proof_va()
        {
            // Basic testing and benchmarking setup
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 100u32;
            let issuance_by_default = true;
            let max_batch_size = 10u32;
            let num_signatures = 10u32;

            // 1. Create credential definition
            let (credential_public_key, credential_private_key,
                credential_key_correctness_proof) =
                Issuer::new_credential_def_generic(
                    &credential_schema,
                    &non_credential_schema,
                    true,
                    RevocationMethod::VA
                ).unwrap();

            // 2. Create Registry Definition
            let (registry_public_key, registry_private_key,
                mut rev_registry, mut aux_params) =
                Issuer::new_revocation_registry_generic(
                    &credential_public_key,
                    max_cred_num,
                    issuance_by_default,
                    max_batch_size,
                ).unwrap();


            // 3. Issue credentials
            let mut prover_data: Vec<GenProverData> = Vec::new();
            for rev_idx in 1..=num_signatures {
                // 3.0 Holder chooses credential values
                let credential_values = get_credential_values(&Prover::new_master_secret().unwrap());
                let credential_blinding_nonce = new_nonce().unwrap();
                // 3.1 Holder blinds secret values
                let (
                    blinded_credential_secrets,
                    credential_secrets_blinding_factors,
                    credential_blinding_correctness_proof
                ) = Prover::blind_credential_secrets_generic(
                    &credential_public_key,
                    &credential_key_correctness_proof,
                    &credential_values,
                    &credential_blinding_nonce,
                ).unwrap();

                // 3.2 Holder requests a signature
                let credential_nonce = new_nonce().unwrap();
                let (mut credential_signature, credential_signature_correctness_proof,
                    rev_reg_delta) =
                    Issuer::sign_credential_with_revoc_generic(
                        &rev_idx.to_string(),
                        &blinded_credential_secrets,
                        &credential_blinding_correctness_proof,
                        &credential_blinding_nonce,
                        &credential_nonce,
                        &credential_values,
                        &credential_public_key,
                        &credential_private_key,
                        rev_idx,
                        max_cred_num,
                        issuance_by_default,
                        &mut rev_registry,
                        &registry_private_key,
                        &NoOpRevocationTailsAccessor::new()
                    ).unwrap();

                // 3.3 Calculate witness (this specific to revocation scheme)


                // 3.4 Post process the credential
                Prover::process_credential_signature_generic(
                    &mut credential_signature,
                    &credential_values,
                    &credential_signature_correctness_proof,
                    &credential_secrets_blinding_factors,
                    &credential_public_key,
                    &credential_nonce,
                    Some(&registry_public_key),
                    Some(&rev_registry),
                    None
                ).unwrap();

                prover_data.push((rev_idx, credential_values, credential_signature, None));
            }

            // 5. Create proof presentation
            let mut nonces: Vec<Nonce> = Vec::new();
            for i in 1..=num_signatures {
                nonces.push(new_nonce().unwrap());
            }

            let sub_proof_request = get_sub_proof_request();
            let proofs = gen_proofs_generic(
                &credential_schema,
                &non_credential_schema,
                &credential_public_key,
                &sub_proof_request,
                &nonces,
                &rev_registry,
                &mut prover_data
            );

            let mut verifier = Verifier::new_proof_verifier().unwrap();
            verifier
                .add_sub_proof_request_generic(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_public_key,
                    Some(&registry_public_key),
                    Some(&rev_registry)
                ).unwrap();

            for i in 0..proofs.len() {
                println!("Verification result for proof {} is {}", i,
                         verifier.verify_generic(&proofs[i], &nonces[i]).unwrap());
            }
        }


        #[test]
        fn test_compatibility_with_existing()
        {

            // First we generate credential definition, registry definition, signatures and proofs
            // using the old interface, and then new generic interface to verify the proofs

            // 1. Setup up credential definition
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();

            let max_cred_num = 100u32;
            let issuance_by_default = true;

            let (cred_public_key, cred_private_key,
                cred_key_correctness_proof) =
                Issuer::new_credential_def(
                    &credential_schema,
                    &non_credential_schema,
                    true
                ).unwrap();

            // 2. Setup up revocation registry definition
            let (reg_pub_key, reg_priv_key, mut rev_reg,
                mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &cred_public_key,
                    max_cred_num,
                    issuance_by_default
                ).unwrap();

            let simple_tails_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            let issued = (1..max_cred_num).into_iter().collect::<HashSet<u32>>();
            let revoked: HashSet<u32> = HashSet::new();

            let mut rev_reg_delta = RevocationRegistryDelta::from_parts(
                None,
                &rev_reg,
                &issued,
                &revoked
            );

            let mut prover_data: Vec<ProverData> = Vec::new();

            // 3. Obtain two signatures for rev_idx = 1,2
            for rev_idx in 1..=1 as u32 {
                // 3.1 Issuer creates nonce used by Prover to create correctness proof for blinded secrets
                let blinding_correctness_nonce = new_nonce().unwrap();
                let credential_values = get_credential_values(&Prover::new_master_secret().unwrap());

                // 3.2 Prover blinds master secret
                let (
                    blinded_credential_secrets,
                    credential_secrets_blinding_factors,
                    blinded_credential_secrets_correctness_proof,
                ) = Prover::blind_credential_secrets(
                    &cred_public_key,
                    &cred_key_correctness_proof,
                    &credential_values,
                    &blinding_correctness_nonce,
                ).unwrap();

                // 3.3 Prover creates nonce used by Issuer to create correctness proof for signature
                let signature_correctness_nonce = new_nonce().unwrap();

                // 3.4 Issuer creates and sign credential values
                let (mut credential_signature, signature_correctness_proof, rr_delta) =
                    Issuer::sign_credential_with_revoc(
                        &rev_idx.to_string(),
                        &blinded_credential_secrets,
                        &blinded_credential_secrets_correctness_proof,
                        &blinding_correctness_nonce,
                        &signature_correctness_nonce,
                        &credential_values,
                        &cred_public_key,
                        &cred_private_key,
                        rev_idx,
                        max_cred_num,
                        issuance_by_default,
                        &mut rev_reg,
                        &reg_priv_key,
                        &simple_tails_accessor,
                    ).unwrap();

                // 3.5 Update the witness. Note that since
                // issuance is by default, no need to merge the
                // rr_delta (which is None) with current revocation delta
                let witness = Witness::new(
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &rev_reg_delta,
                    &simple_tails_accessor,
                ).unwrap();

                // 3.6 Post process the received signature
                Prover::process_credential_signature(
                    &mut credential_signature,
                    &credential_values,
                    &signature_correctness_proof,
                    &credential_secrets_blinding_factors,
                    &cred_public_key,
                    &signature_correctness_nonce,
                    Some(&reg_pub_key),
                    Some(&rev_reg),
                    Some(&witness),
                ).unwrap();

                // Store data for prover to make a presentation later.
                prover_data.push((rev_idx, credential_values.try_clone().unwrap(), credential_signature, witness));
            }

            // 4. create a subproof request
            //   4.0 proof_builder::new()
            //   4.1 add_sub_proof_request()
            //   4.2 finalize()
            let sub_proof_request = get_sub_proof_request();
            let mut nonces: Vec<Nonce> = Vec::new();
            nonces.push(new_nonce().unwrap());

            let proofs = gen_proofs(
                max_cred_num,
                issuance_by_default,
                &credential_schema,
                &non_credential_schema,
                &cred_public_key,
                &sub_proof_request,
                &nonces,
                &rev_reg,
                &rev_reg_delta,
                &simple_tails_accessor,
                &mut prover_data);

            /*
         *  Serialize the objects needed for verification
         */

            let sub_proof_request_str = serde_json::to_string::<SubProofRequest>(&sub_proof_request).unwrap();
            let credential_schema_str = serde_json::to_string::<CredentialSchema>(&credential_schema).unwrap();
            let non_credential_schema_str = serde_json::to_string::<NonCredentialSchema>(&non_credential_schema).unwrap();
            let credential_public_key_str = serde_json::to_string::<CredentialPublicKey>(&cred_public_key).unwrap();
            let registry_public_key_str = serde_json::to_string::<Option<RevocationKeyPublic>>(&Some(reg_pub_key)).unwrap();
            let rev_reg_str = serde_json::to_string::<Option<RevocationRegistry>>(&Some(rev_reg)).unwrap();
            let proof_str = serde_json::to_string::<Proof>(&proofs[0]).unwrap();
            let nonce_str = serde_json::to_string::<Nonce>(&nonces[0]).unwrap();

            let sub_proof_schema = SubproofRequestSchema {
                sub_proof_request: sub_proof_request_str,
                credential_schema: credential_schema_str,
                non_credential_schema: non_credential_schema_str,
                credential_public_key: credential_public_key_str,
                registry_public_key: registry_public_key_str,
                revocation_registry: rev_reg_str,
            };


            let proof_schema = ProofSchema { proof: proof_str, nonce: nonce_str };

            let mut verifier = Verifier::new_proof_verifier().unwrap();
            verifier
                .add_sub_proof_request_json(&sub_proof_schema).unwrap();

            let result = verifier.verify_json(&proof_schema).unwrap();
            println!("Verification result is {}", result);
        }

        #[test]
        fn test_compatibility_with_new()
        {

            // First we generate credential definition, registry definition, signatures and proofs
            // using the old interface, and then new generic interface to verify the proofs

            // 1. Setup up credential definition
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();

            let max_cred_num = 100u32;
            let issuance_by_default = true;
            let batch_size = 10u32;

            let (cred_public_key, cred_private_key, cred_key_correctness_proof) =
                Issuer::new_credential_def_generic(
                    &credential_schema,
                    &non_credential_schema,
                    true,
                    RevocationMethod::VA
                ).unwrap();

            // 2. Setup up revocation registry definition
            let (reg_pub_key, reg_priv_key, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_generic(
                    &cred_public_key,
                    max_cred_num,
                    issuance_by_default,
                    batch_size
                ).unwrap();


            let mut prover_data: Vec<GenProverData> = Vec::new();

            // 3. Obtain two signatures for rev_idx = 1,2
            for rev_idx in 1..=1 as u32 {
                // 3.1 Issuer creates nonce used by Prover to create correctness proof for blinded secrets
                let blinding_correctness_nonce = new_nonce().unwrap();
                let credential_values = get_credential_values(&Prover::new_master_secret().unwrap());

                // 3.2 Prover blinds master secret
                let (
                    blinded_credential_secrets,
                    credential_secrets_blinding_factors,
                    blinded_credential_secrets_correctness_proof,
                ) = Prover::blind_credential_secrets_generic(
                    &cred_public_key,
                    &cred_key_correctness_proof,
                    &credential_values,
                    &blinding_correctness_nonce,
                ).unwrap();

                // 3.3 Prover creates nonce used by Issuer to create correctness proof for signature
                let signature_correctness_nonce = new_nonce().unwrap();

                // 3.4 Issuer creates and sign credential values
                let (mut credential_signature, signature_correctness_proof, rr_delta) =
                    Issuer::sign_credential_with_revoc_generic(
                        &rev_idx.to_string(),
                        &blinded_credential_secrets,
                        &blinded_credential_secrets_correctness_proof,
                        &blinding_correctness_nonce,
                        &signature_correctness_nonce,
                        &credential_values,
                        &cred_public_key,
                        &cred_private_key,
                        rev_idx,
                        max_cred_num,
                        issuance_by_default,
                        &mut rev_reg,
                        &reg_priv_key,
                        &NoOpRevocationTailsAccessor::new(),
                    ).unwrap();


                // 3.6 Post process the received signature
                Prover::process_credential_signature_generic(
                    &mut credential_signature,
                    &credential_values,
                    &signature_correctness_proof,
                    &credential_secrets_blinding_factors,
                    &cred_public_key,
                    &signature_correctness_nonce,
                    Some(&reg_pub_key),
                    Some(&rev_reg),
                    None,
                ).unwrap();

                // Store data for prover to make a presentation later.
                prover_data.push((rev_idx, credential_values.try_clone().unwrap(), credential_signature, None));
            }

            // 4. create a subproof request
            //   4.0 proof_builder::new()
            //   4.1 add_sub_proof_request()
            //   4.2 finalize()
            let sub_proof_request = get_sub_proof_request();
            let mut nonces: Vec<Nonce> = Vec::new();
            nonces.push(new_nonce().unwrap());

            let proofs = gen_proofs_generic(
                &credential_schema,
                &non_credential_schema,
                &cred_public_key,
                &sub_proof_request,
                &nonces,
                &rev_reg,
                &mut prover_data);

            /*
         *  Serialize the objects needed for verification
         */

            let sub_proof_request_str = serde_json::to_string::<SubProofRequest>(&sub_proof_request).unwrap();
            let credential_schema_str = serde_json::to_string::<CredentialSchema>(&credential_schema).unwrap();
            let non_credential_schema_str = serde_json::to_string::<NonCredentialSchema>(&non_credential_schema).unwrap();
            let credential_public_key_str = serde_json::to_string::<GenCredentialPublicKey>(&cred_public_key).unwrap();
            let registry_public_key_str = serde_json::to_string::<Option<GenRevocationKeyPublic>>(&Some(reg_pub_key)).unwrap();
            let rev_reg_str = serde_json::to_string::<Option<GenRevocationRegistry>>(&Some(rev_reg)).unwrap();
            let proof_str = serde_json::to_string::<GenProof>(&proofs[0]).unwrap();
            let nonce_str = serde_json::to_string::<Nonce>(&nonces[0]).unwrap();

            let sub_proof_schema = SubproofRequestSchema {
                sub_proof_request: sub_proof_request_str,
                credential_schema: credential_schema_str,
                non_credential_schema: non_credential_schema_str,
                credential_public_key: credential_public_key_str,
                registry_public_key: registry_public_key_str,
                revocation_registry: rev_reg_str,
            };


            let proof_schema = ProofSchema { proof: proof_str, nonce: nonce_str };

            let mut verifier = Verifier::new_proof_verifier().unwrap();
            verifier
                .add_sub_proof_request_json(&sub_proof_schema).unwrap();

            let result = verifier.verify_json(&proof_schema).unwrap();
            println!("Verification result is {}", result);
        }
    }

    #[cfg(test)]
    mod benchmarks {
        use super::*;

        #[test]
        /// registry_size = 100K, 1000K
        fn bench_issuer_new_revocation_def_cks() {
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 100000u32;
            let issuance_by_default = true;
            let max_batch_size = 10u32;

            // 1. Create credential definition
            let (credential_public_key, credential_private_key,
                credential_key_correctness_proof) =
                Issuer::new_credential_def_generic(
                    &credential_schema,
                    &non_credential_schema,
                    true,
                    RevocationMethod::CKS
                ).unwrap();

            // 2. Create Registry Definition
            let mut start = Instant::now();
            let (registry_public_key, registry_private_key, mut rev_registry, mut aux_params) =
                Issuer::new_revocation_registry_generic(
                    &credential_public_key,
                    max_cred_num,
                    issuance_by_default,
                    max_batch_size,
                ).unwrap();

            let simple_tails_accessor = aux_params.unwrap_cks().unwrap();
            println!("Time to create CKS registry for {} credentials is {:?}", max_cred_num, start.elapsed());
        }

        #[test]
        /// registry_size = 100K, 1000K
        fn bench_issuer_new_revocation_def_va() {
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 100000u32;
            let issuance_by_default = true;
            let max_batch_size = 10u32;

            // 1. Create credential definition
            let (credential_public_key, credential_private_key,
                credential_key_correctness_proof) =
                Issuer::new_credential_def_generic(
                    &credential_schema,
                    &non_credential_schema,
                    true,
                    RevocationMethod::VA
                ).unwrap();

            // 2. Create Registry Definition
            let mut start = Instant::now();
            let (registry_public_key, registry_private_key, mut rev_registry, mut aux_params) =
                Issuer::new_revocation_registry_generic(
                    &credential_public_key,
                    max_cred_num,
                    issuance_by_default,
                    max_batch_size,
                ).unwrap();

            let simple_tails_accessor = aux_params.unwrap_va().unwrap();
            println!("Time to create VA registry for {} credentials is {:?}", max_cred_num, start.elapsed());
        }

        #[test]
        /// registry_size = 100K, 1000K
        fn bench_issuer_sign_with_revok_cks() {}

        #[test]
        /// registry_size = 100K, 1000K
        fn bench_issuer_sign_with_revok_va() {}

        #[test]
        /// registry_size = 100K, 1000K
        fn bench_prover_update_signature_cks() {}

        #[test]
        /// registry_size = 100K
        fn bench_prover_generate_proof_cks() {}

        #[test]
        /// registry_size = 100K
        fn bench_prover_generate_proof_va() {}

        #[test]
        /// registry_size = 100K
        fn bench_verifier_verify_proof_cks() {}

        #[test]
        /// registry_size = 100K
        fn bench_verifier_verify_proof_va() {}

    }


}