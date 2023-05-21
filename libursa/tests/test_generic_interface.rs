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

    fn get_sub_proof_request2() -> SubProofRequest {
        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("age").unwrap();
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


    fn gen_proofs_generic_mix(
        credential_schema_1: &CredentialSchema,
        credential_schema_2: &CredentialSchema,
        non_credential_schema: &NonCredentialSchema,
        credential_pub_key_1: &GenCredentialPublicKey,
        credential_pub_key_2: &GenCredentialPublicKey,
        sub_proof_request_1: &SubProofRequest,
        sub_proof_request_2: &SubProofRequest,
        nonces: &[Nonce],
        rev_reg_1: &GenRevocationRegistry,
        rev_reg_2: &GenRevocationRegistry,
        prover_data_1: &mut [GenProverData],
        prover_data_2: &mut [GenProverData]
    ) -> Vec<GenProof> {
        let mut proofs = Vec::with_capacity(nonces.len());
        let mut total_witness_gen = Duration::new(0, 0);
        let mut total_proving = Duration::new(0, 0);
        for i in 0..nonces.len() {
            let (
                rev_idx_1,
                ref credential_values_1,
                ref credential_signature_1,
                ref witness_1
            ) = prover_data_1[i as usize];

            let (
                rev_idx_2,
                ref credential_values_2,
                ref credential_signature_2,
                ref witness_2
            ) = prover_data_2[i as usize];

            let mut start = Instant::now();

            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();

            start = Instant::now();
            proof_builder
                .add_sub_proof_request_generic(
                    sub_proof_request_1,
                    &credential_schema_1,
                    non_credential_schema,
                    credential_signature_1,
                    credential_values_1,
                    &credential_pub_key_1,
                    Some(&rev_reg_1),
                    witness_1.as_ref()
                ).unwrap();
            proof_builder
                .add_sub_proof_request_generic(
                    sub_proof_request_2,
                    &credential_schema_2,
                    non_credential_schema,
                    credential_signature_2,
                    credential_values_2,
                    &credential_pub_key_2,
                    Some(&rev_reg_2),
                    witness_2.as_ref()
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
        use ursa::cl::verifier::extension::verify_non_mem_witness;
        use super::*;

        #[test]
        fn test_credential_setup_read_write_cks()
        {
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

        #[test]
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
        fn test_revoke_and_proof_cks() {
            // Basic testing and benchmarking setup
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 1000u32;
            let issuance_by_default = true;
            let max_batch_size = 10u32;
            let num_signatures = 20u32;

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
                    issuance_by_default,
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

            // Now we revoke credentials 1..max_batch_size
            let revoke_delta = Issuer::update_revocation_registry(
            rev_registry.unwrap_cks().unwrap(), // gets &mut ref to underlying rev_reg_cks
            max_cred_num,
            BTreeSet::<u32>::new(),
            BTreeSet::<u32>::from_iter((1..=max_batch_size).into_iter()),
            &simple_tails_accessor
            ).unwrap();

            // Update the witnesses
            for i in 0..prover_data.len() {
                let rev_idx = prover_data[i].0;
                prover_data[i].3.as_mut().unwrap().unwrap_cks().unwrap().update(
                    rev_idx,
                    max_cred_num,
                    &revoke_delta,
                    &simple_tails_accessor
                ).unwrap();
            }

            // Create and verify presentations again after revocation

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
        fn test_revoke_and_proof_va() {
            // Basic testing and benchmarking setup
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 1000u32;
            let issuance_by_default = true;
            let max_batch_size = 10u32;
            let num_signatures = 20u32;

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

            let simple_tails_accessor = aux_params.unwrap_va().unwrap();

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

                prover_data.push((rev_idx, credential_values, credential_signature.try_clone().unwrap(), None));

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


            // Now we revoke credentials 1..max_batch_size
            let revoke_delta = Issuer::update_revocation_registry_va(
                rev_registry.unwrap_va().unwrap(),
                registry_private_key.unwrap_va().unwrap(),
                 &simple_tails_accessor.get_domain(),
                 BTreeSet::<u32>::from_iter((1..=max_batch_size).into_iter())
            ).unwrap();

            // Holders update the witness
            for i in 0..prover_data.len() {
                let rev_idx = prover_data[i].0;
                let ldomain = LagrangianDomain::from_parts(
                    simple_tails_accessor.get_domain(),
                    &FieldElement::from(rev_idx)
                ).unwrap();

                prover_data[i].2.unwrap_va().unwrap().r_credential.as_mut().unwrap().witness.update(
                    &revoke_delta,
                    &ldomain
                ).unwrap();
            }

            // Create and verify presentations again after revocation

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
        use std::iter::FromIterator;
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
        fn bench_issuer_sign_with_revok_cks() {
            // Basic testing and benchmarking setup
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 100000u32;
            let issuance_by_default = true;
            let max_batch_size = 10u32;
            let num_signatures = 1000u32;

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
            println!("Issuing {} credentials now", num_signatures);
            let mut start = Instant::now();
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
            }
            println!("Time to issue {} CKS signatures {:?}", num_signatures, start.elapsed());
        }

        #[test]
        /// registry_size = 100K, 1000K
        fn bench_issuer_sign_with_revok_va() {
            // Basic testing and benchmarking setup
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 100000u32;
            let issuance_by_default = true;
            let max_batch_size = 10u32;
            let num_signatures = 1000u32;

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

            let simple_tails_accessor = aux_params.unwrap_va().unwrap();

            // 3. Issue credentials
            println!("Issuing {} credentials now", num_signatures);
            let mut start = Instant::now();
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
            }
            println!("Time to issue {} VA signatures {:?}", num_signatures, start.elapsed());
        }

        #[test]
        /// Generate registry delta for a revocation batch
        fn bench_issuer_generate_delta_cks() {
            // Basic testing and benchmarking setup
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 10000u32;
            let issuance_by_default = true;
            let max_batch_size = 100u32;
            let num_signatures = 1000u32;

            // do the setup
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
            println!("Issuing {} credentials now", num_signatures);
            let mut start = Instant::now();
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
            }
            println!("Time to issue {} CKS signatures {:?}", num_signatures, start.elapsed());

            let mut rev_reg_cks = rev_registry.unwrap_cks().unwrap().clone();
            println!("Now revoke credentials in batches of batch_size {}", max_batch_size);
            let mut start = Instant::now();
            let mut batch_start = 0u32;
            for i in 0..5u32 {
                let revoke_delta =
                    Issuer::update_revocation_registry(
                        &mut rev_reg_cks,
                        max_cred_num,
                        BTreeSet::<u32>::new(),
                        BTreeSet::<u32>::from_iter((batch_start..(batch_start + max_batch_size)).into_iter()),
                        &simple_tails_accessor
                    ).unwrap();
                batch_start = batch_start + max_batch_size;
            }
            println!("Time for 5 updates of batch size {} is {:?}", max_batch_size, start.elapsed());
        }

        #[test]
        /// Generate registry delta for a revocation batch
        fn bench_issuer_generate_delta_va() {
            // Basic testing and benchmarking setup
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 10000u32;
            let issuance_by_default = true;
            let max_batch_size = 100u32;
            let num_signatures = 1000u32;

            // do the setup
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

            let simple_tails_accessor = aux_params.unwrap_va().unwrap();


            // 3. Issue credentials
            println!("Issuing {} credentials now", num_signatures);
            let mut start = Instant::now();
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
            }
            println!("Time to issue {} VA signatures {:?}", num_signatures, start.elapsed());

            let mut rev_reg_va = rev_registry.unwrap_va().unwrap();
            let mut va_registry = VARegistry::new(rev_reg_va);
            println!("Now revoke credentials in batches of batch_size {}", max_batch_size);
            let mut start = Instant::now();
            let mut batch_start = 0u32;
            for i in 0..5u32 {
                let revoke_delta =
                    va_registry.revoke(
                        registry_private_key.unwrap_va().unwrap(),
                        simple_tails_accessor.get_domain(),
                        &Vec::<u32>::from_iter((batch_start..(batch_start + max_batch_size)).into_iter())
                    ).unwrap();
            }
            println!("Time for 5 updates of batch size {} is {:?}", max_batch_size, start.elapsed());
        }

        #[test]
        fn bench_cks() {
            // Basic testing and benchmarking setup
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 100000u32;
            let issuance_by_default = true;
            let max_batch_size = 100u32;
            let num_signatures = 100u32;

            let mut total_process_sig = Duration::from_secs(0);
            let mut total_prover_time = Duration::from_secs(0);
            let mut total_verifier_time = Duration::from_secs(0);

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
                let mut start = Instant::now();
                let mut witness = Witness::new(
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
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

                total_process_sig += start.elapsed();

                prover_data.push((rev_idx, credential_values, credential_signature, Some(witness)));
            }

            // 5. Create proof presentation
            let mut nonces: Vec<Nonce> = Vec::new();
            for i in 1..=num_signatures {
                nonces.push(new_nonce().unwrap());
            }

            let sub_proof_request = get_sub_proof_request();
            let mut start = Instant::now();
            let proofs = gen_proofs_generic(
                &credential_schema,
                &non_credential_schema,
                &credential_public_key,
                &sub_proof_request,
                &nonces,
                &rev_registry,
                &mut prover_data
            );
            total_prover_time += start.elapsed();


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

            let mut start = Instant::now();
            for i in 0..proofs.len() {
                verifier.verify_generic(&proofs[i], &nonces[i]).unwrap();
            }
            total_verifier_time += start.elapsed();

            println!("Total Signature Processing Time for {} signatures {:?}", num_signatures, total_process_sig);
            println!("Total Prover Time for {} presentations {:?}", num_signatures, total_prover_time);
            println!("Total Verifier Time for {} presentations {:?}", num_signatures, total_verifier_time);
        }

        #[test]
        fn bench_va() {
            // Basic testing and benchmarking setup
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 100000u32;
            let issuance_by_default = true;
            let max_batch_size = 10u32;
            let num_signatures = 100u32;

            let mut total_prover_time = Duration::from_secs(0);
            let mut total_verifier_time = Duration::from_secs(0);

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
            let mut start = Instant::now();
            let proofs = gen_proofs_generic(
                &credential_schema,
                &non_credential_schema,
                &credential_public_key,
                &sub_proof_request,
                &nonces,
                &rev_registry,
                &mut prover_data
            );
            total_prover_time += start.elapsed();

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

            let mut start = Instant::now();
            for i in 0..proofs.len() {
                verifier.verify_generic(&proofs[i], &nonces[i]).unwrap();
            }
            total_verifier_time += start.elapsed();

            println!("Total Prover Time for {} presentations {:?}", num_signatures, total_prover_time);
            println!("Total Verifier Time for {} presentations {:?}", num_signatures, total_verifier_time);
        }

        #[test]
        /// registry_size = 100K, 1000K
        fn bench_prover_update_witness_cks() {
            // Basic testing and benchmarking setup
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 100000u32;
            let issuance_by_default = true;
            let max_batch_size = 10u32;
            let num_signatures = 100u32;

            let mut time_wit_update = Duration::from_secs(0);

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

            // Now we revoke credentials 1..max_batch_size
            let revoke_delta = Issuer::update_revocation_registry(
                rev_registry.unwrap_cks().unwrap(), // gets &mut ref to underlying rev_reg_cks
                max_cred_num,
                BTreeSet::<u32>::new(),
                BTreeSet::<u32>::from_iter((1..=max_batch_size).into_iter()),
                &simple_tails_accessor
            ).unwrap();

            // Update the witnesses
            let mut start = Instant::now();
            for i in 0..prover_data.len() {
                let rev_idx = prover_data[i].0;
                prover_data[i].3.as_mut().unwrap().unwrap_cks().unwrap().update(
                    rev_idx,
                    max_cred_num,
                    &revoke_delta,
                    &simple_tails_accessor
                ).unwrap();
            }
            time_wit_update += start.elapsed();

            // Create and verify presentations again after revocation

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

            println!("Time to update {} witnesses {:?}", num_signatures, time_wit_update);

        }


        #[test]
        /// registry size = 100K
        fn bench_prover_update_witness_va() {
            // Basic testing and benchmarking setup
            let credential_schema = get_credential_schema();
            let non_credential_schema = get_non_credential_schema();
            let max_cred_num = 100000u32;
            let issuance_by_default = true;
            let max_batch_size = 10u32;
            let num_signatures = 100u32;

            let mut time_wit_update = Duration::from_secs(0);

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

            let simple_tails_accessor = aux_params.unwrap_va().unwrap();
            // Create registry object for Issuer
            let mut va_registry = VARegistry::new(&rev_registry.unwrap_va().cloned().unwrap());

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

                prover_data.push((rev_idx, credential_values, credential_signature.try_clone().unwrap(), None));

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


            // Now we revoke credentials 1..max_batch_size
            let revoke_delta = va_registry.revoke(
                &registry_private_key.unwrap_va().unwrap(),
                &simple_tails_accessor.get_domain(),
                &Vec::<u32>::from_iter((1..=max_batch_size).into_iter())
            ).unwrap();

            // Issuer updates the registry
            rev_registry = GenRevocationRegistry::VA(RevocationRegistryVA::from_delta(&revoke_delta));

            // Holders update the witness

            for i in 0..prover_data.len() {
                let rev_idx = prover_data[i].0;
                let m2 = prover_data[i].2.unwrap_va().unwrap().r_credential.as_ref().unwrap().m2.clone();

                let ldomain = LagrangianDomain::from_parts(
                    simple_tails_accessor.get_domain(),
                    &FieldElement::from(rev_idx)
                ).unwrap();

                let mut start = Instant::now();
                prover_data[i].2.unwrap_va().unwrap().r_credential.as_mut().unwrap().witness.update(
                    &revoke_delta,
                    &ldomain
                ).unwrap();
                time_wit_update += start.elapsed();
            }

            // Create and verify presentations again after revocation

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

            println!("Time to update {} witnesses {:?}", num_signatures, time_wit_update);
        }
    }

    #[cfg(test)]
    mod tutorial {
        use std::iter::FromIterator;
        use test_generic::{get_credential_schema, get_non_credential_schema};
        use ursa::cl::prover::mocks::blinded_credential_secrets_correctness_proof;
        use super::*;

        #[test]
        fn complete_flow_cks_revocation()
        {
            // This function gives a tutorial introduction to the major interfaces of the
            // cl module, using the generic interface. Broadly, we will do the following
            //  1. Issuer generate(s) schema artefacts
            //  2. Issuer generate(s) revocation registry with CKS revocation type
            //  3. Holder(s) request for signatures from the issuer.
            //  4. Holder(s) generate presentations using obtained signatures
            //  5. Verifier verifies the proof presentations.
            //  6. Issuer revokes a subset of credentials and publishes registry update
            //  7. Holders update their witnesses.
            //  8. Holders generate proofs with updated witnesses.
            //  9. Verifier verifies proofs against updated registry.


            // ******************* 1. Generate Schema Artefacts ***********************************
            let credential_schema = get_credential_schema();
            // above returns a schema object with the following attributes
            // {"name": BigNumber, "age": BigNumber, "sex": BigNumber, "height": BigNumber }
            // all the above attributes are known to the issuer.
            let non_credential_schema = get_non_credential_schema();
            // above returns a scheme object with
            // {"master_secret": BigNumber }

            // finally we call the interface to output the artefacts for the schema defined by
            // credential and non-credential schemas.
            // Create credential definition
            let (credential_public_key, credential_private_key,
                credential_key_correctness_proof) =
                Issuer::new_credential_def_generic(
                    &credential_schema,
                    &non_credential_schema,
                    true,
                    RevocationMethod::CKS
                ).unwrap();
            // The last argument to the above call specifies the revocation scheme to use.
            // The function returns public and private Issuer keys for the schema. The public key
            // is used by verifiers to verify correctness of presentations for the issuer's credentials.

            // *********************** 2. Generate Registry Artefacts ******************************

            // We first define certain parameters associated with registry
            let max_cred_num: u32 = 1000;               // maximum number of credentials supported by registry
            let max_batch_size: u32 = 10;               // maximum size of update
            let issuance_by_default: bool = true;       // are credentials "accumulated" by default.

            // Create Registry Definition
            let (registry_public_key, registry_private_key, mut rev_registry, mut aux_params) =
                Issuer::new_revocation_registry_generic(
                    &credential_public_key,
                    max_cred_num,
                    issuance_by_default,
                    max_batch_size,
                ).unwrap();
            // The above function outputs public and private keys for the revocation registry. The
            // third output rev_registry contains the initial state (accumulator), while the final
            // value aux_params allows generating some (public) auxiliary information specific to the
            // revocation scheme, which allows efficient subsequent operations.
            // For the CKS scheme considered in this example, final returned value allows us to generate
            // the tails vector. We note the use of unwrap_cks() to "downgrade" the generic type to
            // a CKS specific type.
            let mut simple_tails_accessor = aux_params.unwrap_cks().expect("Unable to generate tails vector");
            let mut rev_reg_delta_cks = RevocationRegistryDelta::from_parts(
                None,
                &rev_registry.unwrap_cks().unwrap(),
                &HashSet::<u32>::from_iter((1..=max_cred_num).into_iter()),
                &HashSet::<u32>::new(),
            );


            // 3. ********************** Issue Credentials *****************************************
            let num_signatures: u32 = 100;
            let mut prover_data : Vec<GenProverData> = Vec::new();
            // we issue number of credentials (num_signatures), and store information about each credential
            // in the vector prover_data. This information will be used to create presentations.
            for rev_idx in 1..=num_signatures {
                // 3.1 As a first step, the holder chooses the values for the credential.
                let credential_values = get_credential_values(&Prover::new_master_secret().unwrap());
                // 3.2 Next, the prover blinds the hidden values. It also needs to show proof of knowledge of hidden values, for
                // which it uses a nonce sent by the issuer.
                let credential_secrets_nonce = new_nonce().unwrap();
                let (blinded_credential_secrets, credential_secrets_blinding_factors,
                    blinded_credential_secrets_correctness_proof) =
                    Prover::blind_credential_secrets_generic(
                        &credential_public_key,
                        &credential_key_correctness_proof,
                        &credential_values,
                        &credential_secrets_nonce,
                    ).unwrap();

                // 3.3 Now the holder supplies credential values to the issuer, where
                // the known values are supplied in plain-text, while hidden values are
                // supplied in form of blinded_credential_secrets. The holder also generates
                // a nonce which is used by the issuer to prove correctness of issued signature.
                let credential_correctness_nonce = new_nonce().unwrap();
                let (mut credential_signature, credential_signature_correctness_proof, rev_reg_delta) =
                    Issuer::sign_credential_with_revoc_generic(
                        &rev_idx.to_string(),
                        &blinded_credential_secrets,
                        &blinded_credential_secrets_correctness_proof,
                        &credential_secrets_nonce,
                        &credential_correctness_nonce,
                        &credential_values,
                        &credential_public_key,
                        &credential_private_key,
                        rev_idx,
                        max_cred_num,
                        issuance_by_default,
                        &mut rev_registry,
                        &registry_private_key,
                        &simple_tails_accessor,
                    ).expect("Error issuing the signature");

                // 3.4 Holder initializes the witness
                // In the CKS scheme, the holder has to compute the witness corresponding to
                // the issued non-revocation signature, using the tails. This is a major difference
                // from the VA scheme, where the issuer provides initialized witness as part of
                // the non-revocation signature.
                let mut witness = Witness::new(
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &rev_reg_delta_cks,
                    &simple_tails_accessor,
                ).unwrap();

                // upgrade witness back to generic type
                let mut witness = GenWitness::CKS(witness);


                // 3.5 Holder post-processes the signature (technically a pre-signature).
                Prover::process_credential_signature_generic(
                    &mut credential_signature,
                    &credential_values,
                    &credential_signature_correctness_proof,
                    &credential_secrets_blinding_factors,
                    &credential_public_key,
                    &credential_correctness_nonce,
                    Some(&registry_public_key),
                    Some(&rev_registry),
                    Some(&witness),
                ).expect("Error while post-processing signature");

                prover_data.push((rev_idx, credential_values.try_clone().unwrap(),
                                  credential_signature.try_clone().unwrap(), Some(witness)));
            }

            // ******************** 5. Proof Presentation ******************************************
            // First the verifier generates a nonce for each proof
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

            // ******************** Proof Verification ********************************************
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

            // 7. ********************** Revoke Credential ****************************************
            // Now we revoke credentials 1..max_batch_size
            let revoke_delta = Issuer::update_revocation_registry(
                rev_registry.unwrap_cks().unwrap(), // gets &mut ref to underlying rev_reg_cks
                max_cred_num,
                BTreeSet::<u32>::new(),
                BTreeSet::<u32>::from_iter((1..=max_batch_size).into_iter()),
                &simple_tails_accessor
            ).unwrap();

            // 8. ************************** Update Witnesses *************************************
            let mut start = Instant::now();
            for i in 0..prover_data.len() {
                let rev_idx = prover_data[i].0;
                // prover_data[i].3 gives Option<&GenWitness>, as_mut() gives &mut GenWitness,
                // unwrap_cks() gives Result<&mut Witness>, and unwrap() gives &mut Witness.
                prover_data[i].3.as_mut().unwrap().unwrap_cks().unwrap().update(
                    rev_idx,
                    max_cred_num,
                    &revoke_delta,
                    &simple_tails_accessor
                ).unwrap();
            }

            // 9. ************************ Prove and Verify Presentations Again *******************

            // Create proof presentation
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
        fn complete_workflow_va_revocation()
        {
            // This function gives a tutorial introduction to the major interfaces of the
            // cl module, using the generic interface. Broadly, we will do the following
            //  1. Issuer generate(s) schema artefacts
            //  2. Issuer generate(s) revocation registry with CKS revocation type
            //  3. Holder(s) request for signatures from the issuer.
            //  4. Holder(s) generate presentations using obtained signatures
            //  5. Verifier verifies the proof presentations.
            //  6. Issuer revokes a subset of credentials and publishes registry update
            //  7. Holders update their witnesses.
            //  8. Holders generate proofs with updated witnesses.
            //  9. Verifier verifies proofs against updated registry.


            // ******************* 1. Generate Schema Artefacts ***********************************
            let credential_schema = get_credential_schema();
            // above returns a schema object with the following attributes
            // {"name": BigNumber, "age": BigNumber, "sex": BigNumber, "height": BigNumber }
            // all the above attributes are known to the issuer.
            let non_credential_schema = get_non_credential_schema();
            // above returns a scheme object with
            // {"master_secret": BigNumber }

            // finally we call the interface to output the artefacts for the schema defined by
            // credential and non-credential schemas.
            // Create credential definition
            let (credential_public_key, credential_private_key,
                credential_key_correctness_proof) =
                Issuer::new_credential_def_generic(
                    &credential_schema,
                    &non_credential_schema,
                    true,
                    RevocationMethod::VA
                ).unwrap();
            // The last argument to the above call specifies the revocation scheme to use.
            // The function returns public and private Issuer keys for the schema. The public key
            // is used by verifiers to verify correctness of presentations for the issuer's credentials.

            // *********************** 2. Generate Registry Artefacts ******************************

            // We first define certain parameters associated with registry
            let max_cred_num: u32 = 1000;               // maximum number of credentials supported by registry
            let max_batch_size: u32 = 10;               // maximum size of update
            let issuance_by_default: bool = true;       // are credentials "accumulated" by default.

            // Create Registry Definition
            let (registry_public_key, registry_private_key, mut rev_registry, mut aux_params) =
                Issuer::new_revocation_registry_generic(
                    &credential_public_key,
                    max_cred_num,
                    issuance_by_default,
                    max_batch_size,
                ).unwrap();
            // The above function outputs public and private keys for the revocation registry. The
            // third output rev_registry contains the initial state (accumulator), while the final
            // value aux_params allows generating some (public) auxiliary information specific to the
            // revocation scheme, which allows efficient subsequent operations.
            // For the VA scheme considered in this example, final returned value corresponds to
            // interpolation domain for update polynomials. This allows efficient polynomial arithmetic.
            // We use of unwrap_va() to "downgrade" the generic type AuxParams to
            // a VA specific type NoOpRevTailsGenerator to confirm to the trait RevTailsGenerator
            let mut aux_info_va = aux_params.unwrap_va().expect("Unable to generate tails vector");


            // 3. ********************** Issue Credentials *****************************************
            let num_signatures: u32 = 100;
            let mut prover_data : Vec<GenProverData> = Vec::new();
            // we issue number of credentials (num_signatures), and store information about each credential
            // in the vector prover_data. This information will be used to create presentations.
            for rev_idx in 1..=num_signatures {
                // 3.1 As a first step, the holder chooses the values for the credential.
                let credential_values = get_credential_values(&Prover::new_master_secret().unwrap());
                // 3.2 Next, the prover blinds the hidden values. It also needs to show proof of knowledge of hidden values, for
                // which it uses a nonce sent by the issuer.
                let credential_secrets_nonce = new_nonce().unwrap();
                let (blinded_credential_secrets, credential_secrets_blinding_factors,
                    blinded_credential_secrets_correctness_proof) =
                    Prover::blind_credential_secrets_generic(
                        &credential_public_key,
                        &credential_key_correctness_proof,
                        &credential_values,
                        &credential_secrets_nonce,
                    ).unwrap();

                // 3.3 Now the holder supplies credential values to the issuer, where
                // the known values are supplied in plain-text, while hidden values are
                // supplied in form of blinded_credential_secrets. The holder also generates
                // a nonce which is used by the issuer to prove correctness of issued signature.
                let credential_correctness_nonce = new_nonce().unwrap();
                let (mut credential_signature, credential_signature_correctness_proof, rev_reg_delta) =
                    Issuer::sign_credential_with_revoc_generic(
                        &rev_idx.to_string(),
                        &blinded_credential_secrets,
                        &blinded_credential_secrets_correctness_proof,
                        &credential_secrets_nonce,
                        &credential_correctness_nonce,
                        &credential_values,
                        &credential_public_key,
                        &credential_private_key,
                        rev_idx,
                        max_cred_num,
                        issuance_by_default,
                        &mut rev_registry,
                        &registry_private_key,
                        &aux_info_va,
                    ).expect("Error issuing the signature");

                // 3.4 Holder initializes the witness
                // The VA accumulator scheme does not require witness initialization.

                // 3.5 Holder post-processes the signature (technically a pre-signature).
                Prover::process_credential_signature_generic(
                    &mut credential_signature,
                    &credential_values,
                    &credential_signature_correctness_proof,
                    &credential_secrets_blinding_factors,
                    &credential_public_key,
                    &credential_correctness_nonce,
                    Some(&registry_public_key),
                    Some(&rev_registry),
                    None, // no witness required
                ).expect("Error while post-processing signature");

                prover_data.push((rev_idx, credential_values.try_clone().unwrap(),
                                  credential_signature.try_clone().unwrap(), None));
            }

            // ******************** 5. Proof Presentation ******************************************
            // First the verifier generates a nonce for each proof
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

            // ******************** Proof Verification ********************************************
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

            // 7. ********************** Revoke Credential ****************************************
            // Now we revoke credentials 1..max_batch_size
            // Note the differences from the interface in the CKS scheme.
            // Appropriately we need to "downgrade" generic types to the VA specific types.
            let revoke_delta = Issuer::update_revocation_registry_va(
                rev_registry.unwrap_va().unwrap(), // gets &mut ref to underlying rev_reg_cks
                registry_private_key.unwrap_va().unwrap(),
                aux_info_va.get_domain(),
                BTreeSet::<u32>::from_iter((1..=max_batch_size).into_iter()),
            ).unwrap();

            // 8. ************************** Update Witnesses *************************************
            // Note that witness update differs substantially from the witness update in CKS scheme.
            let mut start = Instant::now();
            for i in 0..prover_data.len() {
                let rev_idx = prover_data[i].0;
                // We need to set up the lagrangian coefficients
                let lagrangian_domain =
                    LagrangianDomain::from_parts(aux_info_va.get_domain(), &FieldElement::from(rev_idx));
                // Get mutable access to witness embedded in non-revocation credential.
                let rev_credential =
                    prover_data[i].2.unwrap_va().unwrap().r_credential.as_mut().unwrap();
                rev_credential.witness.update(
                    &revoke_delta,
                    &lagrangian_domain.unwrap()
                ).unwrap();
            }

            // 9. ************************ Prove and Verify Presentations Again *******************

            // Create proof presentation
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
        fn complete_workflow_mixed_credentials()
        {
            // In this tutorial we will illustrate the generic interface capability by
            // verifying two credentials supporting different revocation types as part
            // of a proof request.

            // ******************* 1. Generate Schema Artefacts ***********************************
            let credential_schema_1 = get_credential_schema();
            // above returns a schema object with the following attributes
            // {"name": BigNumber, "age": BigNumber, "sex": BigNumber, "height": BigNumber }
            // all the above attributes are known to the issuer.
            let non_credential_schema = get_non_credential_schema();
            // above returns a scheme object with
            // {"master_secret": BigNumber }

            // finally we call the interface to output the artefacts for the schema defined by
            // credential and non-credential schemas for issuer 1, who uses CKS revocation mechanism
            // Create credential definition
            let (credential_public_key_1, credential_private_key_1,
                credential_key_correctness_proof_1) =
                Issuer::new_credential_def_generic(
                    &credential_schema_1,
                    &non_credential_schema,
                    true,
                    RevocationMethod::CKS
                ).unwrap();

            // Next we create artefacts for issuer 2 for which uses VA based revocation scheme
            let credential_schema_2 = get_credential_schema();
            let (credential_public_key_2, credential_private_key_2,
                credential_key_correctness_proof_2) =
                Issuer::new_credential_def_generic(
                    &credential_schema_2,
                    &non_credential_schema,
                    true,
                    RevocationMethod::VA
                ).unwrap();

            let (credential_public_key_1, credential_private_key_1,
                credential_key_correctness_proof_1) =
                Issuer::new_credential_def_generic(
                    &credential_schema_1,
                    &non_credential_schema,
                    true,
                    RevocationMethod::CKS
                ).unwrap();


            // *********************** 2. Generate Registry Artefacts ******************************

            // We first define certain parameters associated with registry
            let max_cred_num: u32 = 1000;               // maximum number of credentials supported by registry
            let max_batch_size: u32 = 10;               // maximum size of update
            let issuance_by_default: bool = true;       // are credentials "accumulated" by default.

            // Create Registry Definition for Issuer 1
            let (registry_public_key_1, registry_private_key_1, mut rev_registry_1, mut aux_params_1) =
                Issuer::new_revocation_registry_generic(
                    &credential_public_key_1,
                    max_cred_num,
                    issuance_by_default,
                    max_batch_size,
                ).unwrap();


            // Create Registry Definition for Issuer 2
            let (registry_public_key_2, registry_private_key_2, mut rev_registry_2, mut aux_params_2) =
                Issuer::new_revocation_registry_generic(
                    &credential_public_key_2,
                    max_cred_num,
                    issuance_by_default,
                    max_batch_size,
                ).unwrap();


            // Setup Initial artefacts for Issuer 1
            let mut simple_tails_accessor = aux_params_1.unwrap_cks().expect("Unable to generate tails vector");
            let mut rev_reg_delta_cks = RevocationRegistryDelta::from_parts(
                None,
                &rev_registry_1.unwrap_cks().unwrap(),
                &HashSet::<u32>::from_iter((1..=max_cred_num).into_iter()),
                &HashSet::<u32>::new(),
            );

            // Setup Initial artefacts for Issuer 2
            let mut aux_info_va = aux_params_2.unwrap_va().expect("Unable to obtain evaluation domain");


            // 3. ********************** Issue Credentials *****************************************
            // Issue credentials by Issuer 1
            let num_signatures: u32 = 10;
            let mut prover_data_1 : Vec<GenProverData> = Vec::new();
            // we issue number of credentials (num_signatures), and store information about each credential
            // in the vector prover_data. This information will be used to create presentations.
            let master_secret = Prover::new_master_secret().unwrap();

            for rev_idx in 1..=num_signatures {
                // 3.1 As a first step, the holder chooses the values for the credential.
                let credential_values = get_credential_values(&master_secret.try_clone().unwrap());
                // 3.2 Next, the prover blinds the hidden values. It also needs to show proof of knowledge of hidden values, for
                // which it uses a nonce sent by the issuer.
                let credential_secrets_nonce = new_nonce().unwrap();
                let (blinded_credential_secrets, credential_secrets_blinding_factors,
                    blinded_credential_secrets_correctness_proof) =
                    Prover::blind_credential_secrets_generic(
                        &credential_public_key_1,
                        &credential_key_correctness_proof_1,
                        &credential_values,
                        &credential_secrets_nonce,
                    ).unwrap();
                // 3.3 Now the holder supplies credential values to the issuer, where
                // the known values are supplied in plain-text, while hidden values are
                // supplied in form of blinded_credential_secrets. The holder also generates
                // a nonce which is used by the issuer to prove correctness of issued signature.
                let credential_correctness_nonce = new_nonce().unwrap();
                let (mut credential_signature, credential_signature_correctness_proof, rev_reg_delta) =
                    Issuer::sign_credential_with_revoc_generic(
                        &rev_idx.to_string(),
                        &blinded_credential_secrets,
                        &blinded_credential_secrets_correctness_proof,
                        &credential_secrets_nonce,
                        &credential_correctness_nonce,
                        &credential_values,
                        &credential_public_key_1,
                        &credential_private_key_1,
                        rev_idx,
                        max_cred_num,
                        issuance_by_default,
                        &mut rev_registry_1,
                        &registry_private_key_1,
                        &simple_tails_accessor,
                    ).expect("Error issuing the signature");

                // 3.4 Holder initializes the witness
                // In the CKS scheme, the holder has to compute the witness corresponding to
                // the issued non-revocation signature, using the tails. This is a major difference
                // from the VA scheme, where the issuer provides initialized witness as part of
                // the non-revocation signature.
                let mut witness = Witness::new(
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &rev_reg_delta_cks,
                    &simple_tails_accessor,
                ).unwrap();

                // upgrade witness back to generic type
                let mut witness = GenWitness::CKS(witness);


                // 3.5 Holder post-processes the signature (technically a pre-signature).
                Prover::process_credential_signature_generic(
                    &mut credential_signature,
                    &credential_values,
                    &credential_signature_correctness_proof,
                    &credential_secrets_blinding_factors,
                    &credential_public_key_1,
                    &credential_correctness_nonce,
                    Some(&registry_public_key_1),
                    Some(&rev_registry_1),
                    Some(&witness),
                ).expect("Error while post-processing signature");

                prover_data_1.push((rev_idx, credential_values.try_clone().unwrap(),
                                  credential_signature.try_clone().unwrap(), Some(witness)));

            }

            // Issue Credentials by Issuer 2
            let mut prover_data_2 : Vec<GenProverData> = Vec::new();
            // we issue number of credentials (num_signatures), and store information about each credential
            // in the vector prover_data. This information will be used to create presentations.
            for rev_idx in 1..=num_signatures {
                // 3.1 As a first step, the holder chooses the values for the credential.
                let credential_values = get_credential_values(&master_secret.try_clone().unwrap());
                // 3.2 Next, the prover blinds the hidden values. It also needs to show proof of knowledge of hidden values, for
                // which it uses a nonce sent by the issuer.
                let credential_secrets_nonce = new_nonce().unwrap();
                let (blinded_credential_secrets, credential_secrets_blinding_factors,
                    blinded_credential_secrets_correctness_proof) =
                    Prover::blind_credential_secrets_generic(
                        &credential_public_key_2,
                        &credential_key_correctness_proof_2,
                        &credential_values,
                        &credential_secrets_nonce,
                    ).unwrap();

                // 3.3 Now the holder supplies credential values to the issuer, where
                // the known values are supplied in plain-text, while hidden values are
                // supplied in form of blinded_credential_secrets. The holder also generates
                // a nonce which is used by the issuer to prove correctness of issued signature.
                let credential_correctness_nonce = new_nonce().unwrap();
                let (mut credential_signature, credential_signature_correctness_proof, rev_reg_delta) =
                    Issuer::sign_credential_with_revoc_generic(
                        &rev_idx.to_string(),
                        &blinded_credential_secrets,
                        &blinded_credential_secrets_correctness_proof,
                        &credential_secrets_nonce,
                        &credential_correctness_nonce,
                        &credential_values,
                        &credential_public_key_2,
                        &credential_private_key_2,
                        rev_idx,
                        max_cred_num,
                        issuance_by_default,
                        &mut rev_registry_2,
                        &registry_private_key_2,
                        &aux_info_va,
                    ).expect("Error issuing the VA signature");

                // 3.4 Holder initializes the witness
                // The VA accumulator scheme does not require witness initialization.

                // 3.5 Holder post-processes the signature (technically a pre-signature).
                Prover::process_credential_signature_generic(
                    &mut credential_signature,
                    &credential_values,
                    &credential_signature_correctness_proof,
                    &credential_secrets_blinding_factors,
                    &credential_public_key_2,
                    &credential_correctness_nonce,
                    Some(&registry_public_key_2),
                    Some(&rev_registry_2),
                    None, // no witness required
                ).expect("Error while post-processing signature");

                prover_data_2.push((rev_idx, credential_values.try_clone().unwrap(),
                                  credential_signature.try_clone().unwrap(), None));
            }


            // Nonces for proof presentations
            let mut nonces: Vec<Nonce> = Vec::new();
            for i in 1..=num_signatures {
                nonces.push(new_nonce().unwrap());
            }

            // Mixed proof presentation and verification
            let sub_proof_request_1 = get_sub_proof_request();
            let sub_proof_request_2 = get_sub_proof_request2();
            let proofs = gen_proofs_generic_mix(
                &credential_schema_1,
                &credential_schema_2,
                &non_credential_schema,
                &credential_public_key_1,
                &credential_public_key_2,
                &sub_proof_request_1,
                &sub_proof_request_2,
                &nonces,
                &rev_registry_1,
                &rev_registry_2,
                &mut prover_data_1,
                &mut prover_data_2
            );

            // verify presentations consisting of two subproofs.
            for i in 0..proofs.len() {
            let mut verifier = Verifier::new_proof_verifier().unwrap();
            verifier.add_common_attribute("master_secret").unwrap();
            verifier
                .add_sub_proof_request_generic(
                    &sub_proof_request_1,
                    &credential_schema_1,
                    &non_credential_schema,
                    &credential_public_key_1,
                    Some(&registry_public_key_1),
                    Some(&rev_registry_1)
                ).unwrap();
            verifier
                .add_sub_proof_request_generic(
                    &sub_proof_request_2,
                    &credential_schema_2,
                    &non_credential_schema,
                    &credential_public_key_2,
                    Some(&registry_public_key_2),
                    Some(&rev_registry_2)
                ).unwrap();



                println!("Verification result for proof {} is {}", i,
                         verifier.verify_generic(&proofs[i as usize], &nonces[i as usize]).unwrap());
            }

        }


    }

}