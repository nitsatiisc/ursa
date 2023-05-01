extern crate ursa;
extern crate time_graph;
extern crate serde;
extern crate serde_json;
extern crate amcl_wrapper;
extern crate num_traits;

mod test_new_acc_benchmarks {
    use std::fs::File;
    use std::io::{Read, Write};
    use serde::de::Unexpected::Str;
    use ursa::cl::{CredentialSchema, CredentialSignature, CredentialSignatureVA, CredentialValues, GenCredentialSignature, GenWitness, MasterSecret, NonCredentialSchema, SubProofRequest, Witness};
    use ursa::cl::issuer::Issuer;
    use ursa::cl::verifier::Verifier;

    /// Utility functions
    ///


    /// File I/O functions
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
    fn read_object<T>(filename: &str) -> Option<T> {
        let mut contents: String = String::new();
        let res = read_file(&String::from(filename), &mut contents);
        if res.is_ok() {
            let obj: T = serde_json::from_str(contents.as_str());
            obj
        } else {
            None
        }
    }

    fn write_object<T>(filename: &str, obj: &Option<T>) -> std::io::Result<()> {
        let contents = serde_json::to_string_pretty(obj).unwrap();
        write_file(&String::from(filename), &contents)
    }


    /// Functions to create test artefacts
    pub fn get_credential_schema() -> CredentialSchema {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        credential_schema_builder.finalize().unwrap()
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

    #[cfg(test)]
    mod tests {

        // Individual tests


    }


}