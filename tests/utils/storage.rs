use anoncreds::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
use anoncreds::data_types::credential::Credential;
use anoncreds::data_types::link_secret::LinkSecret;
use anoncreds::data_types::rev_reg_def::{
    RevocationRegistryDefinition, RevocationRegistryDefinitionId,
    RevocationRegistryDefinitionPrivate,
};
use anoncreds::data_types::schema::{Schema, SchemaId};
use anoncreds::data_types::w3c::credential::{CredentialAttributes, CredentialAttributeValue, W3CCredential};
use anoncreds::types::{CredentialDefinitionPrivate, CredentialKeyCorrectnessProof, CredentialOffer, CredentialRequest, CredentialRequestMetadata, CredentialRevocationConfig, CredentialRevocationState, CredentialValues, Presentation, PresentationRequest, PresentCredentials, RevocationStatusList};
use std::collections::{BTreeSet, HashMap};
use serde_json::json;
use sha2::digest::typenum::Le;
use anoncreds::{issuer, prover, verifier, w3c};
use anoncreds::data_types::nonce::Nonce;
use anoncreds::data_types::pres_request::PredicateTypes;
use anoncreds::data_types::w3c::presentation_proof::{PredicateAttribute, PredicateAttributeType};
use anoncreds::tails::TailsFileWriter;
use crate::utils::{CredentialFormat, Credentials, fixtures, PresentationFormat, Presentations};

#[derive(Debug)]
pub struct StoredCredDef {
    pub private: CredentialDefinitionPrivate,
    pub key_proof: CredentialKeyCorrectnessProof,
}

#[derive(Debug)]
pub struct StoredRevDef {
    pub public: RevocationRegistryDefinition,
    pub private: RevocationRegistryDefinitionPrivate,
}

#[derive(Debug, Default)]
pub struct Ledger<'a> {
    // CredentialDefinition does not impl Clone
    pub cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
    pub schemas: HashMap<SchemaId, Schema>,
    pub rev_reg_defs: HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition>,
    pub revocation_list: HashMap<&'a str, HashMap<u64, RevocationStatusList>>,
}

impl<'a> Ledger<'a> {
    pub fn resolve_schemas(
        schema_id: &str,
        schema: &Schema,
    ) -> HashMap<SchemaId, Schema> {
        let mut schemas = HashMap::new();
        let schema_id = SchemaId::new_unchecked(schema_id);
        schemas.insert(schema_id, schema.clone());
        schemas
    }

    pub fn resolve_cred_defs(
        cred_def_id: &str,
        gvt_cred_def: &CredentialDefinition,
    ) -> HashMap<CredentialDefinitionId, CredentialDefinition> {
        let mut cred_defs = HashMap::new();
        let cred_def_id = CredentialDefinitionId::new_unchecked(cred_def_id);
        cred_defs.insert(cred_def_id, gvt_cred_def.try_clone().unwrap());
        cred_defs
    }

    pub fn resolve_rev_reg_defs(
        rev_reg_def_id: &str,
        rev_reg_def: &RevocationRegistryDefinition,
    ) -> HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition> {
        let rev_reg_def_id = RevocationRegistryDefinitionId::new_unchecked(rev_reg_def_id);
        let rev_reg_def_map =
            HashMap::from([(rev_reg_def_id, rev_reg_def.clone())]);
        rev_reg_def_map
    }
}

// A struct for keeping all issuer-related objects together
#[derive(Debug, Default)]
pub struct IssuerWallet<'a> {
    // cred_def_id: StoredRevDef
    pub cred_defs: HashMap<&'a str, StoredCredDef>,
    // revocation_reg_id: StoredRevDef
    pub rev_defs: HashMap<&'a str, StoredRevDef>,
}

impl<'a> IssuerWallet<'a> {
    pub fn create_schema<'b>(&'b self, name: &'b str) -> (Schema, &str) {
        fixtures::create_schema(name)
    }

    pub fn create_cred_def<'b>(
        &'b self,
        schema: &'b Schema,
        support_revocation: bool,
    ) -> (
        (
            CredentialDefinition,
            CredentialDefinitionPrivate,
            CredentialKeyCorrectnessProof,
        ),
        &str,
    ) {
        fixtures::create_cred_def(schema, support_revocation)
    }

    pub fn create_revocation_registry<'b>(
        &self,
        cred_def: &CredentialDefinition,
        time: Option<u64>,
        issuance_by_default: bool,
    ) -> (
        &'b str,
        RevocationRegistryDefinition,
        RevocationRegistryDefinitionPrivate,
        RevocationStatusList
    ) {
        // Create tails file writer
        let mut tf = TailsFileWriter::new(None);

        let ((rev_reg_def, rev_reg_def_priv), rev_reg_def_id) =
            fixtures::create_rev_reg_def(cred_def, &mut tf);

        // Issuer creates revocation status list - to be put on the ledger
        let revocation_status_list = fixtures::create_revocation_status_list(
            cred_def,
            &rev_reg_def,
            &rev_reg_def_priv,
            time,
            issuance_by_default,
        );
        (
            rev_reg_def_id,
            rev_reg_def,
            rev_reg_def_priv,
            revocation_status_list
        )
    }

    pub fn create_credential_offer(
        &self,
        schema_id: &str,
        cred_def_id: &str,
        correctness_proof: &CredentialKeyCorrectnessProof,
    ) -> CredentialOffer {
        issuer::create_credential_offer(
            schema_id.try_into().unwrap(),
            cred_def_id.try_into().unwrap(),
            correctness_proof,
        )
            .expect("Error creating credential offer")
    }

    pub fn create_credential(
        &self,
        format: &CredentialFormat,
        cred_def: &CredentialDefinition,
        cred_def_private: &CredentialDefinitionPrivate,
        cred_offer: &CredentialOffer,
        cred_request: &CredentialRequest,
        cred_values: CredentialValues,
        revocation_config: Option<CredentialRevocationConfig>,
        time_create_rev_status_list: Option<u64>,
        credential_rev_index: Option<u32>,
    ) -> (Credentials, Option<RevocationStatusList>, Option<u64>) {
        let revocation_config_copy = revocation_config.as_ref().map(|revocation_config| CredentialRevocationConfig {
            reg_def: revocation_config.reg_def,
            reg_def_private: revocation_config.reg_def_private,
            registry_idx: credential_rev_index.unwrap_or_default(),
            status_list: revocation_config.status_list,
        });
        let credential = match format {
            CredentialFormat::Legacy => {
                let issue_cred = issuer::create_credential(
                    cred_def,
                    cred_def_private,
                    &cred_offer,
                    &cred_request,
                    cred_values,
                    revocation_config_copy,
                )
                    .expect("Error creating credential");
                Credentials::Legacy(issue_cred)
            }
            CredentialFormat::W3C => {
                let issue_cred = w3c::issuer::create_credential(
                    cred_def,
                    cred_def_private,
                    &cred_offer,
                    &cred_request,
                    CredentialAttributes::from(&cred_values),
                    revocation_config_copy,
                    None,
                )
                    .expect("Error creating credential");
                Credentials::W3C(issue_cred)
            }
        };

        let (issued_rev_status_list, time_after_creating_cred) = match revocation_config {
            Some(revocation_config) => {
                let credential_rev_index = credential_rev_index.expect("Revocation index is not provided");
                let time_create_rev_status_list = time_create_rev_status_list.expect("Revocation time is not provided");
                let time_after_creating_cred = time_create_rev_status_list + 1;
                let issued_rev_status_list = issuer::update_revocation_status_list(
                    cred_def,
                    &revocation_config.reg_def,
                    &revocation_config.reg_def_private,
                    &revocation_config.status_list,
                    Some(BTreeSet::from([credential_rev_index])),
                    None,
                    Some(time_after_creating_cred),
                )
                    .unwrap();
                (Some(issued_rev_status_list), Some(time_after_creating_cred))
            }
            None => (None, None)
        };

        (
            credential,
            issued_rev_status_list,
            time_after_creating_cred
        )
    }

    pub fn update_revocation_status_list(
        &self,
        rev_status_list: &mut Vec<RevocationStatusList>,
        cred_def: &CredentialDefinition,
        rev_reg_def: &RevocationRegistryDefinition,
        rev_reg_priv: &RevocationRegistryDefinitionPrivate,
        current_list: &RevocationStatusList,
        issued: Option<BTreeSet<u32>>,
        revoked: Option<BTreeSet<u32>>,
        timestamp: Option<u64>,
    ) -> RevocationStatusList {
        let revoked_status_list = issuer::update_revocation_status_list(
            cred_def,
            rev_reg_def,
            rev_reg_priv,
            current_list,
            issued,
            revoked,
            timestamp,
        )
            .unwrap();

        // update rev_status_lists
        rev_status_list.push(revoked_status_list.clone());
        revoked_status_list
    }
}

// A struct for keeping all issuer-related objects together
#[derive(Debug)]
pub struct ProverWallet<'a> {
    entropy: &'static str,
    link_secret_id: &'static str,
    pub credentials: Vec<Credential>,
    pub w3c_credentials: Vec<W3CCredential>,
    pub rev_states:
    HashMap<RevocationRegistryDefinitionId, (Option<CredentialRevocationState>, Option<u64>)>,
    pub link_secret: LinkSecret,
    pub cred_offers: HashMap<&'a str, CredentialOffer>,
    pub cred_reqs: Vec<(CredentialRequest, CredentialRequestMetadata)>,
}

impl<'a> Default for ProverWallet<'a> {
    fn default() -> Self {
        let link_secret = LinkSecret::new().expect("Error creating prover link secret");
        Self {
            entropy: "entropy",
            link_secret_id: "default",
            credentials: vec![],
            rev_states: HashMap::new(),
            link_secret,
            cred_offers: HashMap::new(),
            cred_reqs: vec![],
            w3c_credentials: vec![],
        }
    }
}

impl<'a> ProverWallet<'a> {
    pub fn create_credential_request(
        &self,
        cred_def: &CredentialDefinition,
        credential_offer: &CredentialOffer,
    ) -> (CredentialRequest, CredentialRequestMetadata) {
        // Prover creates a Credential Request
        prover::create_credential_request(
            Some(self.entropy),
            None,
            cred_def,
            &self.link_secret,
            &self.link_secret_id,
            credential_offer,
        )
            .expect("Error creating credential request")
    }

    pub fn store_credential(
        &mut self,
        mut credential: Credentials,
        cred_request_metadata: &CredentialRequestMetadata,
        cred_def: &CredentialDefinition,
        rev_reg_def: Option<&RevocationRegistryDefinition>,
    ) {
        match credential {
            Credentials::Legacy(mut credential) => {
                prover::process_credential(
                    &mut credential,
                    cred_request_metadata,
                    &self.link_secret,
                    cred_def,
                    rev_reg_def,
                )
                    .expect("Error processing credential");
                self.credentials.push(credential);
            }
            Credentials::W3C(mut credential) => {
                w3c::prover::process_credential(
                    &mut credential,
                    cred_request_metadata,
                    &self.link_secret,
                    cred_def,
                    rev_reg_def,
                )
                    .expect("Error processing credential");
                self.w3c_credentials.push(credential);
            }
        }
    }

    pub fn create_or_update_revocation_state(
        &self,
        tails_location: &str,
        rev_reg_def: &RevocationRegistryDefinition,
        rev_status_list: &RevocationStatusList,
        rev_reg_idx: u32,
        rev_state: Option<&CredentialRevocationState>,
        old_rev_status_list: Option<&RevocationStatusList>,
    ) -> CredentialRevocationState {
        prover::create_or_update_revocation_state(
            tails_location,
            &rev_reg_def,
            rev_status_list,
            rev_reg_idx,
            rev_state,
            old_rev_status_list,
        )
            .expect("Error creating revocation state")
    }

    pub fn create_presentation(
        &self,
        format: &PresentationFormat,
        schemas: &HashMap<SchemaId, Schema>,
        cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
        pres_request: &PresentationRequest,
        rev_state_timestamp: Option<u64>,
        rev_state: Option<&CredentialRevocationState>,
    ) -> Presentations {
        match format {
            PresentationFormat::Legacy => {
                let mut present = PresentCredentials::default();
                {
                    // Here we add credential with the timestamp of which the rev_state is updated to,
                    // also the rev_reg has to be provided for such a time.
                    // TODO: this timestamp is not verified by the `NonRevokedInterval`?
                    let mut cred1 = present.add_credential(
                        &self.credentials[0],
                        rev_state_timestamp,
                        rev_state,
                    );
                    cred1.add_requested_attribute("attr1_referent", true);
                    cred1.add_requested_attribute("attr2_referent", false);
                    cred1.add_requested_attribute("attr4_referent", true);
                    cred1.add_requested_predicate("predicate1_referent");
                }

                let mut self_attested = HashMap::new();
                let self_attested_phone = "8-800-300";
                self_attested.insert(
                    "attr3_referent".to_string(),
                    self_attested_phone.to_string(),
                );

                let presentation = prover::create_presentation(
                    pres_request,
                    present,
                    Some(self_attested),
                    &self.link_secret,
                    schemas,
                    cred_defs,
                )
                    .expect("Error creating presentation");
                Presentations::Legacy(presentation)
            }
            PresentationFormat::W3C => {
                let mut present = PresentCredentials::default();
                {
                    // Here we add credential with the timestamp of which the rev_state is updated to,
                    // also the rev_reg has to be provided for such a time.
                    // TODO: this timestamp is not verified by the `NonRevokedInterval`?
                    let mut cred1 = present.add_credential(
                        &self.w3c_credentials[0],
                        rev_state_timestamp,
                        rev_state,
                    );
                    cred1.add_requested_attribute("attr1_referent", true);
                    cred1.add_requested_attribute("attr2_referent", false);
                    cred1.add_requested_attribute("attr4_referent", true);
                    cred1.add_requested_predicate("predicate1_referent");
                }

                let presentation = w3c::prover::create_presentation(
                    pres_request,
                    present,
                    &self.link_secret,
                    schemas,
                    cred_defs,
                )
                    .expect("Error creating presentation");
                Presentations::W3C(presentation)
            }
        }
    }
}

// A struct for keeping all verifier-related objects together
#[derive(Debug, Default)]
pub struct VerifierWallet {}

impl VerifierWallet {
    pub fn generate_nonce(&self) -> Nonce {
        verifier::generate_nonce().expect("Error generating presentation request nonce")
    }

    pub fn verify_presentation(
        &self,
        presentation: &Presentations,
        pres_req: &PresentationRequest,
        schemas: &HashMap<SchemaId, Schema>,
        cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
        rev_reg_defs: Option<&HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition>>,
        rev_status_lists: Option<Vec<RevocationStatusList>>,
        nonrevoke_interval_override: Option<
            &HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>,
        >,
    ) -> bool {
        match presentation {
            Presentations::Legacy(presentation) => {
                verifier::verify_presentation(
                    presentation,
                    pres_req,
                    schemas,
                    cred_defs,
                    rev_reg_defs,
                    rev_status_lists,
                    nonrevoke_interval_override,
                )
                    .expect("Error verifying presentation")
            }
            Presentations::W3C(presentation) => {
                w3c::verifier::verify_presentation(
                    presentation,
                    pres_req,
                    schemas,
                    cred_defs,
                    rev_reg_defs,
                    rev_status_lists,
                    nonrevoke_interval_override,
                )
                    .expect("Error verifying presentation")
            }
        }
    }

    pub fn verify_presentation_data(
        &self,
        presentation: &Presentations) {
        match presentation {
            Presentations::Legacy(presentation) => {
                // Verifier verifies presentation
                assert_eq!(
                    "Alex",
                    presentation
                        .requested_proof
                        .revealed_attrs
                        .get("attr1_referent")
                        .unwrap()
                        .raw
                );

                assert_eq!(
                    0,
                    presentation
                        .requested_proof
                        .unrevealed_attrs
                        .get("attr2_referent")
                        .unwrap()
                        .sub_proof_index
                );

                let revealed_attr_groups = presentation
                    .requested_proof
                    .revealed_attr_groups
                    .get("attr4_referent")
                    .unwrap();

                assert_eq!("Alex", revealed_attr_groups.values.get("name").unwrap().raw);

                assert_eq!(
                    "175",
                    revealed_attr_groups.values.get("height").unwrap().raw
                );
            }
            Presentations::W3C(presentation) => {
                // Verifier verifies presentation
                assert_eq!(
                    &CredentialAttributeValue::Attribute("Alex".to_string()),
                    presentation.verifiable_credential[0]
                        .credential_subject
                        .attributes
                        .0
                        .get("name")
                        .unwrap()
                );
                assert_eq!(
                    &CredentialAttributeValue::Attribute("175".to_string()),
                    presentation.verifiable_credential[0]
                        .credential_subject
                        .attributes
                        .0
                        .get("height")
                        .unwrap()
                );

                assert_eq!(
                    CredentialAttributeValue::Predicate(vec![PredicateAttribute {
                        type_: PredicateAttributeType::AnonCredsPredicate,
                        predicate: PredicateTypes::GE,
                        value: 18,
                    }]),
                    presentation.verifiable_credential[0]
                        .credential_subject
                        .attributes
                        .0
                        .get("age")
                        .cloned()
                        .unwrap()
                );
            }
        }
    }

    pub fn create_presentation_request(
        &self,
        presentation_format: &PresentationFormat,
        issuer_id: Option<&str>,
        non_revoked: Option<serde_json::Value>,
    ) -> PresentationRequest {
        let nonce = self.generate_nonce();
        let mut pres_request = json!({
            "nonce": nonce,
            "name":"pres_req_1",
            "version":"0.1",
            "requested_attributes":{
                "attr1_referent":{
                    "name":"name",
                    "issuer_id": issuer_id
                },
                "attr2_referent":{
                    "name":"sex"
                },
                "attr4_referent":{
                    "names": ["name", "height"]
                }
            },
            "requested_predicates":{
                "predicate1_referent":{"name":"age","p_type":">=","p_value":18}
            },
            "non_revoked": non_revoked
        });

        if let PresentationFormat::Legacy = presentation_format {
            pres_request["requested_attributes"]["attr3_referent"] = json!({ "name":"phone" });
        }

        let pres_request = serde_json::from_value(pres_request)
            .expect("Error creating proof request");
        pres_request
    }
}