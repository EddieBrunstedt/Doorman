use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs_proto::{
    AllowCredentials, CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, ResidentKeyRequirement,
};

#[derive(Clone)]
struct DiscoverableCredential {
    credential_id: Vec<u8>,
    user_handle: Vec<u8>,
}

// SoftPasskey cannot hold discoverable credentials, so this remembers each
// passkey it registers and answers a discoverable login the way a resident
// authenticator would: by picking the passkey and returning its user handle.
pub struct ResidentAuthenticator {
    inner: SoftPasskey,
    origin: Url,
    discoverable_credentials: Vec<DiscoverableCredential>,
}

impl ResidentAuthenticator {
    pub fn new(origin: &Url) -> Self {
        Self {
            inner: SoftPasskey::new(true),
            origin: origin.clone(),
            discoverable_credentials: Vec::new(),
        }
    }

    pub fn credential_ids(&self) -> Vec<Vec<u8>> {
        self.discoverable_credentials
            .iter()
            .map(|c| c.credential_id.clone())
            .collect()
    }

    pub fn do_registration(
        &mut self,
        challenge: CreationChallengeResponse,
    ) -> RegisterPublicKeyCredential {
        assert_resident_registration_options(&challenge);

        let user_handle = challenge.public_key.user.id.clone();
        let mut compatible = challenge;
        let selection = compatible
            .public_key
            .authenticator_selection
            .as_mut()
            .expect("passkey registration includes authenticator selection");
        selection.require_resident_key = false;
        selection.resident_key = None;

        let response = self
            .inner
            .do_registration(self.origin.clone(), compatible)
            .expect("authenticator register");
        self.discoverable_credentials.push(DiscoverableCredential {
            credential_id: response.raw_id.clone(),
            user_handle,
        });
        response
    }

    pub fn do_authentication(
        &mut self,
        challenge: RequestChallengeResponse,
        credential_id: &[u8],
    ) -> PublicKeyCredential {
        self.do_authentication_inner(challenge, credential_id, true)
    }

    pub fn do_authentication_without_user_handle(
        &mut self,
        challenge: RequestChallengeResponse,
        credential_id: &[u8],
    ) -> PublicKeyCredential {
        self.do_authentication_inner(challenge, credential_id, false)
    }

    pub fn do_scoped_authentication(
        &mut self,
        challenge: RequestChallengeResponse,
    ) -> PublicKeyCredential {
        assert!(
            !challenge.public_key.allow_credentials.is_empty(),
            "re-auth challenge must be allow-list scoped"
        );
        self.inner
            .do_authentication(self.origin.clone(), challenge)
            .expect("authenticator auth")
    }

    fn do_authentication_inner(
        &mut self,
        challenge: RequestChallengeResponse,
        credential_id: &[u8],
        include_user_handle: bool,
    ) -> PublicKeyCredential {
        assert_discoverable_request_options(&challenge);
        let resident = self
            .discoverable_credentials
            .iter()
            .find(|c| c.credential_id == credential_id)
            .cloned()
            .expect("the test authenticator holds the discoverable credential");

        let mut compatible = challenge;
        compatible.public_key.allow_credentials = vec![AllowCredentials {
            type_: "public-key".to_string(),
            id: resident.credential_id.clone(),
            transports: None,
        }];
        let mut assertion = self
            .inner
            .do_authentication(self.origin.clone(), compatible)
            .expect("authenticator auth");
        assertion.response.user_handle = include_user_handle.then_some(resident.user_handle);
        assertion
    }
}

pub fn assert_resident_registration_options(challenge: &CreationChallengeResponse) {
    let selection = challenge
        .public_key
        .authenticator_selection
        .as_ref()
        .expect("registration includes authenticator selection");
    assert!(
        selection.require_resident_key,
        "registration must require resident keys"
    );
    assert_eq!(
        selection.resident_key,
        Some(ResidentKeyRequirement::Required),
        "registration must set residentKey=required"
    );
}

pub fn assert_discoverable_request_options(challenge: &RequestChallengeResponse) {
    assert!(
        challenge.public_key.allow_credentials.is_empty(),
        "discoverable auth must not send allowCredentials"
    );
}
