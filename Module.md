# Module EUDI OpenId4VCI library

`eudi-lib-jvm-openid4vci-kt` is a Kotlin library, targeting JVM, that supports the [OpenId4VCI](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html) (draft 12) protocol.

In particular, the library focuses on the wallet's role in the protocol to:
- Resolve credential issuer metadata
- Resolve metadata of the authorization server protecting issuance services
- Resolve a credential offer presented by an issuer service
- Negotiate authorization of a credential issuance request
- Submit a credential issuance request

## eu.europa.ec.eudi.openid4vci

## OpenId4VCI features supported

### Authorization Endpoint
Specification defines that a credential's issuance can be requested using authorization_details parameter when using authorization code flow.
Current version of the library does not support that. It only supports requesting issuance using `scope` parameter in the authorization endpoint.

### Token Endpoint
Specification defines that upon a successful token response `authorization_details` is included in response,
if `authorization_details` parameter is used in authorization endpoint. Current version of library is not parsing/utilizing this response attribute.

### Credential Request
Current version of the library implements integrations with issuer's [Crednetial Endpoint](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#name-credential-endpoint),
[Batch Crednetial Endpoint](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#name-batch-credential-endpoint) and
[Deferred Crednetial Endpoint](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#name-deferred-credential-endpoin)
endpoints.

**NOTE:** Attribute `credential_identifier` of a credential request (single or batch) is not yet supported.

#### Credential Format Profiles
OpenId4VCI specification defines several extension points to accommodate the differences across Credential formats. The current version of the library fully supports **ISO mDL** profile and gives some initial support for **IETF SD-JWT VC** profile.

#### Proof Types
OpenId4VCI specification (draft 12) defines two types of proofs that can be included in a credential issuance request, JWT proof type and CWT proof type. Current version of the library supports only JWT proof types
