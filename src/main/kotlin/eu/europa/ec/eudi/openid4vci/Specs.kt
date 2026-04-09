/*
 * Copyright (c) 2023-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.openid4vci

/**
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 */
object OpenId4VCISpec {

    const val JWT_PROOF_TYPE = "openid4vci-proof+jwt"

    const val JOSE_HEADER_KEY_ID = "kid"
    const val JOSE_HEADER_JWK = "jwk"
    const val JOSE_HEADER_X5C = "x5c"
    const val JOSE_HEADER_KEY_ATTESTATION = "key_attestation"

    const val KEY_ATTESTATION_JWT_TYPE = "key-attestation+jwt"
    const val KEY_ATTESTATION_ATTESTED_KEYS = "attested_keys"
    const val KEY_ATTESTATION_KEY_STORAGE = "key_storage"
    const val KEY_ATTESTATION_USER_AUTHENTICATION = "user_authentication"

    const val CREDENTIAL_ISSUER_WELL_KNOWN_PATH = "/.well-known/openid-credential-issuer"

    const val SIGNED_METADATA_JWT_TYPE = "openidvci-issuer-metadata+jwt"
}

/**
 * [OAuth 2.0 Attestation-Based Client Authentication](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07)
 */
object AttestationBasedClientAuthenticationSpec {
    //
    // Authentication Method
    //
    const val ATTESTATION_JWT_CLIENT_AUTHENTICATION_METHOD: String = "attest_jwt_client_auth"

    //
    // JWT Types
    //
    const val ATTESTATION_JWT_TYPE: String = "oauth-client-attestation+jwt"
    const val ATTESTATION_POP_JWT_TYPE: String = "oauth-client-attestation-pop+jwt"

    //
    // OAuth 2.0 Authorization Server Metadata
    //
    const val CHALLENGE_ENDPOINT: String = "challenge_endpoint"
    const val ATTESTATION_JWT_SIGNING_ALGORITHMS_SUPPORTED: String = "client_attestation_signing_alg_values_supported"
    const val ATTESTATION_POP_JWT_SIGNING_ALGORITHMS_SUPPORTED: String = "client_attestation_pop_signing_alg_values_supported"

    //
    // Challenge Endpoint Response
    //
    const val ATTESTATION_CHALLENGE: String = "attestation_challenge"

    //
    // Client Attestation POP JWT Claims
    //
    const val CHALLENGE_CLAIM: String = "challenge"

    //
    // HTTP Headers
    //
    const val CHALLENGE_HEADER: String = "OAuth-Client-Attestation-Challenge"
    const val CLIENT_ATTESTATION_HEADER: String = "OAuth-Client-Attestation"
    const val CLIENT_ATTESTATION_POP_HEADER: String = "OAuth-Client-Attestation-PoP"

    //
    // Error codes
    //
    const val USE_ATTESTATION_CHALLENGE_ERROR: String = "use_attestation_challenge"
    const val USE_FRESH_ATTESTATION_ERROR: String = "use_fresh_attestation"
    const val INVALID_CLIENT_ATTESTATION_ERROR: String = "invalid_client_attestation"
}

/**
 * [JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
 */
object RFC7519 {
    //
    // Registered Header Claims
    //
    const val ALGORITHM: String = "alg"
    const val TYPE: String = "typ"
    const val CONTENT_TYPE: String = "cty"

    //
    // Registered Claims
    //
    const val ISSUER: String = "iss"
    const val SUBJECT: String = "sub"
    const val AUDIENCE: String = "aud"
    const val EXPIRATION_TIME: String = "exp"
    const val NOT_BEFORE: String = "nbf"
    const val ISSUED_AT: String = "iat"
    const val JWT_ID: String = "jti"
}
