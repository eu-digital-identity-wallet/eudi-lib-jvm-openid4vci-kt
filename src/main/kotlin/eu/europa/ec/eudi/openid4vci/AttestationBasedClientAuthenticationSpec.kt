/*
 * Copyright (c) 2023 European Commission
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
