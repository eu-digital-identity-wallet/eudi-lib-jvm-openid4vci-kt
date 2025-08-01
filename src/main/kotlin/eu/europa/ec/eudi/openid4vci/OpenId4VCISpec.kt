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
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html)
 */
object OpenId4VCISpec {

    const val JWT_PROOF_TYPE = "openid4vci-proof+jwt"

    const val JOSE_HEADER_KEY_ID = "kid"
    const val JOSE_HEADER_JWK = "jwk"
    const val JOSE_HEADER_X5C = "x5c"
    const val JOSE_HEADER_KEY_ATTESTATION = "key_attestation"

    const val KEY_ATTESTATION_JWT_TYPE = "keyattestation+jwt"
    const val KEY_ATTESTATION_ATTESTED_KEYS = "attested_keys"
    const val KEY_ATTESTATION_KEY_STORAGE = "key_storage"
    const val KEY_ATTESTATION_USER_AUTHENTICATION = "user_authentication"
}
