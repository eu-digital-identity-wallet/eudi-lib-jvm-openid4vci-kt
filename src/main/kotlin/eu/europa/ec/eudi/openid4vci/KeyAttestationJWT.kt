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

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT

data class KeyAttestationJWT(val value: String) {

    val attestedKeys: List<JWK>

    init {
        val jwt = SignedJWT.parse(value)
        jwt.ensureSignedNotMAC()
        require(jwt.header.type != null && jwt.header.type.type.equals(KEY_ATTESTATION_JWT_TYPE)) {
            "Invalid Key Attestation JWT. Type must be set to `$KEY_ATTESTATION_JWT_TYPE`"
        }
        requireNotNull(jwt.jwtClaimsSet.issueTime) { "Invalid Key Attestation JWT. Misses `iat` claim" }

        val attestedKeysClaimEntries = jwt.jwtClaimsSet.getListClaim("attested_keys")
        requireNotNull(attestedKeysClaimEntries) { "Invalid Key Attestation JWT. Misses `attested_keys` claim" }
        require(attestedKeysClaimEntries.isNotEmpty()) {
            "Invalid Key Attestation JWT. `attested_keys` claim must not be empty"
        }

        attestedKeys = attestedKeysClaimEntries.mapIndexed { index, keyObject ->
            require(keyObject is Map<*, *>) {
                "Invalid Key Attestation JWT. Item at index $index in `attested_keys` is not a JSON object."
            }
            try {
                @Suppress("UNCHECKED_CAST")
                val jwk = JWK.parse(keyObject as Map<String, Any>)
                require(!jwk.isPrivate) {
                    "Invalid Key Attestation JWT. Item at index $index in `attested_keys` must be a public key."
                }
                jwk
            } catch (e: java.text.ParseException) {
                throw IllegalArgumentException(
                    "Invalid Key Attestation JWT. Item at index $index in `attested_keys` is not a valid JWK: ${e.message}",
                    e,
                )
            }
        }
    }

    companion object {
        const val KEY_ATTESTATION_JWT_TYPE = "keyattestation+jwt"
    }
}
