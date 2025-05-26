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

@JvmInline
value class KeyAttestationJWT(val jwt: SignedJWT) {

    init {
        jwt.ensureSignedNotMAC()
        require(jwt.header.type != null && jwt.header.type.type.equals(KEY_ATTESTATION_JWT_TYPE)) {
            "Invalid Key Attestation JWT. Type must be set to `$KEY_ATTESTATION_JWT_TYPE`"
        }
        requireNotNull(jwt.jwtClaimsSet.issueTime) { "Invalid Key Attestation JWT. Misses iat claim" }
        requireNotNull(jwt.jwtClaimsSet.getListClaim("attested_keys")) {
            "Invalid Key Attestation JWT. Misses attested_keys claim"
        }
    }

    companion object {
        const val KEY_ATTESTATION_JWT_TYPE = "keyattestation+jwt"
    }

    val attestedKeys: List<JWK>
        get() = jwt.jwtClaimsSet.getListClaim("attested_keys").map {
            JWK.parse(it as Map<String, Any>)
        }
}
