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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.internal.JsonSupport
import java.net.URL
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date

class KeyAttestationJWTBuilder(signatureAlgorithm: JWSAlgorithm) {
    private val header = JWSHeader.Builder(signatureAlgorithm)
    private val claimsSet = JWTClaimsSet.Builder()

    fun typ(typ: JOSEObjectType): KeyAttestationJWTBuilder = apply {
        header.type(typ)
    }

    fun x5c(x5c: List<X509Certificate>): KeyAttestationJWTBuilder = apply {
        header.x509CertChain(x5c.map { Base64.encode(it.encoded) })
    }

    fun iat(iat: Instant): KeyAttestationJWTBuilder = apply {
        claimsSet.issueTime(Date.from(iat))
    }

    fun exp(exp: Instant): KeyAttestationJWTBuilder = apply {
        claimsSet.expirationTime(Date.from(exp))
    }

    fun attestedKeys(attestedKeys: List<JWK>): KeyAttestationJWTBuilder = apply {
        claimsSet.claim(OpenId4VCISpec.ATTESTED_KEYS, attestedKeys.map { it.toJSONObject() })
    }

    fun keyStorage(keyStorage: List<AttackPotentialResistance>): KeyAttestationJWTBuilder = apply {
        claimsSet.claim(OpenId4VCISpec.KEY_STORAGE, keyStorage.map { it.value })
    }

    fun userAuthentication(userAuthentication: List<AttackPotentialResistance>): KeyAttestationJWTBuilder = apply {
        claimsSet.claim(OpenId4VCISpec.USER_AUTHENTICATION, userAuthentication.map { it.value })
    }

    fun certification(certification: URL): KeyAttestationJWTBuilder = apply {
        claimsSet.claim(OpenId4VCISpec.CERTIFICATION, certification.toExternalForm())
    }

    fun nonce(nonce: Nonce): KeyAttestationJWTBuilder = apply {
        claimsSet.claim(OpenId4VCISpec.NONCE, nonce.value)
    }

    fun status(status: StatusClaim): KeyAttestationJWTBuilder = apply {
        claimsSet.claim(TokenStatusListSpec.STATUS, JSONObjectUtils.parse(JsonSupport.encodeToString(status)))
    }

    fun keyStorageStatus(keyStorageStatus: KeyStorageStatus): KeyAttestationJWTBuilder = apply {
        claimsSet.claim(TS3.KEY_STORAGE_STATUS, JSONObjectUtils.parse(JsonSupport.encodeToString(keyStorageStatus)))
    }

    fun build(): SignedJWT = SignedJWT(header.build(), claimsSet.build())

    fun build(signer: JWSSigner): SignedJWT = build().apply { sign(signer) }
}
