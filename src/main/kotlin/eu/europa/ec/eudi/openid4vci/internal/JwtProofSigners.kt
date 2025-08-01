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
package eu.europa.ec.eudi.openid4vci.internal

import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.openid4vci.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.time.Instant

@Serializable
internal data class JwtProofClaims(
    @SerialName("aud") val audience: String,
    @Serializable(with = NumericInstantSerializer::class)
    @SerialName("iat") val issuedAt: Instant,
    @SerialName("iss") val issuer: String? = null,
    @SerialName("nonce") val nonce: String? = null,
)

internal class KeyAttestationJwtProofSigner(
    private val algorithm: JWSAlgorithm,
    private val signOperation: SignOperation<KeyAttestationJWT>,
    private val keyIndex: Int,
) {
    suspend fun sign(claims: JwtProofClaims): String =
        JwtSigner<JwtProofClaims, KeyAttestationJWT>(
            signOperation = signOperation,
            algorithm = algorithm,
            customizeHeader = { key -> keyAttestationJwtProofHeader(key, keyIndex) },
        ).sign(claims)
}

internal class JwtProofsSigner(
    private val algorithm: JWSAlgorithm,
    private val batchSignOperation: BatchSignOperation<JwtBindingKey>,
) {
    suspend fun sign(claims: JwtProofClaims): List<Pair<JwtBindingKey, String>> =
        JwtBatchSigner<JwtProofClaims, JwtBindingKey>(
            algorithm = algorithm,
            batchSignOperation = batchSignOperation,
            customizeHeader = { pubKey -> jwtProofHeader(pubKey) },
        ).sign(claims)
}

internal fun JsonObjectBuilder.jwtProofHeader(key: JwtBindingKey) {
    put("typ", OpenId4VCISpec.JWT_PROOF_TYPE)
    when (key) {
        is JwtBindingKey.Did -> {
            put(OpenId4VCISpec.JOSE_HEADER_KEY_ID, key.identity)
        }
        is JwtBindingKey.Jwk -> {
            put(OpenId4VCISpec.JOSE_HEADER_JWK, key.jwk.asJsonElement())
        }
        is JwtBindingKey.X509 -> {
            put(OpenId4VCISpec.JOSE_HEADER_X5C, key.chain.asJsonElement())
        }
    }
}

internal fun JsonObjectBuilder.keyAttestationJwtProofHeader(keyAttestation: KeyAttestationJWT, keyIndex: Int) {
    check(keyIndex in keyAttestation.attestedKeys.indices) {
        "Key index $keyIndex is out of bounds for attested keys: $keyAttestation.attestedKeys.size"
    }

    put("typ", OpenId4VCISpec.JWT_PROOF_TYPE)
    put(OpenId4VCISpec.JOSE_HEADER_KEY_ID, keyIndex.toString())
    put(OpenId4VCISpec.JOSE_HEADER_KEY_ATTESTATION, keyAttestation.value)
}
