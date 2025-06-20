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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.internal.NumericDateSerializer
import eu.europa.ec.eudi.openid4vci.internal.asJsonElement
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import kotlinx.serialization.serializer
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.util.*

fun interface SignOperation {
    suspend fun sign(input: ByteArray): Result<ByteArray>

    companion object {

        /**
         * @param javaSigningAlgorithm  `"SHA256withECDSA"`
         */
        fun forJavaEcPrivateKey(
            javaSigningAlgorithm: String,
            privateKey: ECPrivateKey,
            secureRandom: SecureRandom?,
            provider: String?,
        ): SignOperation =
            SignOperation { input ->
                withContext(Dispatchers.IO) {
                    runCatching {
                        val signature =
                            provider
                                ?.let { Signature.getInstance(javaSigningAlgorithm, it) }
                                ?: Signature.getInstance(javaSigningAlgorithm)
                        signature.run {
                            secureRandom
                                ?.let { initSign(privateKey, it) }
                                ?: initSign(privateKey)

                            update(input)

                            sign()
                        }
                    }
                }
            }
    }
}

data class SignOp<out PUB>(
    val signingAlgorithm: String,
    val operation: SignOperation,
    val publicMaterial: PUB,
)

data class BatchSignOp<out PUB>(
    val operations: List<SignOp<PUB>>,
)

fun interface Signer<out PUB> {
    suspend fun authenticate(): SignOp<PUB>

    companion object {
        fun <PUB> forEcPrivateKey(
            signingAlgorithm: String,
            privateKey: ECPrivateKey,
            publicMaterial: PUB,
            secureRandom: SecureRandom?,
            provider: String?,
        ): Signer<PUB> = object : Signer<PUB> {
            override suspend fun authenticate(): SignOp<PUB> {
                val sign = SignOperation.forJavaEcPrivateKey(signingAlgorithm, privateKey, secureRandom, provider)
                return SignOp(signingAlgorithm, sign, publicMaterial)
            }
        }
    }
}

interface BatchSigner<out PUB> {
    suspend fun authenticate(): BatchSignOp<PUB>

    companion object {
        fun <PUB> forEcPrivateKeys(
            signingAlgorithm: String,
            ecKeyPairs: Map<ECPrivateKey, PUB>,
            secureRandom: SecureRandom?,
            provider: String?,
        ): BatchSigner<PUB> = object : BatchSigner<PUB> {
            override suspend fun authenticate(): BatchSignOp<PUB> {
                val signOps = ecKeyPairs.map {
                    val sign = SignOperation.forJavaEcPrivateKey(
                        signingAlgorithm,
                        it.key,
                        secureRandom,
                        provider,
                    )
                    SignOp(signingAlgorithm, sign, it.value)
                }
                return BatchSignOp(signOps)
            }
        }
    }
}

fun interface SingleJwtSigner<in Claims> {
    suspend fun sign(claims: Claims): Result<String>
}

class DefaultSingleJwtSigner<Claims, PUB>(
    private val serializer: KSerializer<Claims>,
    private val signer: Signer<PUB>,
    private val customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
) : SingleJwtSigner<Claims> {

    override suspend fun sign(
        claims: Claims,
    ): Result<String> = runCatching {
        val (signingAlgorithm, operation, publicMaterial) = signer.authenticate()

        val headerJson = buildJsonObject {
            requireNotNull(signingAlgorithm.toJoseECAlg()) {
                "Unsupported signing algorithm: $signingAlgorithm"
            }.let {
                put("alg", it.name)
            }
            customizeHeader(publicMaterial)
        }
        val claimsJson = Json.encodeToJsonElement(serializer, claims).jsonObject

        // Base64Url encode header and claims
        val base64UrlEncoder = Base64.getUrlEncoder().withoutPadding()
        val headerB64 = base64UrlEncoder.encodeToString(headerJson.toString().toByteArray(Charsets.UTF_8))
        val claimsB64 = base64UrlEncoder.encodeToString(claimsJson.toString().toByteArray(Charsets.UTF_8))

        val signingInput: ByteArray = "$headerB64.$claimsB64".toByteArray(Charsets.US_ASCII)

        val signatureB64 = operation.sign(signingInput).map {
            base64UrlEncoder.encodeToString(it.transcodeSignatureToConcat(signingAlgorithm))
        }.getOrThrow()

        "$headerB64.$claimsB64.$signatureB64"
    }

    companion object {
        inline operator fun <reified Claims, PUB> invoke(
            signer: Signer<PUB>,
            noinline customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
        ): DefaultSingleJwtSigner<Claims, PUB> = DefaultSingleJwtSigner(serializer(), signer, customizeHeader)
    }
}

@Serializable
data class JwtProofClaims(
    @SerialName("aud") val audience: String,
    @Serializable(with = NumericDateSerializer::class)
    @SerialName("iat") val issuedAt: Date,
    @SerialName("iss") val issuer: String?,
    @SerialName("nonce") val nonce: String?, // TODO GD use CNonce type
)

class JwtProofsSigner(
    private val signer: BatchSigner<JwtBindingKey>,
    private val customizeHeader: JsonObjectBuilder.(JwtBindingKey) -> Unit = {},
) {
    suspend fun sign(claims: JwtProofClaims): List<Pair<JwtBindingKey, SignedJWT>> {
        val (operations) = signer.authenticate()

        return operations.map { signOp ->
            val (alg, operation, pubKey) = signOp
            val headerJson = buildJsonObject {
                requireNotNull(alg.toJoseECAlg()) {
                    "Unsupported signing algorithm: $alg"
                }.let {
                    put("alg", it.name)
                }
                put("typ", "openid4vci-proof+jwt")
                when (pubKey) {
                    is JwtBindingKey.Did -> {
                        put("kid", pubKey.identity)
                    }
                    is JwtBindingKey.Jwk -> {
                        put("jwk", pubKey.jwk.asJsonElement())
                    }
                    is JwtBindingKey.X509 -> {
                        put("x5c", pubKey.chain.asJsonElement())
                    }
                }
                customizeHeader(pubKey)
            }
            val claimsJson = Json.encodeToJsonElement(claims).jsonObject

            // Base64Url encode header and claims
            val base64UrlEncoder = Base64.getUrlEncoder().withoutPadding()
            val headerB64 = base64UrlEncoder.encodeToString(headerJson.toString().toByteArray(Charsets.UTF_8))
            val claimsB64 = base64UrlEncoder.encodeToString(claimsJson.toString().toByteArray(Charsets.UTF_8))

            val signingInput: ByteArray = "$headerB64.$claimsB64".toByteArray(Charsets.US_ASCII)

            val signatureB64 = operation.sign(signingInput).map { signature ->
                base64UrlEncoder.encodeToString(signature.transcodeSignatureToConcat(alg))
            }.getOrThrow()

            val jwtString = "$headerB64.$claimsB64.$signatureB64"
            Pair(pubKey, SignedJWT.parse(jwtString))
        }
    }
}

private fun ByteArray.transcodeSignatureToConcat(signingAlgorithm: String): ByteArray {
    val alg = signingAlgorithm.toJoseECAlg()

    if (!JWSAlgorithm.Family.EC.contains(alg)) {
        return this
    }

    val outputLen = when (alg) {
        JWSAlgorithm.ES256 -> 64
        JWSAlgorithm.ES384 -> 96
        JWSAlgorithm.ES512 -> 132
        else -> error("Unsupported algorithm for JWS signature transcoding: $signingAlgorithm")
    }
    return ECDSA.transcodeSignatureToConcat(this, outputLen)
}

//
// Nimbus Support
//

internal fun <KI> Signer.Companion.fromNimbusEcKey(
    ecPrivateKey: ECKey,
    keyInfo: KI,
    secureRandom: SecureRandom?,
    provider: String?,
): Signer<KI> {
    require(ecPrivateKey.isPrivate)
    val signatureAlgorithm = ecPrivateKey.curve.toJavaSigningAlg()
    return forEcPrivateKey(
        signatureAlgorithm,
        ecPrivateKey.toECPrivateKey(),
        keyInfo,
        secureRandom,
        provider,
    )
}

internal fun <PUB> BatchSigner.Companion.fromNimbusEcKeys(
    ecKeyPairs: Map<ECKey, PUB>,
    secureRandom: SecureRandom?,
    provider: String?,
): BatchSigner<PUB> {
    require(ecKeyPairs.isNotEmpty()) { "At least one EC key pair must be provided" }
    ecKeyPairs.forEach {
        require(it.key.isPrivate) { "All EC keys must be private keys" }
    }
    val signatureAlgorithm = ecKeyPairs.entries.first().key.curve.toJavaSigningAlg()
    return forEcPrivateKeys(
        signatureAlgorithm,
        ecKeyPairs.map {
            it.key.toECPrivateKey() to it.value
        }.toMap(),
        secureRandom,
        provider,
    )
}

private fun Curve.toJavaSigningAlg(): String {
    return when (this) {
        Curve.P_256 -> "SHA256withECDSA"
        Curve.P_384 -> "SHA384withECDSA"
        Curve.P_521 -> "SHA512withECDSA"
        Curve.SECP256K1 -> "SHA256withECDSA"
        else -> error("Unsupported algorithm")
    }
}

private fun String.toJoseECAlg(): JWSAlgorithm? = when (this) {
    "SHA256withECDSA" -> JWSAlgorithm.ES256
    "SHA384withECDSA" -> JWSAlgorithm.ES384
    "SHA512withECDSA" -> JWSAlgorithm.ES512
    else -> null
}
