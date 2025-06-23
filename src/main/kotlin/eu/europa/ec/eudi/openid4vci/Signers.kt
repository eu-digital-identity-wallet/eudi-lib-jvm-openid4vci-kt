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
import eu.europa.ec.eudi.openid4vci.internal.NumericInstantSerializer
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
import java.time.Instant
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

internal fun interface JwtSigner<in Claims> {
    suspend fun sign(claims: Claims): String

    companion object {
        inline operator fun <reified Claims, PUB> invoke(
            signer: Signer<PUB>,
            noinline customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
        ): JwtSigner<Claims> = DefaultJwtSigner(serializer(), signer, customizeHeader)
    }
}

private suspend fun <PUB> SignOp<PUB>.signJwt(header: JsonObject, claims: JsonObject): String {
    // Base64Url encode header and claims
    val base64UrlEncoder = Base64.getUrlEncoder().withoutPadding()
    val headerB64 = base64UrlEncoder.encodeToString(header.toString().toByteArray(Charsets.UTF_8))
    val claimsB64 = base64UrlEncoder.encodeToString(claims.toString().toByteArray(Charsets.UTF_8))

    val signingInput: ByteArray = "$headerB64.$claimsB64".toByteArray(Charsets.US_ASCII)

    val signatureB64 = operation.sign(signingInput).map {
        base64UrlEncoder.encodeToString(it.transcodeSignatureToConcat(signingAlgorithm))
    }.getOrThrow()

    return "$headerB64.$claimsB64.$signatureB64"
}

internal class DefaultJwtSigner<Claims, PUB>(
    private val serializer: KSerializer<Claims>,
    private val signer: Signer<PUB>,
    private val customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
) : JwtSigner<Claims> {

    override suspend fun sign(
        claims: Claims,
    ): String = run {
        val signOp = signer.authenticate()

        val headerJson = buildJsonObject {
            requireNotNull(signOp.signingAlgorithm.toJoseECAlg()) {
                "Unsupported signing algorithm: $signOp.signingAlgorithm"
            }.let {
                put("alg", it.name)
            }
            customizeHeader(signOp.publicMaterial)
        }
        val claimsJson = Json.encodeToJsonElement(serializer, claims).jsonObject

        signOp.signJwt(headerJson, claimsJson)
    }

    companion object {
        inline operator fun <reified Claims, PUB> invoke(
            signer: Signer<PUB>,
            noinline customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
        ): DefaultJwtSigner<Claims, PUB> = DefaultJwtSigner(serializer(), signer, customizeHeader)
    }
}

@Serializable
data class JwtProofClaims(
    @SerialName("aud") val audience: String,
    @Serializable(with = NumericInstantSerializer::class)
    @SerialName("iat") val issuedAt: Instant,
    @SerialName("iss") val issuer: String?,
    @SerialName("nonce") val nonce: String?, // TODO GD use CNonce type
)

private fun JsonObjectBuilder.jwtProofHeader(key: JwtBindingKey) {
    put("typ", "openid4vci-proof+jwt")
    when (key) {
        is JwtBindingKey.Did -> {
            put("kid", key.identity)
        }
        is JwtBindingKey.Jwk -> {
            put("jwk", key.jwk.asJsonElement())
        }
        is JwtBindingKey.X509 -> {
            put("x5c", key.chain.asJsonElement())
        }
    }
}

class JwtProofSigner(
    private val signer: Signer<JwtBindingKey>,
    private val customizeHeader: JsonObjectBuilder.(JwtBindingKey) -> Unit = {},
) {
    suspend fun sign(claims: JwtProofClaims): String {
        return JwtSigner<JwtProofClaims, JwtBindingKey>(
            signer,
        ) { pubKey ->
            jwtProofHeader(pubKey)
            customizeHeader(pubKey)
        }.sign(claims)
    }
}

class JwtProofsSigner(
    private val signer: BatchSigner<JwtBindingKey>,
    private val customizeHeader: JsonObjectBuilder.(JwtBindingKey) -> Unit = {},
) {
    suspend fun sign(claims: JwtProofClaims): List<Pair<JwtBindingKey, String>> {
        val operations = signer.authenticate().operations
        val claimsJson = Json.encodeToJsonElement(claims).jsonObject

        return operations.map { signOp ->
            val (alg, _, pubKey) = signOp
            val headerJson = buildJsonObject {
                requireNotNull(alg.toJoseECAlg()) {
                    "Unsupported signing algorithm: $alg"
                }.let {
                    put("alg", it.name)
                }
                jwtProofHeader(pubKey)
                customizeHeader(pubKey)
            }
            pubKey to signOp.signJwt(headerJson, claimsJson)
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
