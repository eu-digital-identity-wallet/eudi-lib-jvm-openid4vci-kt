package eu.europa.ec.eudi.openid4vci.internal

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.openid4vci.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.util.*
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

@OptIn(ExperimentalContracts::class)
internal suspend fun <PUB, R> Signer<PUB>.use(block: suspend (SignOp<PUB>) -> R): R {
    contract {
        callsInPlace(block, InvocationKind.AT_MOST_ONCE)
    }

    val signOp = authenticate()
    try {
        return block(signOp)
    } finally {
        release(signOp)
    }
}

@OptIn(ExperimentalContracts::class)
internal suspend fun <PUB, R> BatchSigner<PUB>.use(block: suspend (BatchSignOp<PUB>) -> R): R {
    contract {
        callsInPlace(block, InvocationKind.AT_MOST_ONCE)
    }

    val signOps = authenticate()
    try {
        return block(signOps)
    } finally {
        release(signOps)
    }
}

internal fun <PUB> SignOp<PUB>.header(
    customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
): JsonObject = buildJsonObject {
    put("alg", this@header.signingAlgorithm.toJoseAlg().name)
    customizeHeader(this@header.publicMaterial)
}

internal suspend fun <PUB> SignOp<PUB>.signJwt(header: JsonObject, claims: JsonObject): String {
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


internal fun ByteArray.transcodeSignatureToConcat(signingAlgorithm: String): ByteArray {
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

internal fun String.toJoseAlg(): JWSAlgorithm =
    this.toJoseECAlg() ?: JWSAlgorithm.parse(this)

internal fun String.toJoseECAlg(): JWSAlgorithm? = when (this) {
    "SHA256withECDSA" -> JWSAlgorithm.ES256
    "SHA384withECDSA" -> JWSAlgorithm.ES384
    "SHA512withECDSA" -> JWSAlgorithm.ES512
    else -> null
}

internal fun SignOperation.Companion.forJavaEcPrivateKey(
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

internal fun <PUB> Signer.Companion.forEcPrivateKey(
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

    override suspend fun release(signOp: SignOp<PUB>?) {
        // Nothing to do for releasing
    }
}

internal fun <PUB> BatchSigner.Companion.forEcPrivateKeys(
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

    override suspend fun release(signOps: BatchSignOp<PUB>?) {
        // Nothing to do for releasing
    }
}

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
