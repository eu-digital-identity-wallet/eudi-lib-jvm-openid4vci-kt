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
import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.openid4vci.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

@OptIn(ExperimentalContracts::class)
internal suspend fun <PUB, R> Signer<PUB>.use(block: suspend (SignOperation<PUB>) -> R): R {
    contract {
        callsInPlace(block, InvocationKind.AT_MOST_ONCE)
    }

    val signOp = acquire()
    try {
        return block(signOp)
    } finally {
        release(signOp)
    }
}

@OptIn(ExperimentalContracts::class)
internal suspend fun <PUB, R> BatchSigner<PUB>.use(block: suspend (BatchSignOperation<PUB>) -> R): R {
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

internal fun ByteArray.transcodeSignatureToConcat(alg: JWSAlgorithm): ByteArray {
    if (!JWSAlgorithm.Family.EC.contains(alg)) {
        return this
    }
    val outputLen = when (alg) {
        JWSAlgorithm.ES256 -> 64
        JWSAlgorithm.ES384 -> 96
        JWSAlgorithm.ES512 -> 132
        else -> error("Unsupported algorithm for JWS signature transcoding: ${alg.name}")
    }
    return ECDSA.transcodeSignatureToConcat(this, outputLen)
}

internal fun String.toJoseAlg(): JWSAlgorithm =
    this.toJoseECAlg()
        ?: error("Unsupported algorithm for JWS signature: $this")

internal fun String.toJoseECAlg(): JWSAlgorithm? = when (this) {
    "SHA256withECDSA" -> JWSAlgorithm.ES256
    "SHA384withECDSA" -> JWSAlgorithm.ES384
    "SHA512withECDSA" -> JWSAlgorithm.ES512
    else -> null
}

internal fun SignFunction.Companion.forJavaPrivateKey(
    javaSigningAlgorithm: String,
    privateKey: PrivateKey,
    secureRandom: SecureRandom?,
    provider: String?,
): SignFunction =
    SignFunction { input ->
        withContext(Dispatchers.IO) {
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

internal fun <PUB> Signer.Companion.fromEcPrivateKey(
    signingAlgorithm: String,
    privateKey: ECPrivateKey,
    publicMaterial: PUB,
    secureRandom: SecureRandom?,
    provider: String?,
): Signer<PUB> = object : Signer<PUB> {

    override val javaAlgorithm: String
        get() = signingAlgorithm

    override suspend fun acquire(): SignOperation<PUB> {
        val sign = SignFunction.forJavaPrivateKey(signingAlgorithm, privateKey, secureRandom, provider)
        return SignOperation(sign, publicMaterial)
    }

    override suspend fun release(signOperation: SignOperation<PUB>?) {
        // Nothing to do for releasing
    }
}

internal fun <PUB> BatchSigner.Companion.fromECPrivateKeys(
    signingAlgorithm: String,
    ecKeyPairs: Map<ECPrivateKey, PUB>,
    secureRandom: SecureRandom?,
    provider: String?,
): BatchSigner<PUB> = object : BatchSigner<PUB> {

    override val javaAlgorithm: String
        get() = signingAlgorithm

    override suspend fun authenticate(): BatchSignOperation<PUB> {
        val signOperations = ecKeyPairs.map {
            val sign = SignFunction.forJavaPrivateKey(
                signingAlgorithm,
                it.key,
                secureRandom,
                provider,
            )
            SignOperation(sign, it.value)
        }
        return BatchSignOperation(signOperations)
    }

    override suspend fun release(signOps: BatchSignOperation<PUB>?) {
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
    return fromEcPrivateKey(
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
    return fromECPrivateKeys(
        signatureAlgorithm,
        ecKeyPairs.map {
            it.key.toECPrivateKey() to it.value
        }.toMap(),
        secureRandom,
        provider,
    )
}

internal fun Curve.toJavaSigningAlg(): String {
    return when (this) {
        Curve.P_256 -> "SHA256withECDSA"
        Curve.P_384 -> "SHA384withECDSA"
        Curve.P_521 -> "SHA512withECDSA"
        else -> error("Unsupported algorithm")
    }
}
