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

import eu.europa.ec.eudi.openid4vci.internal.toJoseAlg
import eu.europa.ec.eudi.openid4vci.internal.transcodeSignatureToConcat
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.*
import kotlinx.serialization.serializer
import java.util.*

fun interface SignOperation {

    suspend fun sign(input: ByteArray): ByteArray

    companion object
}

data class SignOp<out PUB>(
    val signingAlgorithm: String,
    val operation: SignOperation,
    val publicMaterial: PUB,
)

data class BatchSignOp<out PUB>(
    val operations: List<SignOp<PUB>>,
)

interface Signer<out PUB> {

    suspend fun authenticate(): SignOp<PUB>

    suspend fun release(signOp: SignOp<@UnsafeVariance PUB>?)

    companion object
}

interface BatchSigner<out PUB> {

    suspend fun authenticate(): BatchSignOp<PUB>

    suspend fun release(signOps: BatchSignOp<@UnsafeVariance PUB>?)

    companion object
}

// ///////////////
// JWT Signers //
// ///////////////

fun interface JwtSigner<in Claims> {
    suspend fun sign(claims: Claims): String

    companion object {
        inline operator fun <reified Claims, PUB> invoke(
            signOp: SignOp<PUB>,
            noinline customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
        ): JwtSigner<Claims> = DefaultJwtSigner(serializer(), signOp, customizeHeader)
    }
}

fun interface JwtBatchSigner<in Claims> {
    suspend fun sign(claims: Claims): List<String>

    companion object {

        inline operator fun <reified Claims, PUB> invoke(
            signOps: BatchSignOp<PUB>,
            noinline customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
        ): JwtBatchSigner<Claims> =
            object : JwtBatchSigner<Claims> {

                override suspend fun sign(claims: Claims): List<String> =
                    signOps.operations.map { signOp ->
                        DefaultJwtSigner(
                            serializer = serializer<Claims>(),
                            signOp = signOp,
                            customizeHeader = customizeHeader,
                        ).sign(claims)
                    }
            }
    }
}

class DefaultJwtSigner<Claims, PUB>(
    private val serializer: KSerializer<Claims>,
    private val signOp: SignOp<PUB>,
    private val customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
) : JwtSigner<Claims> {

    override suspend fun sign(
        claims: Claims,
    ): String = run {
        val header = signOp.header(customizeHeader)
        val payload = Json.encodeToJsonElement(serializer, claims).jsonObject
        signOp.signJwt(header, payload)
    }

    internal fun <PUB> SignOp<PUB>.header(
        customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
    ): JsonObject = buildJsonObject {
        put("alg", this@header.signingAlgorithm.toJoseAlg().name)
        customizeHeader(this@header.publicMaterial)
    }

    private suspend fun <PUB> SignOp<PUB>.signJwt(header: JsonObject, claims: JsonObject): String {
        // Base64Url encode header and claims
        val base64UrlEncoder = Base64.getUrlEncoder().withoutPadding()
        val headerB64 = base64UrlEncoder.encodeToString(header.toString().toByteArray(Charsets.UTF_8))
        val claimsB64 = base64UrlEncoder.encodeToString(claims.toString().toByteArray(Charsets.UTF_8))

        val signingInput: ByteArray = "$headerB64.$claimsB64".toByteArray(Charsets.US_ASCII)

        val signatureBytes = operation.sign(signingInput)
        val signatureB64 = base64UrlEncoder.encodeToString(signatureBytes.transcodeSignatureToConcat(signingAlgorithm))

        return "$headerB64.$claimsB64.$signatureB64"
    }
}
