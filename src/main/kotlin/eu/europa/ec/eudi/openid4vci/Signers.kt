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

import eu.europa.ec.eudi.openid4vci.internal.NumericInstantSerializer
import eu.europa.ec.eudi.openid4vci.internal.header
import eu.europa.ec.eudi.openid4vci.internal.signJwt
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.serializer
import java.time.Instant

@Serializable
data class JwtProofClaims(
    @SerialName("aud") val audience: String,
    @Serializable(with = NumericInstantSerializer::class)
    @SerialName("iat") val issuedAt: Instant,
    @SerialName("iss") val issuer: String?,
    @SerialName("nonce") val nonce: String?, // TODO GD use CNonce type
)

fun interface SignOperation {
    suspend fun sign(input: ByteArray): Result<ByteArray>

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

interface BatchSigner<PUB> {

    suspend fun authenticate(): BatchSignOp<PUB>

    suspend fun release(signOps: BatchSignOp<PUB>?)

    companion object
}

interface Signer<PUB> {

    suspend fun authenticate(): SignOp<PUB>

    suspend fun release(signOp: SignOp<PUB>?)

    companion object
}

/////////////////
// JWT Signers //
/////////////////

fun interface JwtSigner<in Claims> {
    suspend fun sign(claims: Claims): String

    companion object {
        inline operator fun <reified Claims, PUB> invoke(
            signOp: SignOp<PUB>,
            noinline customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
            noinline assertions: SignOp<PUB>.() -> Unit = {},
        ): JwtSigner<Claims> = DefaultJwtSigner(serializer(), signOp, customizeHeader, assertions)
    }
}

fun interface JwtBatchSigner<in Claims> {
    suspend fun sign(claims: Claims): List<String>

    companion object {

        inline operator fun <reified Claims, PUB> invoke(
            signOps: BatchSignOp<PUB>,
            noinline customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
            noinline assertions: SignOp<PUB>.() -> Unit = {},
        ): JwtBatchSigner<Claims> =
            object : JwtBatchSigner<Claims> {

                override suspend fun sign(claims: Claims): List<String> =
                    signOps.operations.map { signOp ->
                        DefaultJwtSigner(
                            serializer = serializer<Claims>(),
                            signOp = signOp,
                            customizeHeader = customizeHeader,
                            assertions = assertions,
                        ).sign(claims)
                    }
            }
    }
}

class DefaultJwtSigner<Claims, PUB>(
    private val serializer: KSerializer<Claims>,
    private val signOp: SignOp<PUB>,
    private val customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
    private val assertions: SignOp<PUB>.() -> Unit = {},
) : JwtSigner<Claims> {

    override suspend fun sign(
        claims: Claims,
    ): String = run {
        signOp.apply { assertions }
        val header = signOp.header(customizeHeader)
        val payload = Json.encodeToJsonElement(serializer, claims).jsonObject
        signOp.signJwt(header, payload)
    }
}