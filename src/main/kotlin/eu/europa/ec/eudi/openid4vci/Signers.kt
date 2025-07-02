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

import eu.europa.ec.eudi.openid4vci.internal.header
import eu.europa.ec.eudi.openid4vci.internal.signJwt
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.serializer

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
