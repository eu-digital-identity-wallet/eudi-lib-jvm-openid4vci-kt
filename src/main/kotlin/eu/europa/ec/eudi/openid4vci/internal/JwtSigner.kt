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
import eu.europa.ec.eudi.openid4vci.BatchSignOperation
import eu.europa.ec.eudi.openid4vci.SignOperation
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.serializer
import java.util.Base64

/**
 * Represents an interface for signing JSON Web Tokens (JWTs). The interface provides the functionality to
 * generate signed JWTs based on the provided claims and signing configuration.
 *
 * @param Claims The type of the claims to be included in the signed JWT.
 * @param PUB The type of the public material associated with the signing operation.
 */
internal interface JwtSigner<in Claims, out PUB> {
    val publicMaterial: PUB
    suspend fun sign(claims: Claims): String

    companion object {

        operator fun <Claims, PUB> invoke(
            serializer: KSerializer<Claims>,
            signOperation: SignOperation<PUB>,
            algorithm: JWSAlgorithm,
            customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
        ): JwtSigner<Claims, PUB> = DefaultJwtSigner(serializer, signOperation, algorithm, customizeHeader)

        inline operator fun <reified Claims, PUB> invoke(
            signOperation: SignOperation<PUB>,
            algorithm: JWSAlgorithm,
            noinline customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
        ): JwtSigner<Claims, PUB> = invoke(serializer(), signOperation, algorithm, customizeHeader)
    }
}

/**
 * An interface for performing batch JWT signing operations. This interface allows signing multiple claims
 * using a batch of signing operations, producing a list of signed JWTs paired with their corresponding public materials.
 *
 * @param Claims The type of the claims to be signed.
 * @param PUB The type of the public material associated with the signed JWT.
 */
internal fun interface JwtBatchSigner<in Claims, out PUB> {
    suspend fun sign(claims: Claims): List<Pair<PUB, String>>

    companion object {

        operator fun <Claims, PUB> invoke(
            serializer: KSerializer<Claims>,
            batchSignOperation: BatchSignOperation<PUB>,
            algorithm: JWSAlgorithm,
            customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
        ): JwtBatchSigner<Claims, PUB> =
            object : JwtBatchSigner<Claims, PUB> {

                override suspend fun sign(claims: Claims): List<Pair<PUB, String>> =
                    batchSignOperation.operations.map { signOperation ->
                        val jwtSigner = JwtSigner(serializer, signOperation, algorithm, customizeHeader)
                        val jwt = jwtSigner.sign(claims)
                        jwtSigner.publicMaterial to jwt
                    }
            }

        inline operator fun <reified Claims, PUB> invoke(
            batchSignOperation: BatchSignOperation<PUB>,
            algorithm: JWSAlgorithm,
            noinline customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
        ): JwtBatchSigner<Claims, PUB> = invoke(serializer(), batchSignOperation, algorithm, customizeHeader)
    }
}

private class DefaultJwtSigner<in Claims, out PUB>(
    private val serializer: KSerializer<Claims>,
    private val signOperation: SignOperation<PUB>,
    private val algorithm: JWSAlgorithm,
    private val customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
) : JwtSigner<Claims, PUB> {

    override val publicMaterial: PUB get() = signOperation.publicMaterial

    override suspend fun sign(
        claims: Claims,
    ): String {
        val header = signOperation.header(customizeHeader)
        val payload = Json.encodeToJsonElement(serializer, claims).jsonObject
        return signOperation.signJwt(header, payload)
    }

    fun <PUB> SignOperation<PUB>.header(
        customizeHeader: JsonObjectBuilder.(PUB) -> Unit = {},
    ): JsonObject = buildJsonObject {
        put("alg", algorithm.name)
        customizeHeader(this@header.publicMaterial)
    }

    private suspend fun <PUB> SignOperation<PUB>.signJwt(header: JsonObject, claims: JsonObject): String {
        // Base64Url encode header and claims
        val base64UrlEncoder = Base64.getUrlEncoder().withoutPadding()
        val headerB64 = base64UrlEncoder.encodeToString(header.toString().toByteArray(Charsets.UTF_8))
        val claimsB64 = base64UrlEncoder.encodeToString(claims.toString().toByteArray(Charsets.UTF_8))

        val signingInput: ByteArray = "$headerB64.$claimsB64".toByteArray(Charsets.US_ASCII)

        val signatureBytes = function.sign(signingInput)
        val signatureB64 = base64UrlEncoder.encodeToString(signatureBytes.transcodeSignatureToConcat(algorithm))

        return "$headerB64.$claimsB64.$signatureB64"
    }
}
