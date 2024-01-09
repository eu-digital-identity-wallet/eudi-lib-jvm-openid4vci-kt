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

import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.ClaimName
import eu.europa.ec.eudi.openid4vci.MsoMdocClaimSet
import eu.europa.ec.eudi.openid4vci.Namespace
import eu.europa.ec.eudi.openid4vci.ProofType
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import java.util.*

internal val JsonSupport: Json = Json {
    ignoreUnknownKeys = true
    prettyPrint = true
}

internal object LocaleSerializer : KSerializer<Locale> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Locale", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Locale =
        Locale.forLanguageTag(decoder.decodeString())

    override fun serialize(encoder: Encoder, value: Locale) =
        encoder.encodeString(value.toString())
}

@OptIn(ExperimentalSerializationApi::class)
internal object ProofSerializer : KSerializer<Proof> {
    @Serializable
    data class ProofJson(
        @SerialName("proof_type") val proofType: String,
        @SerialName("jwt") val jwt: String? = null,
        @SerialName("cwt") val cwt: String? = null,
    )

    private val proofSerializer = serializer<ProofJson>()
    override val descriptor: SerialDescriptor = SerialDescriptor("Proof", proofSerializer.descriptor)

    override fun deserialize(decoder: Decoder): Proof {
        val deserialized = proofSerializer.deserialize(decoder)
        return when (deserialized.proofType) {
            ProofType.JWT.toString().lowercase() -> {
                deserialized.jwt?.let {
                    Proof.Jwt(SignedJWT.parse(deserialized.jwt))
                } ?: error("Invalid JWT proof: missing 'jwt' attribute.")
            }

            ProofType.CWT.toString().lowercase() -> {
                deserialized.cwt?.let {
                    Proof.Cwt(deserialized.cwt)
                } ?: error("Invalid CWT proof: missing 'cwt' attribute.")
            }

            else -> error("Unsupported proof type: ${deserialized.proofType}")
        }
    }

    override fun serialize(encoder: Encoder, value: Proof) {
        when (value) {
            is Proof.Cwt -> proofSerializer.serialize(
                encoder,
                ProofJson(
                    proofType = ProofType.CWT.toString().lowercase(),
                    jwt = value.cwt,
                ),
            )

            is Proof.Jwt -> proofSerializer.serialize(
                encoder,
                ProofJson(
                    proofType = ProofType.JWT.toString().lowercase(),
                    jwt = value.jwt.serialize(),
                ),
            )
        }
    }
}

internal object ClaimSetSerializer : KSerializer<MsoMdocClaimSet> {

    val internal = serializer<Map<Namespace, Map<ClaimName, JsonObject>>>()
    override val descriptor: SerialDescriptor =
        internal.descriptor

    override fun deserialize(decoder: Decoder): MsoMdocClaimSet =
        internal.deserialize(decoder).asMsoMdocClaimSet()

    override fun serialize(encoder: Encoder, value: MsoMdocClaimSet) {
        internal.serialize(encoder, value.toJson())
    }

    private fun Map<Namespace, Map<ClaimName, JsonObject>>.asMsoMdocClaimSet() =
        flatMap { (nameSpace, cs) -> cs.map { (claimName, _) -> nameSpace to claimName } }
            .let(::MsoMdocClaimSet)

    private fun MsoMdocClaimSet.toJson(): Map<Namespace, Map<ClaimName, JsonObject>> =
        groupBy { (nameSpace, _) -> nameSpace }
            .mapValues { (_, vs) -> vs.associate { (_, claimName) -> claimName to emptyJsonObject } }

    private val emptyJsonObject = JsonObject(emptyMap())
}
