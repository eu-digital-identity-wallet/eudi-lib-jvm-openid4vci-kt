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
import eu.europa.ec.eudi.openid4vci.Proof
import eu.europa.ec.eudi.openid4vci.ProofType
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonClassDiscriminator
import java.util.*

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
    @JsonClassDiscriminator("proof_type")
    private sealed interface ProofJson {
        @Serializable
        data class ProofJwtJson(
            @SerialName("proof_type") val proofType: String,
            @SerialName("jwt") val jwt: String,
        ) : ProofJson

        @Serializable
        data class ProofCwtJson(
            @SerialName("proof_type") val proofType: String,
            @SerialName("cwt") val cwt: String,
        ) : ProofJson
    }

    private val proofSerializer = serializer<ProofJson>()
    override val descriptor: SerialDescriptor = SerialDescriptor("Proof", proofSerializer.descriptor)

    override fun deserialize(decoder: Decoder): Proof =
        when (val deserialized = proofSerializer.deserialize(decoder)) {
            is ProofJson.ProofJwtJson -> Proof.Jwt(SignedJWT.parse(deserialized.jwt))
            is ProofJson.ProofCwtJson -> Proof.Cwt(deserialized.cwt)
        }

    override fun serialize(encoder: Encoder, value: Proof) {
        when (value) {
            is Proof.Cwt -> proofSerializer.serialize(
                encoder,
                ProofJson.ProofCwtJson(
                    proofType = ProofType.CWT.toString().lowercase(),
                    cwt = value.cwt,
                ),
            )

            is Proof.Jwt -> proofSerializer.serialize(
                encoder,
                ProofJson.ProofJwtJson(
                    proofType = ProofType.CWT.toString().lowercase(),
                    jwt = value.jwt.serialize(),
                ),
            )
        }
    }
}
