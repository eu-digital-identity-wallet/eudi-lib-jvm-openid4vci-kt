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
import eu.europa.ec.eudi.openid4vci.*
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
        @SerialName("ldp_vp") val ldpVp: String? = null,
    )

    private val internal = serializer<ProofJson>()
    override val descriptor: SerialDescriptor = SerialDescriptor("Proof", internal.descriptor)

    override fun deserialize(decoder: Decoder): Proof {
        val deserialized = internal.deserialize(decoder)
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
            is Proof.Cwt -> internal.serialize(
                encoder,
                ProofJson(
                    proofType = ProofType.CWT.toString().lowercase(),
                    cwt = value.cwt,
                ),
            )

            is Proof.Jwt -> internal.serialize(
                encoder,
                ProofJson(
                    proofType = ProofType.JWT.toString().lowercase(),
                    jwt = value.jwt.serialize(),
                ),
            )

            is Proof.LdpVp -> internal.serialize(
                encoder,
                ProofJson(
                    proofType = ProofType.LDP_VP.toString().lowercase(),
                    jwt = value.ldpVp,
                ),
            )
        }
    }
}

internal object ClaimSetSerializer : KSerializer<MsoMdocClaimSet> {

    val internal = serializer<Map<Namespace, Map<ClaimName, JsonObject>>>()
    override val descriptor: SerialDescriptor = internal.descriptor

    override fun deserialize(decoder: Decoder): MsoMdocClaimSet = internal.deserialize(decoder).asMsoMdocClaimSet()

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

@OptIn(ExperimentalSerializationApi::class)
internal object GrantedAuthorizationDetailsSerializer :
    KSerializer<Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>> {

    private const val OPENID_CREDENTIAL: String = "openid_credential"

    @Serializable
    data class AuthorizationDetailJson(
        @SerialName("type") @Required val type: String,
        @SerialName("format") val format: String? = null,
        @SerialName("credential_configuration_id") val credentialConfigurationId: String,
        @SerialName("credential_identifiers") val credentialIdentifiers: List<String> = emptyList(),
    ) {
        init {
            require(type == OPENID_CREDENTIAL) { "type must be $OPENID_CREDENTIAL" }
        }
    }
    private fun authDetails(
        credentialConfigurationId: CredentialConfigurationIdentifier,
        credentialIdentifiers: List<CredentialIdentifier>,
    ): AuthorizationDetailJson =
        AuthorizationDetailJson(
            type = OPENID_CREDENTIAL,
            credentialConfigurationId = credentialConfigurationId.value,
            credentialIdentifiers = credentialIdentifiers.map(CredentialIdentifier::value),
        )

    private val internal = serializer<List<AuthorizationDetailJson>>()
    override val descriptor: SerialDescriptor = SerialDescriptor("GrantedAuthorizationDetails", internal.descriptor)

    override fun deserialize(decoder: Decoder): Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>> {
        val deserialized = internal.deserialize(decoder)
        return deserialized.associate { authDetails ->
            val credentialConfigurationId = CredentialConfigurationIdentifier(authDetails.credentialConfigurationId)
            val credentialIdentifiers = authDetails.credentialIdentifiers.map { CredentialIdentifier(it) }
            credentialConfigurationId to credentialIdentifiers
        }
    }

    override fun serialize(
        encoder: Encoder,
        value: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>,
    ) {
        val authorizationDetailsList = value.entries.map { (cfgId, credIds) -> authDetails(cfgId, credIds) }
        internal.serialize(encoder, authorizationDetailsList)
    }
}
