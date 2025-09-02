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

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.ClaimPathElement.AllArrayElements
import eu.europa.ec.eudi.openid4vci.ClaimPathElement.ArrayElement
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import java.security.cert.X509Certificate
import java.time.Instant
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
        @SerialName("di_vp") val diVp: String? = null,
        @SerialName("attestation") val attestation: String? = null,
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

            else -> error("Unsupported proof type: ${deserialized.proofType}")
        }
    }

    override fun serialize(encoder: Encoder, value: Proof) {
        when (value) {
            is Proof.Jwt -> internal.serialize(
                encoder,
                ProofJson(
                    proofType = ProofType.JWT.toString().lowercase(),
                    jwt = value.jwt.serialize(),
                ),
            )

            is Proof.DiVp -> internal.serialize(
                encoder,
                ProofJson(
                    proofType = ProofType.DI_VP.toString().lowercase(),
                    jwt = value.diVp,
                ),
            )

            is Proof.Attestation -> internal.serialize(
                encoder,
                ProofJson(
                    proofType = ProofType.ATTESTATION.toString().lowercase(),
                    attestation = value.keyAttestation.value,
                ),
            )
        }
    }
}

@OptIn(ExperimentalSerializationApi::class)
internal object GrantedAuthorizationDetailsSerializer :
    KSerializer<Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>> {

    private const val OPENID_CREDENTIAL: String = "openid_credential"

    @Serializable
    data class AuthorizationDetailJson(
        @SerialName("type") @Required val type: String,
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

/**
 * Serializer for [ClaimPath]
 */
internal object ClaimPathSerializer : KSerializer<ClaimPath> {

    private fun ClaimPath.toJson(): JsonArray = JsonArray(value.map { it.toJson() })

    private fun ClaimPathElement.toJson(): JsonPrimitive = when (this) {
        is ClaimPathElement.Claim -> JsonPrimitive(name)
        is ArrayElement -> JsonPrimitive(index)
        AllArrayElements -> JsonNull
    }

    private val arraySerializer = serializer<JsonArray>()

    override val descriptor: SerialDescriptor = arraySerializer.descriptor

    override fun serialize(encoder: Encoder, value: ClaimPath) {
        val array = value.toJson()
        arraySerializer.serialize(encoder, array)
    }

    override fun deserialize(decoder: Decoder): ClaimPath {
        val array = arraySerializer.deserialize(decoder)
        return array.asClaimPath()
    }
}

object NumericInstantSerializer : KSerializer<Instant> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("NumericInstant", PrimitiveKind.LONG)

    override fun serialize(encoder: Encoder, value: Instant) {
        encoder.encodeLong(value.epochSecond)
    }

    override fun deserialize(decoder: Decoder): Instant {
        return Instant.ofEpochSecond(decoder.decodeLong())
    }
}

object JWTClaimsSetSerializer : KSerializer<JWTClaimsSet> {

    private val objectSerializer = serializer<JsonObject>()

    override val descriptor: SerialDescriptor = objectSerializer.descriptor

    override fun serialize(encoder: Encoder, value: JWTClaimsSet) {
        val claimsJsonObject = JsonSupport.decodeFromString<JsonObject>(JSONObjectUtils.toJSONString(value.toJSONObject()))
        objectSerializer.serialize(encoder, claimsJsonObject)
    }

    override fun deserialize(decoder: Decoder): JWTClaimsSet {
        val deserialized = objectSerializer.deserialize(decoder)
        return JWTClaimsSet.parse(JsonSupport.encodeToString(deserialized))
    }
}

fun JWK.asJsonElement(): JsonElement = Json.parseToJsonElement(this.toPublicJWK().toJSONString())

fun List<X509Certificate>.asJsonElement(): JsonArray = JsonArray(
    this.map { Json.encodeToJsonElement(Base64.getEncoder().encodeToString(it.encoded)) },
)
