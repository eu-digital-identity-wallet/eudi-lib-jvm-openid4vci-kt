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
package eu.europa.ec.eudi.openid4vci.examples

import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.net.URI
import java.time.Clock
import java.time.Duration
import java.time.Instant

suspend fun DeferredIssuer.Companion.queryForDeferredCredential(
    clock: Clock = Clock.systemDefaultZone(),
    ctxTO: DeferredIssuanceStoredContextTO,
    recreatePopSigner: ((String) -> Signer<JWK>)? = null,
    recreateClientAttestationPodSigner: ((String) -> Signer<JWK>)? = null,
    httpClient: HttpClient,
    responseEncryptionKey: JWK? = null,
): Result<Pair<DeferredIssuanceStoredContextTO?, DeferredCredentialQueryOutcome>> = runCatchingCancellable {
    val ctx = ctxTO.toDeferredIssuanceStoredContext(clock, recreatePopSigner, recreateClientAttestationPodSigner)
    val (newCtx, outcome) = queryForDeferredCredential(ctx, httpClient, responseEncryptionKey).getOrThrow()
    val newCtxTO =
        newCtx?.let { DeferredIssuanceStoredContextTO.from(it, ctxTO.dPoPSignerKid, ctxTO.clientAttestationPopKeyId) }
    newCtxTO to outcome
}

//
// Serialization
//

@Serializable
data class RefreshTokenTO(
    @Required @SerialName("refresh_token") val refreshToken: String,
) {

    fun toRefreshToken(): RefreshToken {
        return RefreshToken(refreshToken)
    }

    companion object {

        fun from(refreshToken: RefreshToken): RefreshTokenTO =
            RefreshTokenTO(refreshToken.refreshToken)
    }
}

@Serializable
enum class AccessTokenTypeTO {
    DPoP, Bearer
}

@Serializable
data class AccessTokenTO(
    @Required @SerialName("type") val type: AccessTokenTypeTO,
    @Required @SerialName("access_token") val accessToken: String,
    @SerialName("expires_in") val expiresIn: Long? = null,
) {

    fun toAccessToken(): AccessToken {
        val exp = expiresIn?.let { Duration.ofSeconds(it) }
        return when (type) {
            AccessTokenTypeTO.DPoP -> AccessToken.DPoP(accessToken, exp)
            AccessTokenTypeTO.Bearer -> AccessToken.Bearer(accessToken, exp)
        }
    }

    companion object {

        fun from(accessToken: AccessToken): AccessTokenTO {
            return AccessTokenTO(
                type = when (accessToken) {
                    is AccessToken.DPoP -> AccessTokenTypeTO.DPoP
                    is AccessToken.Bearer -> AccessTokenTypeTO.Bearer
                },
                accessToken = accessToken.accessToken,
                expiresIn = accessToken.expiresIn?.toSeconds(),
            )
        }
    }
}

@Serializable
enum class GrantTO {
    @SerialName("authorization_code")
    AuthorizationCode,

    @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    PreAuthorizedCodeGrant,

    ;

    fun toGrant(): Grant =
        when (this) {
            AuthorizationCode -> Grant.AuthorizationCode
            PreAuthorizedCodeGrant -> Grant.PreAuthorizedCodeGrant
        }

    companion object {
        fun fromGrant(grant: Grant): GrantTO =
            when (grant) {
                Grant.AuthorizationCode -> AuthorizationCode
                Grant.PreAuthorizedCodeGrant -> PreAuthorizedCodeGrant
            }
    }
}

@Serializable
data class DeferredIssuanceStoredContextTO(
    @Required @SerialName("credential_issuer") val credentialIssuerId: String,
    @Required @SerialName("client_id") val clientId: String,
    @SerialName("client_attestation_jwt") val clientAttestationJwt: String? = null,
    @SerialName("client_attestation_pop_key_id") val clientAttestationPopKeyId: String? = null,
    @Required @SerialName("deferred_endpoint") val deferredEndpoint: String,
    @Required @SerialName("auth_server_id") val authServerId: String,
    @SerialName("challenge_endpoint") val challengeEndpoint: String? = null,
    @Required @SerialName("token_endpoint") val tokenEndpoint: String,
    @SerialName("credential_request_encryption_spec") val requestEncryptionSpec: JsonObject? = null,
    @SerialName("credential_response_encryption_params") val responseEncryptionParams: JsonObject? = null,
    @SerialName("dpop_key_id") val dPoPSignerKid: String? = null,
    @SerialName("transaction_id") val transactionId: String,
    @SerialName("access_token") val accessToken: AccessTokenTO,
    @SerialName("refresh_token") val refreshToken: RefreshTokenTO? = null,
    @SerialName("authorization_timestamp") val authorizationTimestamp: Long,
    @SerialName("grant") val grant: GrantTO,
) {

    fun toDeferredIssuanceStoredContext(
        clock: Clock,
        recreatePopSigner: ((String) -> Signer<JWK>)?,
        recreateClientAttestationPodSigner: ((String) -> Signer<JWK>)?,
    ): DeferredIssuanceContext {
        return DeferredIssuanceContext(
            config = DeferredIssuerConfig(
                credentialIssuerId = CredentialIssuerId(credentialIssuerId).getOrThrow(),
                clock = clock,
                clientAuthentication =
                    if (clientAttestationJwt == null) ClientAuthentication.None(clientId)
                    else {
                        val jwt = runCatching {
                            ClientAttestationJWT(SignedJWT.parse(clientAttestationJwt))
                        }.getOrNull() ?: error("Invalid client attestation JWT")
                        val signer = clientAttestationPopKeyId?.let {
                                keyId ->
                            recreateClientAttestationPodSigner?.let { recreate -> recreate(keyId) }
                        }
                        val poPJWTSpec = ClientAttestationPoPJWTSpec(checkNotNull(signer))
                        ClientAuthentication.AttestationBased(jwt, poPJWTSpec)
                    },
                deferredEndpoint = URI(deferredEndpoint).toURL(),
                authorizationServerId = URI(authServerId).toURL(),
                challengeEndpoint = challengeEndpoint?.let { URI.create(it).toURL() },
                tokenEndpoint = URI(tokenEndpoint).toURL(),
                requestEncryptionSpec = requestEncryptionSpec?.let { requestEncryption(it) },
                responseEncryptionParams = responseEncryptionParams?.let { responseEncryptionParams(it) },
                dPoPSigner = dPoPSignerKid?.let { requireNotNull(recreatePopSigner).invoke(it) },
            ),
            authorizedTransaction = AuthorizedTransaction(
                authorizedRequest = AuthorizedRequest(
                    accessToken = accessToken.toAccessToken(),
                    refreshToken = refreshToken?.toRefreshToken(),
                    credentialIdentifiers = emptyMap(),
                    timestamp = Instant.ofEpochSecond(authorizationTimestamp),
                    authorizationServerDpopNonce = null,
                    resourceServerDpopNonce = null,
                    grant = grant.toGrant(),
                ),
                transactionId = TransactionId(transactionId),
            ),

        )
    }

    companion object {

        fun <A> ClientAuthentication.ifAttested(getter: ClientAuthentication.AttestationBased.() -> A?): A? =
            when (this) {
                is ClientAuthentication.AttestationBased -> getter()
                is ClientAuthentication.None -> null
            }

        fun from(
            dCtx: DeferredIssuanceContext,
            dPoPSignerKid: String?,
            clientAttestationPopKeyId: String?,
        ): DeferredIssuanceStoredContextTO {
            val authorizedTransaction = dCtx.authorizedTransaction
            return DeferredIssuanceStoredContextTO(
                credentialIssuerId = dCtx.config.credentialIssuerId.toString(),
                clientId = dCtx.config.clientAuthentication.id,
                clientAttestationJwt = dCtx.config.clientAuthentication.ifAttested { attestationJWT.jwt.serialize() },
                clientAttestationPopKeyId = dCtx.config.clientAuthentication.ifAttested { checkNotNull(clientAttestationPopKeyId) },
                deferredEndpoint = dCtx.config.deferredEndpoint.toString(),
                authServerId = dCtx.config.authorizationServerId.toString(),
                tokenEndpoint = dCtx.config.tokenEndpoint.toString(),
                requestEncryptionSpec = dCtx.config.requestEncryptionSpec?.let { requestEncryptionSpecTO(it) },
                responseEncryptionParams = dCtx.config.responseEncryptionParams?.let { responseEncryptionParamsTO(it) },
                dPoPSignerKid = dPoPSignerKid,
                transactionId = authorizedTransaction.transactionId.value,
                accessToken = AccessTokenTO.from(authorizedTransaction.authorizedRequest.accessToken),
                refreshToken = authorizedTransaction.authorizedRequest.refreshToken?.let { RefreshTokenTO.from(it) },
                authorizationTimestamp = authorizedTransaction.authorizedRequest.timestamp.epochSecond,
                grant = GrantTO.fromGrant(authorizedTransaction.authorizedRequest.grant),
            )
        }
    }
}

private fun requestEncryptionSpecTO(spec: EncryptionSpec): JsonObject {
    val jwkJson = Json.parseToJsonElement(spec.recipientKey.toJSONString())
    return buildJsonObject {
        put("recipient_key", jwkJson)
        put("encryption_method", spec.encryptionMethod.toString())
        put("compression_algorithm", spec.compressionAlgorithm.toString())
    }
}

private fun requestEncryption(specTO: JsonObject): EncryptionSpec =
    EncryptionSpec(
        recipientKey = run {
            val element = specTO["recipient_key"]
            require(element is JsonObject)
            JWK.parse(element.toString())
        },
        encryptionMethod = run {
            val element = specTO["encryption_method"]
            require(element is JsonPrimitive)
            EncryptionMethod.parse(requireNotNull(element.contentOrNull))
        },
        compressionAlgorithm = run {
            val element = specTO["compression_algorithm"]
            element?.let {
                require(it is JsonPrimitive)
                CompressionAlgorithm(requireNotNull(it.contentOrNull))
            }
        },
    )

private fun responseEncryptionParamsTO(params: Pair<EncryptionMethod, CompressionAlgorithm?>): JsonObject =
    buildJsonObject {
        put("encryption_method", params.first.toString())
        put("compression_algorithm", params.second?.toString())
    }

private fun responseEncryptionParams(specTO: JsonObject): Pair<EncryptionMethod, CompressionAlgorithm?> {
    val encryptionMethod = run {
        val element = specTO["encryption_method"]
        require(element is JsonPrimitive)
        EncryptionMethod.parse(requireNotNull(element.contentOrNull))
    }
    val compressionAlgorithm = run {
        val element = specTO["compression_algorithm"]
        element?.let {
            require(it is JsonPrimitive)
            CompressionAlgorithm(requireNotNull(it.contentOrNull))
        }
    }
    return encryptionMethod to compressionAlgorithm
}
