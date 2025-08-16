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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.time.Clock
import java.time.Duration
import java.time.Instant
import kotlin.time.toKotlinDuration

suspend fun DeferredIssuer.Companion.queryForDeferredCredential(
    clock: Clock = Clock.systemDefaultZone(),
    ctxTO: DeferredIssuanceStoredContextTO,
    recreatePopSigner: ((String) -> Signer<JWK>)? = null,
    recreateClientAttestationPodSigner: ((String) -> JWSSigner)? = null,
    httpClient: HttpClient,
    issuerMetadataPolicy: IssuerMetadataPolicy,
    encryptionSupportConfig: EncryptionSupportConfig,
): Result<Pair<DeferredIssuanceStoredContextTO?, DeferredCredentialQueryOutcome>> = runCatching {
    val ctx = ctxTO.toDeferredIssuanceStoredContext(clock, recreatePopSigner, recreateClientAttestationPodSigner)
    val (newCtx, outcome) = queryForDeferredCredential(ctx, httpClient, issuerMetadataPolicy, encryptionSupportConfig).getOrThrow()
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
    @SerialName("client_attestation_pop_duration") val clientAttestationPopDuration: Long? = null,
    @SerialName("client_attestation_pop_alg") val clientAttestationPopAlgorithm: String? = null,
    @SerialName("client_attestation_pop_typ") val clientAttestationPopType: String? = null,
    @SerialName("client_attestation_pop_key_id") val clientAttestationPopKeyId: String? = null,
    @Required @SerialName("auth_server_id") val authServerId: String,
    @Required @SerialName("token_endpoint") val tokenEndpoint: String,
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
        recreateClientAttestationPodSigner: ((String) -> JWSSigner)?,
    ): DeferredIssuanceContext {
        return DeferredIssuanceContext(
            config = DeferredIssuerConfig(
                credentialIssuerId = CredentialIssuerId(credentialIssuerId).getOrThrow(),
                clock = clock,
                client =
                    if (clientAttestationJwt == null) Client.Public(clientId)
                    else {
                        val jwt = runCatching {
                            ClientAttestationJWT(SignedJWT.parse(clientAttestationJwt))
                        }.getOrNull() ?: error("Invalid client attestation JWT")
                        val poPJWTSpec = ClientAttestationPoPJWTSpec(
                            signingAlgorithm = JWSAlgorithm.parse(checkNotNull(clientAttestationPopAlgorithm)),
                            duration = Duration.ofSeconds(checkNotNull(clientAttestationPopDuration))
                                .toKotlinDuration(),
                            typ = checkNotNull(clientAttestationPopType),
                            jwsSigner = checkNotNull(recreateClientAttestationPodSigner).invoke(
                                checkNotNull(
                                    clientAttestationPopKeyId,
                                ),
                            ),
                        )

                        Client.Attested(jwt, poPJWTSpec)
                    },
                authServerId = URI(authServerId).toURL(),
                tokenEndpoint = URI(tokenEndpoint).toURL(),
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

        fun <A> Client.ifAttested(getter: Client.Attested.() -> A?): A? =
            when (this) {
                is Client.Attested -> getter()
                is Client.Public -> null
            }

        fun from(
            dCtx: DeferredIssuanceContext,
            dPoPSignerKid: String?,
            clientAttestationPopKeyId: String?,
        ): DeferredIssuanceStoredContextTO {
            val authorizedTransaction = dCtx.authorizedTransaction
            return DeferredIssuanceStoredContextTO(
                credentialIssuerId = dCtx.config.credentialIssuerId.toString(),
                clientId = dCtx.config.client.id,
                clientAttestationJwt = dCtx.config.client.ifAttested { attestationJWT.jwt.serialize() },
                clientAttestationPopType = dCtx.config.client.ifAttested { popJwtSpec.typ },
                clientAttestationPopDuration = dCtx.config.client.ifAttested { popJwtSpec.duration.inWholeSeconds },
                clientAttestationPopAlgorithm = dCtx.config.client.ifAttested { popJwtSpec.signingAlgorithm.toJSONString() },
                clientAttestationPopKeyId = dCtx.config.client.ifAttested { checkNotNull(clientAttestationPopKeyId) },
                authServerId = dCtx.config.authServerId.toString(),
                tokenEndpoint = dCtx.config.tokenEndpoint.toString(),
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
