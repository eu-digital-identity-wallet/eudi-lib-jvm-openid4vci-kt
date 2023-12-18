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

import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Duration.Companion.seconds

/**
 * The unvalidated data of a Credential Offer.
 */
@Serializable
private data class CredentialOfferRequestTO(
    @SerialName("credential_issuer") @Required val credentialIssuerIdentifier: String,
    @SerialName("credentials") @Required val credentials: List<String>,
    @SerialName("grants") val grants: GrantsTO? = null,
)

/**
 * Data of the Grant Types the Credential Issuer is prepared to process for a Credential Offer.
 */
@Serializable
private data class GrantsTO(
    @SerialName("authorization_code") val authorizationCode: AuthorizationCodeTO? = null,
    @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code") val preAuthorizedCode: PreAuthorizedCodeTO? = null,
)

/**
 * Data for an Authorization Code Grant Type.
 */
@Serializable
private data class AuthorizationCodeTO(
    @SerialName("issuer_state") val issuerState: String? = null,
    @SerialName("authorization_server") val authorizationServer: String? = null,
)

/**
 * Data for a Pre-Authorized Code Grant Type.
 */
@Serializable
private data class PreAuthorizedCodeTO(
    @SerialName("pre-authorized_code") @Required val preAuthorizedCode: String,
    @SerialName("user_pin_required") val pinRequired: Boolean? = null,
    @SerialName("interval") val interval: Long? = null,
    @SerialName("authorization_server") val authorizationServer: String? = null,
)

/**
 * A default implementation for [CredentialOfferRequestResolver].
 */
internal class DefaultCredentialOfferRequestResolver(
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) : CredentialOfferRequestResolver {

    private val credentialIssuerMetadataResolver =
        CredentialIssuerMetadataResolver(ktorHttpClientFactory)
    private val authorizationServerMetadataResolver =
        AuthorizationServerMetadataResolver(ktorHttpClientFactory)

    override suspend fun resolve(request: CredentialOfferRequest): Result<CredentialOffer> =
        runCatching {
            val credentialOfferRequestObjectString: String = when (request) {
                is CredentialOfferRequest.PassByValue -> request.value
                is CredentialOfferRequest.PassByReference ->
                    try {
                        ktorHttpClientFactory().use { client ->
                            client.get(request.value.value).body()
                        }
                    } catch (t: Throwable) {
                        throw CredentialOfferRequestError.UnableToFetchCredentialOffer(t).toException()
                    }
            }
            val credentialOfferRequestObject = runCatching {
                JsonSupport.decodeFromString<CredentialOfferRequestTO>(credentialOfferRequestObjectString)
            }.getOrElse { CredentialOfferRequestError.NonParseableCredentialOffer(it).raise() }

            val credentialIssuerId = CredentialIssuerId(credentialOfferRequestObject.credentialIssuerIdentifier)
                .getOrElse { CredentialOfferRequestValidationError.InvalidCredentialIssuerId(it).raise() }

            val credentialIssuerMetadata = credentialIssuerMetadataResolver.resolve(credentialIssuerId)
                .getOrElse { CredentialOfferRequestError.UnableToResolveCredentialIssuerMetadata(it).raise() }

            val credentials = runCatching {
                credentialOfferRequestObject.credentials
                    .map {
                        val credentialIdentifier = CredentialIdentifier(it)
                        requireNotNull(credentialIssuerMetadata.credentialsSupported[credentialIdentifier])
                        credentialIdentifier
                    }
                    .also {
                        require(it.isNotEmpty()) { "credentials are required" }
                    }
            }.getOrElse { CredentialOfferRequestValidationError.InvalidCredentials(it).raise() }

            val grants = runCatching {
                credentialOfferRequestObject.grants?.toGrants(credentialIssuerMetadata)
            }.getOrElse { CredentialOfferRequestValidationError.InvalidGrants(it).raise() }

            val authorizationServer = when (grants) {
                is Grants.AuthorizationCode -> grants.authorizationServer
                is Grants.PreAuthorizedCode -> grants.authorizationServer
                is Grants.Both ->
                    grants.authorizationCode.authorizationServer
                        ?: grants.preAuthorizedCode.authorizationServer

                null -> null
            }

            val authorizationServerMetadata =
                authorizationServerMetadataResolver.resolve(
                    authorizationServer ?: credentialIssuerMetadata.authorizationServers[0],
                )
                    .getOrElse { CredentialOfferRequestError.UnableToResolveAuthorizationServerMetadata(it).raise() }

            CredentialOffer(
                credentialIssuerId,
                credentialIssuerMetadata,
                authorizationServerMetadata,
                credentials,
                grants,
            )
        }
}

/**
 * Tries to parse a [GrantsTO] to a [Grants] instance.
 */
private fun GrantsTO.toGrants(credentialIssuerMetadata: CredentialIssuerMetadata): Grants? {
    val maybeAuthorizationCodeGrant =
        authorizationCode?.let {
            val authorizationServer = it.authorizationServer?.let { url ->
                val authServer = HttpsUrl(url).getOrThrow()
                require(credentialIssuerMetadata.authorizationServers.contains(authServer))
                authServer
            }
            Grants.AuthorizationCode(it.issuerState, authorizationServer)
        }
    val maybePreAuthorizedCodeGrant =
        preAuthorizedCode?.let {
            val authorizationServer = it.authorizationServer?.let { url ->
                val authServer = HttpsUrl(url).getOrThrow()
                require(credentialIssuerMetadata.authorizationServers.contains(authServer))
                authServer
            }
            Grants.PreAuthorizedCode(
                it.preAuthorizedCode,
                it.pinRequired ?: false,
                it.interval?.seconds ?: 5.seconds,
                authorizationServer,
            )
        }

    return when {
        maybeAuthorizationCodeGrant != null && maybePreAuthorizedCodeGrant != null -> Grants.Both(
            maybeAuthorizationCodeGrant,
            maybePreAuthorizedCodeGrant,
        )

        maybeAuthorizationCodeGrant == null && maybePreAuthorizedCodeGrant == null -> null
        maybeAuthorizationCodeGrant != null -> maybeAuthorizationCodeGrant
        else -> maybePreAuthorizedCodeGrant
    }
}
