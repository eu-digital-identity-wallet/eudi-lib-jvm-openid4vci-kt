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
import eu.europa.ec.eudi.openid4vci.CredentialOfferRequestError.UnableToResolveAuthorizationServerMetadata
import eu.europa.ec.eudi.openid4vci.CredentialOfferRequestError.UnableToResolveCredentialIssuerMetadata
import eu.europa.ec.eudi.openid4vci.CredentialOfferRequestValidationError.InvalidGrants
import io.ktor.client.*
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

internal class DefaultCredentialOfferRequestResolver(
    private val httpClient: HttpClient,
) : CredentialOfferRequestResolver {
    override suspend fun resolve(request: CredentialOfferRequest): Result<CredentialOffer> = runCatching {
        val credentialOffer = fetchOffer(request)
        val credentialIssuerId = CredentialIssuerId(credentialOffer.credentialIssuerIdentifier)
            .getOrElse { CredentialOfferRequestValidationError.InvalidCredentialIssuerId(it).raise() }

        ensure(credentialOffer.credentials.isNotEmpty()) {
            val er = IllegalArgumentException("credentials are required")
            CredentialOfferRequestValidationError.InvalidCredentials(er).toException()
        }

        val credentialIssuerMetadata = fetchIssuerMetaData(credentialIssuerId)
        val credentials = credentialOffer.credentials.map { CredentialIdentifier(it) }
        ensure(credentialIssuerMetadata.credentialsSupported.keys.containsAll(credentials)) {
            val er = IllegalArgumentException("Credential offer contains unknown credential ids")
            CredentialOfferRequestValidationError.InvalidCredentials(er).toException()
        }

        val grants = credentialOffer.grants?.toGrants(credentialIssuerMetadata)
        val authorizationServer = grants?.authServer() ?: credentialIssuerMetadata.authorizationServers[0]
        val authorizationServerMetadata = fetchAuthServerMetaData(authorizationServer)

        CredentialOffer(
            credentialIssuerId,
            credentialIssuerMetadata,
            authorizationServerMetadata,
            credentials,
            grants,
        )
    }

    private suspend fun fetchOffer(request: CredentialOfferRequest): CredentialOfferRequestTO {
        val credentialOfferRequestObjectString: String = when (request) {
            is CredentialOfferRequest.PassByValue -> request.value
            is CredentialOfferRequest.PassByReference ->
                try {
                    httpClient.get(request.value.value).body()
                } catch (t: Throwable) {
                    throw CredentialOfferRequestError.UnableToFetchCredentialOffer(t).toException()
                }
        }
        return try {
            JsonSupport.decodeFromString<CredentialOfferRequestTO>(credentialOfferRequestObjectString)
        } catch (t: Throwable) {
            throw CredentialOfferRequestError.NonParseableCredentialOffer(t).toException()
        }
    }

    private suspend fun fetchIssuerMetaData(credentialIssuerId: CredentialIssuerId): CredentialIssuerMetadata =
        with(DefaultCredentialIssuerMetadataResolver(httpClient)) {
            resolve(credentialIssuerId)
                .getOrElse { throw UnableToResolveCredentialIssuerMetadata(it).toException() }
        }

    private suspend fun fetchAuthServerMetaData(authorizationServer: HttpsUrl): CIAuthorizationServerMetadata =
        with(DefaultAuthorizationServerMetadataResolver(httpClient)) {
            resolve(authorizationServer)
                .getOrElse { throw UnableToResolveAuthorizationServerMetadata(it).toException() }
        }
}

private fun Grants.authServer(): HttpsUrl? = when (this) {
    is Grants.AuthorizationCode -> authorizationServer
    is Grants.PreAuthorizedCode -> authorizationServer
    is Grants.Both -> authorizationCode.authorizationServer ?: preAuthorizedCode.authorizationServer
}

/**
 * Tries to parse a [GrantsTO] to a [Grants] instance.
 */
private fun GrantsTO.toGrants(credentialIssuerMetadata: CredentialIssuerMetadata): Grants? = runCatching {
    val maybeAuthorizationCodeGrant =
        authorizationCode?.let {
            val authorizationServer = it.authorizationServer?.let { url ->
                val authServer = HttpsUrl(url).getOrThrow()
                require(authServer in credentialIssuerMetadata.authorizationServers)
                authServer
            }
            Grants.AuthorizationCode(it.issuerState, authorizationServer)
        }
    val maybePreAuthorizedCodeGrant =
        preAuthorizedCode?.let {
            val authorizationServer = it.authorizationServer?.let { url ->
                val authServer = HttpsUrl(url).getOrThrow()
                require(authServer in credentialIssuerMetadata.authorizationServers)
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
}.getOrElse { throw InvalidGrants(it).toException() }
