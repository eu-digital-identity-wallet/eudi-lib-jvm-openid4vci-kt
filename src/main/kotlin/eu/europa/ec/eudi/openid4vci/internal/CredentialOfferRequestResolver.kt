/*
 * Copyright (c) 2023-2026 European Commission
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

import com.eygraber.uri.Uri
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialOfferRequestError.UnableToResolveAuthorizationServerMetadata
import eu.europa.ec.eudi.openid4vci.CredentialOfferRequestError.UnableToResolveCredentialIssuerMetadata
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * The unvalidated data of a Credential Offer.
 */
@Serializable
private data class CredentialOfferRequestTO(
    @SerialName(OpenId4VCISpec.CREDENTIAL_ISSUER) @Required val credentialIssuerIdentifier: String,
    @SerialName(OpenId4VCISpec.CREDENTIAL_CONFIGURATION_IDS) @Required val credentialConfigurationIds: List<String>,
    @SerialName(OpenId4VCISpec.GRANTS) val grants: GrantsTO? = null,
)

/**
 * Data of the Grant Types the Credential Issuer is prepared to process for a Credential Offer.
 */
@Serializable
private data class GrantsTO(
    @SerialName(OpenId4VCISpec.AUTHORIZATION_CODE_GRANT) val authorizationCode: AuthorizationCodeTO? = null,
    @SerialName(OpenId4VCISpec.PRE_AUTHORIZED_CODE_GRANT) val preAuthorizedCode: PreAuthorizedCodeTO? = null,
)

/**
 * Data for an Authorization Code Grant Type.
 */
@Serializable
private data class AuthorizationCodeTO(
    @SerialName(OpenId4VCISpec.ISSUER_STATE) val issuerState: String? = null,
    @SerialName(OpenId4VCISpec.AUTHORIZATION_SERVER) val authorizationServer: String? = null,
)

/**
 * Data for a Pre-Authorized Code Grant Type.
 */
@Serializable
private data class PreAuthorizedCodeTO(
    @SerialName(OpenId4VCISpec.PRE_AUTHORIZED_CODE) @Required val preAuthorizedCode: String,
    @SerialName(OpenId4VCISpec.TRANSACTION_CODE) val txCode: TxCodeTO? = null,
    @SerialName(OpenId4VCISpec.AUTHORIZATION_SERVER) val authorizationServer: String? = null,
)

@Serializable
private data class TxCodeTO(
    @SerialName(OpenId4VCISpec.INPUT_MODE) val inputMode: InputModeTO? = InputModeTO.NUMERIC,
    @SerialName(OpenId4VCISpec.LENGTH) val length: Int? = null,
    @SerialName(OpenId4VCISpec.DESCRIPTION) val description: String? = null,
)

@Serializable
private enum class InputModeTO {
    @SerialName(OpenId4VCISpec.INPUT_MODE_TEXT)
    TEXT,

    @SerialName(OpenId4VCISpec.INPUT_MODE_NUMERIC)
    NUMERIC,
}

internal class CredentialOfferRequestResolver(
    private val httpClient: HttpClient,
    private val requestEncryptionSpecFactory: RequestEncryptionSpecFactory = RequestEncryptionSpecFactory.DEFAULT,
    private val responseEncryptionSpecFactory: ResponseEncryptionSpecFactory = ResponseEncryptionSpecFactory.DEFAULT,
) {

    suspend fun resolve(config: OpenId4VCIConfig, request: CredentialOfferRequest): Result<CredentialOffer> =
        runCatchingCancellable {
            val credentialOffer = fetchOffer(request)
            val credentialIssuerId = CredentialIssuerId(credentialOffer.credentialIssuerIdentifier)
                .getOrElse { CredentialOfferRequestValidationError.InvalidCredentialIssuerId(it).raise() }

            ensure(credentialOffer.credentialConfigurationIds.isNotEmpty()) {
                val er = IllegalArgumentException("credentials are required")
                CredentialOfferRequestValidationError.InvalidCredentials(er).toException()
            }

            val credentialIssuerMetadata = fetchIssuerMetaData(config.issuerMetadataPolicy, credentialIssuerId)
            val credentials = credentialOffer.credentialConfigurationIds.map { CredentialConfigurationIdentifier(it) }
            ensure(credentialIssuerMetadata.credentialConfigurationsSupported.keys.containsAll(credentials)) {
                val er = IllegalArgumentException("Credential offer contains unknown credential ids")
                CredentialOfferRequestValidationError.InvalidCredentials(er).toException()
            }

            val grants = credentialOffer.grants?.toGrants(credentialIssuerMetadata)
            val authorizationServer = grants?.authServer() ?: credentialIssuerMetadata.authorizationServers[0]
            val authorizationServerMetadata = fetchAuthServerMetaData(authorizationServer)
            if (grants is Grants.AuthorizationCode) {
                ensureNotNull(authorizationServerMetadata.authorizationEndpointURI) {
                    val error =
                        IllegalArgumentException(
                            "Credential Offer requires Authorization Code Grant, but the Authorization Server does not support it",
                        )
                    CredentialOfferRequestValidationError.InvalidGrants(error).toException()
                }
            }

            val exchangeEncryptionSpecification = issuanceEncryptionSpecs(
                issuerMetadata = credentialIssuerMetadata,
                encryptionSupportConfig = config.encryptionSupportConfig,
                requestEncryptionSpecFactory = requestEncryptionSpecFactory,
                responseEncryptionSpecFactory = responseEncryptionSpecFactory,
            ).getOrThrow()

            val dPoPCtx = run {
                val dPoPUsage = config.provisionDPoPUsage(authorizationServer).map { JwsAlgorithm(it.javaAlgorithm.toJoseAlg().name) }
                DPoPCtx.createForServer(dPoPUsage, authorizationServerMetadata).getOrThrow()
            }

            CredentialOffer(
                credentialIssuerId,
                credentialIssuerMetadata,
                authorizationServerMetadata,
                credentials,
                grants,
                exchangeEncryptionSpecification,
                dPoPCtx,
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

    private suspend fun fetchIssuerMetaData(
        issuerMetadataPolicy: IssuerMetadataPolicy,
        credentialIssuerId: CredentialIssuerId,
    ): CredentialIssuerMetadata =
        with(DefaultCredentialIssuerMetadataResolver(httpClient)) {
            resolve(credentialIssuerId, issuerMetadataPolicy)
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
    fun TxCodeTO.toTxCode(): TxCode {
        return when (inputMode) {
            InputModeTO.TEXT ->
                TxCode(
                    inputMode = TxCodeInputMode.TEXT,
                    length = length,
                    description = description,
                )

            else ->
                TxCode(
                    inputMode = TxCodeInputMode.NUMERIC,
                    length = length,
                    description = description,
                )
        }
    }

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
                it.txCode?.toTxCode(),
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
}.getOrElse { throw CredentialOfferRequestValidationError.InvalidGrants(it).toException() }

/**
 * Creates a new Credential Offer URI using Authorization Code Grant.
 *
 * @param credentialIssuerId the Id of the Credential Issuer
 * @param credentialConfigurationIdentifiers the Credential Configuration Identifiers for which to generate the Credential Offer URI; must not be empty
 * @param authorizationServer the Authorization Server
 */
internal fun createAuthorizationCodeGrantCredentialOfferUri(
    credentialIssuerId: CredentialIssuerId,
    credentialConfigurationIdentifiers: List<CredentialConfigurationIdentifier>,
    authorizationServer: HttpsUrl,
): String {
    require(credentialConfigurationIdentifiers.isNotEmpty()) {
        "At least one credential configuration identifier must be specified"
    }

    val credentialOfferRequest = CredentialOfferRequestTO(
        credentialIssuerIdentifier = credentialIssuerId.toString(),
        credentialConfigurationIds = credentialConfigurationIdentifiers.map { it.value },
        grants = GrantsTO(
            authorizationCode = AuthorizationCodeTO(
                authorizationServer = authorizationServer.toString(),
                issuerState = null,
            ),
            preAuthorizedCode = null,
        ),
    )

    return Uri.parse(OpenId4VCISpec.CREDENTIAL_OFFER_URI_SCHEME)
        .buildUpon()
        .appendQueryParameter(OpenId4VCISpec.CREDENTIAL_OFFER, JsonSupport.encodeToString(credentialOfferRequest))
        .build()
        .toString()
}

internal fun <A : Any, B : Any> DPoPUsage<A>.map(convert: (A) -> B): DPoPUsage<B> =
    when (this) {
        DPoPUsage.Never -> DPoPUsage.Never
        is DPoPUsage.IfSupported -> DPoPUsage.IfSupported(convert(value))
        is DPoPUsage.Required -> DPoPUsage.Required(convert(value))
    }
