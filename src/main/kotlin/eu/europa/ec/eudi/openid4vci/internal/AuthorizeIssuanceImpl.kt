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

import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vci.*

internal sealed interface AuthorizationDetail {
    data class ByCredentialConfiguration(
        val credentialConfigurationId: CredentialConfigurationIdentifier,
    ) : AuthorizationDetail

    sealed class ByFormat(
        val format: String,
    ) : AuthorizationDetail
}

internal data class MsoMdocAuthorizationDetails(
    val doctype: String,
) : AuthorizationDetail.ByFormat(FORMAT_MSO_MDOC)

internal data class SdJwtVcAuthorizationDetails(
    val vct: String,
) : AuthorizationDetail.ByFormat(FORMAT_SD_JWT_VC)

internal class AuthorizeIssuanceImpl(
    private val credentialOffer: CredentialOffer,
    config: OpenId4VCIConfig,
    ktorHttpClientFactory: KtorHttpClientFactory,
) : AuthorizeIssuance {

    private val authorizer: IssuanceAuthorizer =
        IssuanceAuthorizer(credentialOffer.authorizationServerMetadata, config, ktorHttpClientFactory)

    override suspend fun prepareAuthorizationRequest(): Result<AuthorizationRequestPrepared> = runCatching {
        val scopes = mutableListOf<Scope>()
        val authDetails = mutableListOf<AuthorizationDetail>()
        credentialOffer.credentialConfigurationIdentifiers.map { credentialConfigurationId ->
            credentialSupportedById(credentialConfigurationId).scope?.let { scopes.add(Scope(it)) }
                ?: authDetails.add(AuthorizationDetail.ByCredentialConfiguration(credentialConfigurationId))
        }
        val state = State().value
        val issuerState = when (credentialOffer.grants) {
            is Grants.AuthorizationCode -> credentialOffer.grants.issuerState
            is Grants.Both -> credentialOffer.grants.authorizationCode.issuerState
            else -> null
        }

        val authorizationServerSupportsPar = credentialOffer.authorizationServerMetadata.pushedAuthorizationRequestEndpointURI != null
        val (codeVerifier, authorizationCodeUrl) = when (authorizationServerSupportsPar) {
            true -> authorizer.submitPushedAuthorizationRequest(scopes, authDetails, state, issuerState).getOrThrow()
            false -> authorizer.authorizationRequestUrl(scopes, authDetails, state, issuerState).getOrThrow()
        }
        AuthorizationRequestPrepared(authorizationCodeUrl, codeVerifier)
    }

    private fun credentialSupportedById(credentialConfigurationId: CredentialConfigurationIdentifier): CredentialSupported {
        val credentialSupported = credentialOffer.credentialIssuerMetadata.credentialsSupported[credentialConfigurationId]
        return requireNotNull(credentialSupported) {
            "$credentialConfigurationId was not found within issuer metadata"
        }
    }

    override suspend fun AuthorizationRequestPrepared.authorizeWithAuthorizationCode(
        authorizationCode: AuthorizationCode,
    ): Result<AuthorizedRequest> = kotlin.runCatching {
        val offerRequiresProofs = credentialOffer.requiresProofs()
        val (accessToken, cNonce) = authorizer.requestAccessTokenAuthFlow(authorizationCode.code, pkceVerifier.codeVerifier).getOrThrow()

        when {
            cNonce != null && offerRequiresProofs -> AuthorizedRequest.ProofRequired(accessToken, cNonce)
            else -> AuthorizedRequest.NoProofRequired(accessToken)
        }
    }

    override suspend fun authorizeWithPreAuthorizationCode(txCode: String?): Result<AuthorizedRequest> = runCatching {
        val offeredGrants = credentialOffer.grants
        require(offeredGrants != null) { "Grant not specified in credential offer." }
        val preAuthorizedCode = when (offeredGrants) {
            is Grants.PreAuthorizedCode -> offeredGrants
            is Grants.Both -> offeredGrants.preAuthorizedCode
            is Grants.AuthorizationCode -> error("Pre-authorized code grant expected")
        }
        preAuthorizedCode.txCode?.let {
            require(!txCode.isNullOrEmpty()) {
                "Issuer's grant is pre-authorization code with transaction code required but no transaction code passed"
            }
            preAuthorizedCode.txCode.length?.let {
                require(preAuthorizedCode.txCode.length == txCode.length) {
                    "Expected transaction code length is ${preAuthorizedCode.txCode.length} but code of length ${txCode.length} passed"
                }
            }
            if (TxCodeInputMode.NUMERIC == preAuthorizedCode.txCode.inputMode) {
                require(txCode.toIntOrNull() != null) {
                    "Issuers expects transaction code to be numeric but is not."
                }
            }
        }
        val offerRequiresProofs = credentialOffer.requiresProofs()
        val (accessToken, cNonce) = authorizer.requestAccessTokenPreAuthFlow(preAuthorizedCode.preAuthorizedCode, txCode).getOrThrow()

        when {
            cNonce != null && offerRequiresProofs -> AuthorizedRequest.ProofRequired(accessToken, cNonce)
            else -> AuthorizedRequest.NoProofRequired(accessToken)
        }
    }

    private fun CredentialOffer.requiresProofs(): Boolean =
        credentialConfigurationIdentifiers.any { !credentialIssuerMetadata.credentialsSupported[it]?.proofTypesSupported.isNullOrEmpty() }
}
