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
package eu.europa.ec.eudi.openid4vci.internal.issuance

import eu.europa.ec.eudi.openid4vci.*
import java.util.*

@Suppress("ktlint")
class DefaultAuthorizationCodeFlowIssuer(
    val authorizer: IssuanceAuthorizer,
    val issuanceRequester: IssuanceRequester,
) : AuthorizationCodeFlowIssuer {

    override suspend fun placePushedAuthorizationRequest(
        credentials: List<OfferedCredential>,
        issuerState: String?,
    ): Result<AuthCodeFlowIssuance.ParRequested> =
        runCatching {
            // Get scopes from credentials
            val scopes = credentials.map { it.scope }.filterNotNull()

            val state = UUID.randomUUID().toString()
            // Place PAR
            val (codeVerifier, getAuthorizationCodeUrl) =
                authorizer.submitPushedAuthorizationRequest(scopes, state, issuerState).getOrThrow()

            // Transition state
            AuthCodeFlowIssuance.ParRequested(
                credentials = credentials,
                getAuthorizationCodeURL = getAuthorizationCodeUrl,
                pkceVerifier = codeVerifier,
                state = state,
            )
        }

    override suspend fun AuthCodeFlowIssuance.ParRequested.completePar(
        authorizationCode: String,
    ): Result<AuthCodeFlowIssuance.AuthorizationCodeRetrieved> =
        runCatching {

            require(authorizationCode.isNotEmpty()) { "Authorization code cannot be empty" }

            AuthCodeFlowIssuance.AuthorizationCodeRetrieved(
                credentials = credentials,
                authorizationCode = IssuanceAuthorization.AuthorizationCode(authorizationCode),
                pkceVerifier = this.pkceVerifier,
            )

        }

    override suspend fun AuthCodeFlowIssuance.AuthorizationCodeRetrieved.placeAccessTokenRequest(): Result<AuthCodeFlowIssuance.Authorized> =
        runCatching {
            val (accessToken, nonce) =
                authorizer.requestAccessTokenAuthFlow(
                    this.authorizationCode.authorizationCode,
                    this.pkceVerifier.codeVerifier,
                ).getOrThrow()

            nonce?.let {
                AuthCodeFlowIssuance.Authorized.ProofRequired(
                    credentials = credentials,
                    token = IssuanceAccessToken(accessToken),
                    cNonce = nonce,
                )
            } ?: AuthCodeFlowIssuance.Authorized.NoProofRequired(
                credentials = credentials,
                token = IssuanceAccessToken(accessToken),
            )
        }

    override suspend fun AuthCodeFlowIssuance.Authorized.NoProofRequired.requestIssuance(claims: ClaimSet): Result<AuthCodeFlowIssuance.Requested> =
        runCatching {

            val credentialRequest = credentialRequest(null)

            requestIssuance(credentialRequest, token) {
                if (it is CredentialIssuanceException) {
                    if (it.error is CredentialIssuanceError.InvalidProof) {
                        AuthCodeFlowIssuance.Requested.NonceMissing(
                            error = it.error,
                            credentials = credentials,
                            token = token,
                        )
                    } else
                        AuthCodeFlowIssuance.Requested.GenericFailure(it.error)
                } else
                    throw it

            }
        }

    override suspend fun AuthCodeFlowIssuance.Authorized.ProofRequired.requestIssuance(
        proof: Proof,
        claims: ClaimSet
    ): Result<AuthCodeFlowIssuance.Requested> = runCatching {

        val credentialRequest = credentialRequest(proof)

        requestIssuance(credentialRequest, token) {
            if (it is CredentialIssuanceException) {
                AuthCodeFlowIssuance.Requested.GenericFailure(it.error)
            } else {
                throw it
            }
        }
    }

    override suspend fun AuthCodeFlowIssuance.Requested.NonceMissing.reProcess(): AuthCodeFlowIssuance.Authorized.ProofRequired =
        AuthCodeFlowIssuance.Authorized.ProofRequired(
            credentials = credentials,
            token = token,
            cNonce = cNonce,
        )

    private suspend fun requestIssuance(
        credentialRequest: CredentialIssuanceRequest,
        token: IssuanceAccessToken,
        handleFailure: (Throwable) -> AuthCodeFlowIssuance.Requested,
    ): AuthCodeFlowIssuance.Requested =
        when (credentialRequest) {
            is CredentialIssuanceRequest.SingleCredential -> {
                issuanceRequester.placeIssuanceRequest(token, credentialRequest)
                    .fold(
                        onSuccess = {
                            AuthCodeFlowIssuance.Requested.Success(it)
                        },
                        onFailure = handleFailure
                    )
            }
            is CredentialIssuanceRequest.BatchCredentials -> {
                issuanceRequester.placeBatchIssuanceRequest(token, credentialRequest)
                    .fold(
                        onSuccess = {
                            AuthCodeFlowIssuance.Requested.Success(it)
                        },
                        onFailure = handleFailure
                    )
            }
        }


    private fun AuthCodeFlowIssuance.Authorized.credentialRequest(proof: Proof?): CredentialIssuanceRequest =
        when {
            credentials.size == 1 -> {
                issuanceRequester.issuerMetadata.credentialsSupported
                    .firstOrNull { it.scope == credentials[0].scope }
                    ?.let {
                        when (it) {
                            is CredentialSupported.MsoMdocCredentialCredentialSupported ->
                                CredentialIssuanceRequest.SingleCredential.MsoMdocIssuanceRequest(
                                    doctype = it.docType,
                                    proof = proof,
                                ).getOrThrow()

                            else -> throw CredentialIssuanceException(
                                CredentialIssuanceError.InvalidIssuanceRequest(
                                    "Only mso_mdoc credential requests supported"
                                )
                            )
                        }
                    } ?: throw CredentialIssuanceException(
                    CredentialIssuanceError.InvalidIssuanceRequest(
                        "Offered credential scope does not match any of issuer's supported credentials"
                    )
                )
            }

            else -> TODO("Batch issuance requests not yet supported")
        }

}
