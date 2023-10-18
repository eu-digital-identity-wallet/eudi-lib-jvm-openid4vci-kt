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

internal class DefaultIssuer(
    val authorizer: IssuanceAuthorizer,
    val issuanceRequester: IssuanceRequester,
) : Issuer {

    override suspend fun placePushedAuthorizationRequest(
        credentials: List<OfferedCredential>,
        issuerState: String?,
    ): Result<UnauthorizedRequest.ParRequested> =
        runCatching {
            // Get scopes from credentials
            val scopes = credentials.map { it.scope }.filterNotNull()

            val state = UUID.randomUUID().toString()
            // Place PAR
            val (codeVerifier, getAuthorizationCodeUrl) =
                authorizer.submitPushedAuthorizationRequest(scopes, state, issuerState).getOrThrow()

            // Transition state
            UnauthorizedRequest.ParRequested(
                credentials = credentials,
                getAuthorizationCodeURL = getAuthorizationCodeUrl,
                pkceVerifier = codeVerifier,
                state = state,
            )
        }

    override suspend fun preAuthorize(
        credentials: List<OfferedCredential>,
        preAuthorizedCode: String,
        pin: String,
    ): Result<UnauthorizedRequest.PreAuthorized> =
        Result.success(
            UnauthorizedRequest.PreAuthorized(
                credentials = credentials,
                authorizationCode = IssuanceAuthorization.PreAuthorizationCode(
                    preAuthorizedCode = preAuthorizedCode,
                    pin = pin,
                ),
            ),
        )

    override suspend fun UnauthorizedRequest.ParRequested.receiveAuthorizationCode(
        authorizationCode: String,
    ): Result<UnauthorizedRequest.AuthorizationCodeRetrieved> =
        runCatching {
            require(authorizationCode.isNotEmpty()) { "Authorization code cannot be empty" }

            UnauthorizedRequest.AuthorizationCodeRetrieved(
                credentials = credentials,
                authorizationCode = IssuanceAuthorization.AuthorizationCode(authorizationCode),
                pkceVerifier = this.pkceVerifier,
            )
        }

    override suspend fun UnauthorizedRequest.AuthorizationCodeRetrieved.placeAccessTokenRequest(): Result<AuthorizedRequest> =
        runCatching {
            val (accessToken, nonce) =
                authorizer.requestAccessTokenAuthFlow(
                    this.authorizationCode.authorizationCode,
                    this.pkceVerifier.codeVerifier,
                ).getOrThrow()

            nonce?.let {
                AuthorizedRequest.ProofRequired(
                    credentials = credentials,
                    token = IssuanceAccessToken(accessToken),
                    cNonce = nonce,
                )
            } ?: AuthorizedRequest.NoProofRequired(
                credentials = credentials,
                token = IssuanceAccessToken(accessToken),
            )
        }

    override suspend fun UnauthorizedRequest.PreAuthorized.placeAccessTokenRequest(): Result<AuthorizedRequest> =
        runCatching {
            val (accessToken, nonce) =
                authorizer.requestAccessTokenPreAuthFlow(
                    authorizationCode.preAuthorizedCode,
                    authorizationCode.pin,
                ).getOrThrow()

            nonce?.let {
                AuthorizedRequest.ProofRequired(
                    credentials = credentials,
                    token = IssuanceAccessToken(accessToken),
                    cNonce = nonce,
                )
            } ?: AuthorizedRequest.NoProofRequired(
                credentials = credentials,
                token = IssuanceAccessToken(accessToken),
            )
        }

    override suspend fun AuthorizedRequest.NoProofRequired.submitRequest(claims: ClaimSet): Result<SubmittedRequest> =
        runCatching {
            val credentialRequest = credentialRequest(null)

            requestIssuance(credentialRequest, token) {
                if (it is CredentialIssuanceException) {
                    if (it.error is CredentialIssuanceError.InvalidProof) {
                        SubmittedRequest.NonceMissing(
                            error = it.error,
                            credentials = credentials,
                            token = token,
                        )
                    } else {
                        SubmittedRequest.Failed(it.error)
                    }
                } else {
                    throw it
                }
            }
        }

    private fun AuthorizedRequest.credentialRequest(proof: Proof?): CredentialIssuanceRequest =
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
                                    "Only mso_mdoc credential requests supported",
                                ),
                            )
                        }
                    } ?: throw CredentialIssuanceException(
                    CredentialIssuanceError.InvalidIssuanceRequest(
                        "Offered credential scope does not match any of issuer's supported credentials",
                    ),
                )
            }

            else -> TODO("Batch issuance requests not yet supported")
        }
    private suspend fun requestIssuance(
        credentialRequest: CredentialIssuanceRequest,
        token: IssuanceAccessToken,
        handleFailure: (Throwable) -> SubmittedRequest,
    ): SubmittedRequest =
        when (credentialRequest) {
            is CredentialIssuanceRequest.SingleCredential -> {
                issuanceRequester.placeIssuanceRequest(token, credentialRequest)
                    .fold(
                        onSuccess = {
                            SubmittedRequest.Success(it)
                        },
                        onFailure = handleFailure,
                    )
            }
            is CredentialIssuanceRequest.BatchCredentials -> {
                issuanceRequester.placeBatchIssuanceRequest(token, credentialRequest)
                    .fold(
                        onSuccess = {
                            SubmittedRequest.Success(it)
                        },
                        onFailure = handleFailure,
                    )
            }
        }

    override suspend fun AuthorizedRequest.ProofRequired.submitRequest(
        proof: Proof,
        claims: ClaimSet,
    ): Result<SubmittedRequest> = runCatching {
        val credentialRequest = credentialRequest(proof)

        requestIssuance(credentialRequest, token) {
            if (it is CredentialIssuanceException) {
                SubmittedRequest.Failed(it.error)
            } else {
                throw it
            }
        }
    }

    override suspend fun SubmittedRequest.NonceMissing.reProcess(): AuthorizedRequest.ProofRequired =
        AuthorizedRequest.ProofRequired(
            credentials = credentials,
            token = token,
            cNonce = cNonce,
        )

    override suspend fun SubmittedRequest.Success.process(): Result<ProcessedRequest.Unvalidated> {
        TODO("Not yet implemented")
    }

    override suspend fun ProcessedRequest.Unvalidated.Responded.validate(): Result<ProcessedRequest.Issued> {
        TODO("Not yet implemented")
    }

    override suspend fun ProcessedRequest.Unvalidated.Deferred.request(): Result<ProcessedRequest.Unvalidated> {
        TODO("Not yet implemented")
    }
}
