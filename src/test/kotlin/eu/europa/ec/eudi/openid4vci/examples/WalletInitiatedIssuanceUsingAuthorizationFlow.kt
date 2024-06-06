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

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.ensure
import kotlinx.coroutines.runBlocking

fun main(): Unit = runBlocking {
    runUseCase(PidDevIssuer.issuerId, PidDevIssuer.AllCredentialConfigurationIds)
}

fun runUseCase(
    credentialIssuerId: CredentialIssuerId,
    credentialConfigurationIds: List<CredentialConfigurationIdentifier>,
): Unit = runBlocking {
    println("[[Scenario: Issuance based on credential configuration ids: $credentialConfigurationIds]] ")

    val (issuerMetadata, authorizationServersMetadata) = createHttpClient(enableLogging = false).use { client ->
        Issuer.metaData(client, credentialIssuerId)
    }

    credentialConfigurationIds.forEach {
        ensure(issuerMetadata.credentialConfigurationsSupported[it] != null) {
            error("Credential identifier $it not supported by issuer")
        }
    }

    val credentialOffer = CredentialOffer(
        credentialIssuerIdentifier = credentialIssuerId,
        credentialIssuerMetadata = issuerMetadata,
        authorizationServerMetadata = authorizationServersMetadata[0],
        credentialConfigurationIdentifiers = credentialConfigurationIds,
    )

    val issuer = Issuer.make(
        config = PidDevIssuer.cfg,
        credentialOffer = credentialOffer,
        ktorHttpClientFactory = ::createHttpClient,
    ).getOrThrow()

    with(issuer) {
        authorizationLog("Using authorized code flow to authorize")
        val authorizedRequest = authorizeRequestWithAuthCodeUseCase(PidDevIssuer.testUser).also {
            authorizationLog("Authorization retrieved: $it")
        }

        credentialOffer.credentialConfigurationIdentifiers.forEach { credentialIdentifier ->
            submitCredentialRequest(authorizedRequest, credentialIdentifier).also {
                println("--> Issued credential: $it \n")
            }
        }
    }
}

private suspend fun Issuer.authorizeRequestWithAuthCodeUseCase(actingUser: ActingUser): AuthorizedRequest {
    authorizationLog("Preparing authorization code request")

    val prepareAuthorizationCodeRequest = prepareAuthorizationRequest().getOrThrow().also {
        authorizationLog("Get authorization code URL is: ${it.authorizationCodeURL.value}")
    }

    return with(prepareAuthorizationCodeRequest) {
        val (authorizationCode, serverState) = PidDevIssuer.loginUserAndGetAuthCode(
            prepareAuthorizationCodeRequest,
            actingUser,
        )

        authorizationLog("Authorization code retrieved: $authorizationCode")

        authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState).getOrThrow().also {
            authorizationLog("Authorization code exchanged with access token : ${it.accessToken.accessToken}")
        }
    }
}

private suspend fun Issuer.submitCredentialRequest(
    authorizedRequest: AuthorizedRequest,
    credentialConfigurationId: CredentialConfigurationIdentifier,
): String {
    issuanceLog("Requesting issuance of '$credentialConfigurationId'")
    return when (authorizedRequest) {
        is AuthorizedRequest.NoProofRequired -> submitProvidingNoProofs(authorizedRequest, credentialConfigurationId)

        is AuthorizedRequest.ProofRequired -> submitProvidingProofs(authorizedRequest, credentialConfigurationId)
    }
}

private suspend fun Issuer.submitProvidingNoProofs(
    authorized: AuthorizedRequest.NoProofRequired,
    credentialConfigurationId: CredentialConfigurationIdentifier,
): String {
    val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, null)
    return when (val submittedRequest = authorized.requestSingle(requestPayload).getOrThrow()) {
        is SubmittedRequest.Success -> handleSuccess(authorized, submittedRequest)
        is SubmittedRequest.Failed -> throw submittedRequest.error
        is SubmittedRequest.InvalidProof -> {
            this@submitProvidingNoProofs.submitProvidingProofs(
                authorized.handleInvalidProof(submittedRequest.cNonce),
                credentialConfigurationId,
            )
        }
    }
}

private suspend fun Issuer.submitProvidingProofs(
    authorized: AuthorizedRequest.ProofRequired,
    credentialConfigurationId: CredentialConfigurationIdentifier,
): String {
    val proofSigner = popSigner(credentialConfigurationId)

    val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, null)
    val submittedRequest = authorized.requestSingle(requestPayload, proofSigner).getOrThrow()

    return when (submittedRequest) {
        is SubmittedRequest.Success -> handleSuccess(authorized, submittedRequest)
        is SubmittedRequest.Failed -> throw submittedRequest.error
        is SubmittedRequest.InvalidProof -> throw IllegalStateException(
            "Although providing a proof with c_nonce the proof is still invalid",
        )
    }
}

private suspend fun Issuer.handleSuccess(
    authorizedRequest: AuthorizedRequest,
    submittedRequest: SubmittedRequest.Success,
) =
    when (val issuedCredential = submittedRequest.credentials.first()) {
        is IssuedCredential.Issued -> issuedCredential.credential
        is IssuedCredential.Deferred -> {
            handleDeferred(authorizedRequest, issuedCredential)
        }
    }
