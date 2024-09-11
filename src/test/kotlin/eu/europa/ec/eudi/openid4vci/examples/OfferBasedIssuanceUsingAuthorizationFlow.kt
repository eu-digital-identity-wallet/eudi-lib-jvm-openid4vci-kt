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
    val credentialOfferUrl = "eudi-openid4ci://?credential_offer=%7B%22" +
        "credential_issuer%22:%22https://dev.issuer-backend.eudiw.dev%22,%22" +
        "credential_configuration_ids%22:[%22${PidDevIssuer.PID_MsoMdoc_config_id.value}%22," +
        "%22${PidDevIssuer.PID_SdJwtVC_config_id.value}%22,%22${PidDevIssuer.MDL_config_id.value}%22]," +
        "%22grants%22:%7B%22authorization_code%22:%7B%22" +
        "authorization_server%22:%22https://dev.auth.eudiw.dev/realms/pid-issuer-realm%22%7D%7D%7D"

    println("[[Scenario: Issuance based on credential offer url: $credentialOfferUrl]] ")

    val issuer = Issuer.make(
        config = PidDevIssuer.cfg,
        credentialOfferUri = credentialOfferUrl,
        ktorHttpClientFactory = ::createHttpClient,
    ).getOrThrow()

    val credentialOffer = issuer.credentialOffer
    ensure(credentialOffer.grants is Grants.AuthorizationCode || credentialOffer.grants is Grants.Both) {
        IllegalStateException("Offer does not have expected grants (AuthorizationCode | Both)")
    }

    authorizationLog("Using authorized code flow to authorize")
    var authorizedRequest = authorizeRequestWithAuthCodeUseCase(issuer, PidDevIssuer.testUser)
    authorizationLog("Authorization retrieved: $authorizedRequest")

    val offerCredentialConfIds = credentialOffer.credentialConfigurationIdentifiers

    val credentials = offerCredentialConfIds.associate { credentialId ->
        issuanceLog("Requesting issuance of '$credentialId'")
        val (newAuthorizedRequest, credentials) = submit(issuer, authorizedRequest, credentialId)
        authorizedRequest = newAuthorizedRequest
        credentialId.value to credentials
    }

    println("--> Issued credentials :")
    credentials.onEach { (credentialId, credentials) ->
        println("\t [$credentialId] : $credentials")
    }
}

private suspend fun authorizeRequestWithAuthCodeUseCase(
    issuer: Issuer,
    actingUser: KeycloakUser,
): AuthorizedRequest =
    with(issuer) {
        authorizationLog("Preparing authorization code request")

        val prepareAuthorizationCodeRequest = issuer.prepareAuthorizationRequest().getOrThrow()

        authorizationLog("Get authorization code URL is: ${prepareAuthorizationCodeRequest.authorizationCodeURL.value}")

        val (authorizationCode, serverState) =
            PidDevIssuer.loginUserAndGetAuthCode(prepareAuthorizationCodeRequest, actingUser)

        authorizationLog("Authorization code retrieved: $authorizationCode")

        val authorizedRequest = prepareAuthorizationCodeRequest.authorizeWithAuthorizationCode(
            AuthorizationCode(authorizationCode),
            serverState,
        ).getOrThrow()

        authorizationLog("Authorization code exchanged with access token : ${authorizedRequest.accessToken.accessToken}")

        authorizedRequest
    }

private suspend fun submit(
    issuer: Issuer,
    authorized: AuthorizedRequest,
    credentialConfigurationId: CredentialConfigurationIdentifier,
): AuthorizedRequestAnd<List<IssuedCredential>> {
    with(issuer) {
        val proofSigner = popSigner(credentialConfigurationId)
        val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, null)
        val (newAuthorized, outcome) = authorized.requestSingle(requestPayload, proofSigner).getOrThrow()
        return when (outcome) {
            is SubmissionOutcome.Success -> newAuthorized to outcome.credentials
            is SubmissionOutcome.Deferred -> newAuthorized to handleDeferred(issuer, authorized, outcome.transactionId)
            is SubmissionOutcome.Failed ->
                throw if (outcome.error is CredentialIssuanceError.InvalidProof) {
                    IllegalStateException("Although providing a proof with c_nonce the proof is still invalid")
                } else outcome.error
        }
    }
}

private suspend fun handleDeferred(
    issuer: Issuer,
    authorized: AuthorizedRequest,
    transactionId: TransactionId,
): List<IssuedCredential> {
    issuanceLog(
        "Got a deferred issuance response from server with transaction_id ${transactionId.value}. Retrying issuance...",
    )
    with(issuer) {
        val (_, outcome) = authorized.queryForDeferredCredential(transactionId).getOrThrow()
        return when (outcome) {
            is DeferredCredentialQueryOutcome.Issued -> outcome.credentials
            is DeferredCredentialQueryOutcome.IssuancePending -> throw RuntimeException(
                "Credential not ready yet. Try after ${outcome.interval}",
            )

            is DeferredCredentialQueryOutcome.Errored -> throw RuntimeException(outcome.error)
        }
    }
}
