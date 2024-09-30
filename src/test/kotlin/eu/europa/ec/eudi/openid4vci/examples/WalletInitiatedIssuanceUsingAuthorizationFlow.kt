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
import kotlinx.coroutines.runBlocking

fun main(): Unit = runBlocking {
    runUseCase(PidDevIssuer.cfg, PidDevIssuer.issuerId, PidDevIssuer.AllCredentialConfigurationIds)
}

fun runUseCase(
    config: OpenId4VCIConfig,
    credentialIssuerId: CredentialIssuerId,
    credentialConfigurationIds: List<CredentialConfigurationIdentifier>,
): Unit = runBlocking {
    println("[[Scenario: Issuance based on credential configuration ids: $credentialConfigurationIds]] ")

    val issuer = Issuer.makeWalletInitiated(
        config,
        credentialIssuerId,
        credentialConfigurationIds,
        { createHttpClient(enableLogging = false) },
    ).getOrThrow()

    with(issuer) {
        authorizationLog("Using authorized code flow to authorize")
        var authorizedRequest = authorizeRequestWithAuthCodeUseCase(PidDevIssuer.testUser).also {
            authorizationLog("Authorization retrieved: $it")
        }

        credentialOffer.credentialConfigurationIdentifiers.forEach { credentialIdentifier ->

            submitCredentialRequest(
                authorizedRequest,
                credentialIdentifier,
            ).also { (newAuthorizedRequest, credential) ->
                println("--> Issued credential: $credential \n")
                authorizedRequest = newAuthorizedRequest
            }
        }
    }
}

private suspend fun Issuer.authorizeRequestWithAuthCodeUseCase(actingUser: KeycloakUser): AuthorizedRequest {
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
): AuthorizedRequestAnd<List<IssuedCredential>> {
    issuanceLog("Requesting issuance of '$credentialConfigurationId'")
    val proofSigners = popSigners(credentialConfigurationId, proofsNo = 1)
    val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, null)
    val (newAuthorized, outcome) =
        authorizedRequest.request(requestPayload, proofSigners).getOrThrow()

    return when (outcome) {
        is SubmissionOutcome.Success -> newAuthorized to outcome.credentials
        is SubmissionOutcome.Deferred -> {
            println("Hm we got a deferred issuance case with ${outcome.transactionId.value}")
            val vcs = run {
                val ctx = newAuthorized.deferredContext(outcome)
                queryDeferredEndpoint(ctx)
            }

            newAuthorized to vcs
        }
        is SubmissionOutcome.Failed ->
            throw if (outcome.error is CredentialIssuanceError.InvalidProof) {
                IllegalStateException("Although providing a proof with c_nonce the proof is still invalid")
            } else outcome.error
    }
}

private suspend fun queryDeferredEndpoint(
    deferredContext: DeferredIssuanceContext,
): List<IssuedCredential> {
    var ctx = deferredContext
    var cred: List<IssuedCredential>
    do {
        val (newCtx, outcome) = DeferredIssuer.queryForDeferredCredential(ctx = ctx).getOrThrow()
        ctx = newCtx ?: ctx
        cred = when (outcome) {
            is DeferredCredentialQueryOutcome.Errored -> error(outcome.error)
            is DeferredCredentialQueryOutcome.IssuancePending -> emptyList()
            is DeferredCredentialQueryOutcome.Issued -> outcome.credentials
        }
    } while (cred.isEmpty())
    return cred
}
