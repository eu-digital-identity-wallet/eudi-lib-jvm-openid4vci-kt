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
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.coroutines.runBlocking
import org.jsoup.Jsoup
import org.jsoup.nodes.FormElement
import java.net.URL

private val CredentialIssuer_URL = "https://dev.issuer-backend.eudiw.dev"
private val actingUser = ActingUser("tneal", "password")

fun main(): Unit = runBlocking {
    val credentialConfigurationIds = listOf(PID_SdJwtVC_config_id, PID_MsoMdoc_config_id, MDL_config_id)

    println("[[Scenario: Issuance based on credential configuration ids: $credentialConfigurationIds]] ")
    val credentialIssuerId = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()

    val (issuerMetadata, authorizationServersMetadata) = httpClientFactory().use { client ->
        Issuer.metaData(client, credentialIssuerId)
    }

    val identifiers = credentialConfigurationIds.map { CredentialConfigurationIdentifier(it) }

    identifiers.forEach {
        ensure(issuerMetadata.credentialConfigurationsSupported.get(it) != null) {
            error("Credential identifier $it not supported by issuer")
        }
    }

    val credentialOffer = CredentialOffer(
        credentialIssuerIdentifier = credentialIssuerId,
        credentialIssuerMetadata = issuerMetadata,
        authorizationServerMetadata = authorizationServersMetadata[0],
        credentialConfigurationIdentifiers = identifiers,
    )

    val issuer = Issuer.make(
        config = DefaultOpenId4VCIConfig,
        credentialOffer = credentialOffer,
    ).getOrThrow()

    authorizationLog("Using authorized code flow to authorize")
    val authorizedRequest = authorizeRequestWithAuthCodeUseCase(issuer, actingUser)
    authorizationLog("Authorization retrieved: $authorizedRequest")

    credentialOffer.credentialConfigurationIdentifiers.forEach { credentialIdentifier ->
        issuanceLog("Requesting issuance of '$credentialIdentifier'")
        val outcome = when (authorizedRequest) {
            is AuthorizedRequest.NoProofRequired -> submitProvidingNoProofs(issuer, authorizedRequest, credentialIdentifier)
            is AuthorizedRequest.ProofRequired -> submitProvidingProofs(issuer, authorizedRequest, credentialIdentifier)
        }
        println("--> Issued credential: $outcome \n")
    }
}

private suspend fun authorizeRequestWithAuthCodeUseCase(issuer: Issuer, actingUser: ActingUser): AuthorizedRequest =
    with(issuer) {
        authorizationLog("Preparing authorization code request")

        val prepareAuthorizationCodeRequest = issuer.prepareAuthorizationRequest().getOrThrow()

        authorizationLog("Get authorization code URL is: ${prepareAuthorizationCodeRequest.authorizationCodeURL.value}")

        val authorizationCode = loginUserAndGetAuthCode(
            prepareAuthorizationCodeRequest.authorizationCodeURL.value,
            actingUser,
        ) ?: error("Could not retrieve authorization code")

        authorizationLog("Authorization code retrieved: $authorizationCode")

        val authorizedRequest = prepareAuthorizationCodeRequest.authorizeWithAuthorizationCode(
            AuthorizationCode(authorizationCode),
        ).getOrThrow()

        authorizationLog("Authorization code exchanged with access token : ${authorizedRequest.accessToken.accessToken}")

        authorizedRequest
    }

private suspend fun loginUserAndGetAuthCode(getAuthorizationCodeUrl: URL, actingUser: ActingUser): String? {
    return httpClientFactory().use { client ->
        val loginUrl = client.get(getAuthorizationCodeUrl).body<String>().extractASLoginUrl()

        val formParameters = mapOf(
            "username" to actingUser.username,
            "password" to actingUser.password,
        )
        val response = client.submitForm(
            url = loginUrl.toString(),
            formParameters = Parameters.build {
                formParameters.entries.forEach { append(it.key, it.value) }
            },
        )
        val redirectLocation = response.headers["Location"].toString()
        URLBuilder(redirectLocation).parameters["code"]
    }
}

private fun String.extractASLoginUrl(): URL {
    val form = Jsoup.parse(this).body().getElementById("kc-form-login") as FormElement
    val action = form.attr("action")
    return URL(action)
}

private suspend fun submitProvidingNoProofs(
    issuer: Issuer,
    authorized: AuthorizedRequest.NoProofRequired,
    credentialConfigurationId: CredentialConfigurationIdentifier,
): String {
    with(issuer) {
        val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, null)
        val submittedRequest = authorized.requestSingle(requestPayload).getOrThrow()

        return when (submittedRequest) {
            is SubmittedRequest.Success -> handleSuccess(submittedRequest, issuer, authorized)
            is SubmittedRequest.Failed -> throw submittedRequest.error
            is SubmittedRequest.InvalidProof -> {
                submitProvidingProofs(
                    issuer,
                    authorized.handleInvalidProof(submittedRequest.cNonce),
                    credentialConfigurationId,
                )
            }
        }
    }
}

private suspend fun submitProvidingProofs(
    issuer: Issuer,
    authorized: AuthorizedRequest.ProofRequired,
    credentialConfigurationId: CredentialConfigurationIdentifier,
): String {
    with(issuer) {
        val proofSigner = DefaultProofSignersMap[credentialConfigurationId.value]
            ?: error("No signer found for credential $credentialConfigurationId")

        val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, null)
        val submittedRequest = authorized.requestSingle(requestPayload, proofSigner).getOrThrow()

        return when (submittedRequest) {
            is SubmittedRequest.Success -> handleSuccess(submittedRequest, issuer, authorized)
            is SubmittedRequest.Failed -> throw submittedRequest.error
            is SubmittedRequest.InvalidProof -> throw IllegalStateException(
                "Although providing a proof with c_nonce the proof is still invalid",
            )
        }
    }
}

private suspend fun handleSuccess(
    submittedRequest: SubmittedRequest.Success,
    issuer: Issuer,
    noProofRequiredState: AuthorizedRequest,
) = when (val issuedCredential = submittedRequest.credentials[0]) {
    is IssuedCredential.Issued -> issuedCredential.credential
    is IssuedCredential.Deferred -> {
        handleDeferred(issuer, noProofRequiredState, issuedCredential)
    }
}

private suspend fun handleDeferred(
    issuer: Issuer,
    authorized: AuthorizedRequest,
    deferred: IssuedCredential.Deferred,
): String {
    issuanceLog(
        "Got a deferred issuance response from server with transaction_id ${deferred.transactionId.value}. Retrying issuance...",
    )
    with(issuer) {
        return when (val outcome = authorized.queryForDeferredCredential(deferred).getOrThrow()) {
            is DeferredCredentialQueryOutcome.Issued -> outcome.credential.credential
            is DeferredCredentialQueryOutcome.IssuancePending -> throw RuntimeException(
                "Credential not ready yet. Try after ${outcome.interval}",
            )

            is DeferredCredentialQueryOutcome.Errored -> throw RuntimeException(outcome.error)
        }
    }
}
