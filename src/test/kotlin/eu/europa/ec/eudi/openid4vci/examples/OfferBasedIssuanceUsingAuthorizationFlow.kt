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

private val actingUser = ActingUser("tneal", "password")

fun main(): Unit = runBlocking {
    val credentialOfferUrl = "eudi-openid4ci://?credential_offer=%7B%22" +
        "credential_issuer%22:%22https://dev.issuer-backend.eudiw.dev%22,%22" +
        "credential_configuration_ids%22:[%22$PID_MsoMdoc_config_id%22," +
        "%22$PID_SdJwtVC_config_id%22,%22$MDL_config_id%22]," +
        "%22grants%22:%7B%22authorization_code%22:%7B%22" +
        "authorization_server%22:%22https://dev.auth.eudiw.dev/realms/pid-issuer-realm%22%7D%7D%7D"

    println("[[Scenario: Issuance based on credential offer url: $credentialOfferUrl]] ")

    val issuer = Issuer.make(
        config = DefaultOpenId4VCIConfig,
        credentialOfferUri = credentialOfferUrl,
        ktorHttpClientFactory = ::createHttpClient,
    ).getOrThrow()

    val credentialOffer = issuer.credentialOffer
    ensure(credentialOffer.grants is Grants.AuthorizationCode || credentialOffer.grants is Grants.Both) {
        IllegalStateException("Offer does not have expected grants (AuthorizationCode | Both)")
    }

    authorizationLog("Using authorized code flow to authorize")
    val authorizedRequest = authorizeRequestWithAuthCodeUseCase(issuer, actingUser)
    authorizationLog("Authorization retrieved: $authorizedRequest")

    val offerCredentialConfIds = credentialOffer.credentialConfigurationIdentifiers

    val credentials = when (authorizedRequest) {
        is AuthorizedRequest.NoProofRequired -> offerCredentialConfIds.map { credentialId ->
            issuanceLog("Requesting issuance of '$credentialId'")
            val credential = submitProvidingNoProofs(issuer, authorizedRequest, credentialId)
            credentialId.value to credential
        }

        is AuthorizedRequest.ProofRequired -> offerCredentialConfIds.map { credentialId ->
            issuanceLog("Requesting issuance of '$credentialId'")
            val credential = submitProvidingProofs(issuer, authorizedRequest, credentialId)
            credentialId.value to credential
        }
    }

    println("--> Issued credentials :")
    credentials.onEach { (credentialId, credential) ->
        println("\t [$credentialId] : $credential")
    }
}

private suspend fun authorizeRequestWithAuthCodeUseCase(issuer: Issuer, actingUser: ActingUser): AuthorizedRequest =
    with(issuer) {
        authorizationLog("Preparing authorization code request")

        val prepareAuthorizationCodeRequest = issuer.prepareAuthorizationRequest().getOrThrow()

        authorizationLog("Get authorization code URL is: ${prepareAuthorizationCodeRequest.authorizationCodeURL.value}")

        val (authorizationCode, serverState) = loginUserAndGetAuthCode(
            prepareAuthorizationCodeRequest.authorizationCodeURL.value,
            actingUser,
        ) ?: error("Could not retrieve authorization code")

        authorizationLog("Authorization code retrieved: $authorizationCode")

        val authorizedRequest = prepareAuthorizationCodeRequest.authorizeWithAuthorizationCode(
            AuthorizationCode(authorizationCode),
            serverState,
        ).getOrThrow()

        authorizationLog("Authorization code exchanged with access token : ${authorizedRequest.accessToken.accessToken}")

        authorizedRequest
    }

private suspend fun loginUserAndGetAuthCode(getAuthorizationCodeUrl: URL, actingUser: ActingUser): Pair<String, String>? {
    return createHttpClient().use { client ->
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
        with(URLBuilder(redirectLocation)) {
            parameters["code"] to parameters["state"]
        }.toNullable()
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
    authorized: AuthorizedRequest,
) = when (val issuedCredential = submittedRequest.credentials[0]) {
    is IssuedCredential.Issued -> issuedCredential.credential
    is IssuedCredential.Deferred -> {
        handleDeferred(issuer, authorized, issuedCredential)
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
