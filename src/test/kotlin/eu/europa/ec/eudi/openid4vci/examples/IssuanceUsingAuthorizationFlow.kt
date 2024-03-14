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
import eu.europa.ec.eudi.openid4vci.internal.DefaultIssuer
import eu.europa.ec.eudi.openid4vci.internal.ensure
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.coroutines.runBlocking
import org.jsoup.Jsoup
import org.jsoup.nodes.FormElement
import java.net.URL

//private val CredentialIssuer_URL = "https://dev.issuer-backend.eudiw.dev"
private const val CredentialIssuer_URL = "http://localhost:8080"
private val actingUser = ActingUser("tneal", "password")

fun main(): Unit = runBlocking {

    offerBasedIssuance(
        credentialOfferUrl = "eudi-openid4vci://?credential_offer=${
            createCredentialOfferStr(
                CredentialIssuer_URL,
                listOf(PID_SdJwtVC_config_id, PID_MsoMdoc_config_id, MDL_config_id)
            )
        }",
        actingUser = actingUser,
    )

    credentialConfigurationBasedIssuance(
        credentialConfigurationId = PID_SdJwtVC_config_id,
        credentialIssuerIdentifier = CredentialIssuer_URL,
        actingUser = actingUser,
    )
    credentialConfigurationBasedIssuance(
        credentialConfigurationId = PID_MsoMdoc_config_id,
        credentialIssuerIdentifier = CredentialIssuer_URL,
        actingUser = actingUser,
    )
    credentialConfigurationBasedIssuance(
        credentialConfigurationId = MDL_config_id,
        credentialIssuerIdentifier = CredentialIssuer_URL,
        actingUser = actingUser,
    )
}

private suspend fun offerBasedIssuance(
    credentialOfferUrl: String,
    actingUser: ActingUser,
    vciConfig: OpenId4VCIConfig = DefaultOpenId4VCIConfig,
) {
    println("[[Scenario: Issuance based on credential offer url: $credentialOfferUrl]] ")

    val credentialOfferRequestResolver = CredentialOfferRequestResolver(ktorHttpClientFactory = ::httpClientFactory)
    val credentialOffer = credentialOfferRequestResolver.resolve(credentialOfferUrl).getOrThrow()

    val issuer = Issuer.make(
        config = vciConfig,
        credentialOffer = credentialOffer,
    )

    authorizationLog("Using authorized code flow to authorize")
    val authorizedRequest = authorizeRequestWithAuthCodeUseCase(issuer, actingUser)
    authorizationLog("Authorization retrieved: $authorizedRequest")

    val credentials = when (authorizedRequest) {
        is AuthorizedRequest.NoProofRequired -> credentialOffer.credentialConfigurationIdentifiers.map { credentialId ->
            issuanceLog("Requesting issuance of '$credentialId'")
            val credential = noProofRequiredSubmissionUseCase(issuer, authorizedRequest, credentialId)
            credentialId.value to credential
        }

        is AuthorizedRequest.ProofRequired -> credentialOffer.credentialConfigurationIdentifiers.map { credentialId ->
            issuanceLog("Requesting issuance of '$credentialId'")
            val credential = proofRequiredSubmissionUseCase(issuer, authorizedRequest, credentialId)
            credentialId.value to credential
        }
    }

    println("--> Issued credentials :")
    credentials.onEach { (credentialId, credential) ->
        println("\t [$credentialId] : $credential")
    }
    println()
}


private suspend fun credentialConfigurationBasedIssuance(
    credentialIssuerIdentifier: String,
    credentialConfigurationId: String,
    actingUser: ActingUser,
    vciConfig: OpenId4VCIConfig = DefaultOpenId4VCIConfig,
) {
    println("[[Scenario: Issuance based on credential configuration: $credentialConfigurationId]] ")
    val credentialIssuerId = CredentialIssuerId(credentialIssuerIdentifier).getOrThrow()

    val (issuerMetadata, authorizationServersMetadata) = httpClientFactory().use { client ->
        Issuer.metaData(client, credentialIssuerId)
    }

    val credentialIdentifier = CredentialConfigurationIdentifier(credentialConfigurationId)
    ensure(issuerMetadata.credentialConfigurationsSupported.get(credentialIdentifier) != null) {
        error("Credential identifier $credentialConfigurationId not supported by issuer")
    }

    val credentialOffer = CredentialOffer(
        credentialIssuerIdentifier = credentialIssuerId,
        credentialIssuerMetadata = issuerMetadata,
        authorizationServerMetadata = authorizationServersMetadata[0],
        credentialConfigurationIdentifiers = listOf(credentialIdentifier),
    )

    val issuer = Issuer.make(
        config = vciConfig,
        credentialOffer = credentialOffer,
    )

    authorizationLog("Using authorized code flow to authorize")
    val authorizedRequest = authorizeRequestWithAuthCodeUseCase(issuer, actingUser)
    authorizationLog("Authorization retrieved: $authorizedRequest")

    issuanceLog("Requesting issuance of '$credentialIssuerIdentifier'")
    val outcome = when (authorizedRequest) {
        is AuthorizedRequest.NoProofRequired -> noProofRequiredSubmissionUseCase(issuer, authorizedRequest, credentialIdentifier)
        is AuthorizedRequest.ProofRequired -> proofRequiredSubmissionUseCase(issuer, authorizedRequest, credentialIdentifier)
    }

    println("--> Issued credential: $outcome \n")
}

private suspend fun authorizeRequestWithAuthCodeUseCase(issuer: Issuer, actingUser: ActingUser): AuthorizedRequest =
    with(issuer) {
        check(issuer is DefaultIssuer)
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

private suspend fun noProofRequiredSubmissionUseCase(
    issuer: Issuer,
    noProofRequiredState: AuthorizedRequest.NoProofRequired,
    credentialConfigurationId: CredentialConfigurationIdentifier,
): String {
    with(issuer) {
        val submittedRequest = noProofRequiredState.requestSingle(credentialConfigurationId to null, null).getOrThrow()

        return when (submittedRequest) {
            is SubmittedRequest.Success -> {
                when (val issuedCredential = submittedRequest.credentials[0]) {
                    is IssuedCredential.Issued -> issuedCredential.credential
                    is IssuedCredential.Deferred -> {
                        deferredCredentialUseCase(issuer, noProofRequiredState, issuedCredential)
                    }
                }
            }

            is SubmittedRequest.InvalidProof -> {
                proofRequiredSubmissionUseCase(
                    issuer,
                    noProofRequiredState.handleInvalidProof(submittedRequest.cNonce),
                    credentialConfigurationId,
                )
            }

            is SubmittedRequest.Failed -> throw submittedRequest.error
        }
    }
}

private suspend fun proofRequiredSubmissionUseCase(
    issuer: Issuer,
    authorized: AuthorizedRequest.ProofRequired,
    credentialConfigurationId: CredentialConfigurationIdentifier,
): String {
    with(issuer) {
        val proofSigner = DefaultProofSignersMap[credentialConfigurationId.value]
            ?: error("No signer found for credential $credentialConfigurationId")

        val submittedRequest =
            authorized.requestSingle(credentialConfigurationId to null, null, proofSigner).getOrThrow()

        return when (submittedRequest) {
            is SubmittedRequest.Success -> {
                when (val issuedCredential = submittedRequest.credentials[0]) {
                    is IssuedCredential.Issued -> issuedCredential.credential
                    is IssuedCredential.Deferred -> {
                        deferredCredentialUseCase(issuer, authorized, issuedCredential)
                    }
                }
            }

            is SubmittedRequest.Failed -> throw submittedRequest.error

            is SubmittedRequest.InvalidProof -> throw IllegalStateException(
                "Although providing a proof with c_nonce the proof is still invalid",
            )
        }
    }
}

private suspend fun deferredCredentialUseCase(
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



