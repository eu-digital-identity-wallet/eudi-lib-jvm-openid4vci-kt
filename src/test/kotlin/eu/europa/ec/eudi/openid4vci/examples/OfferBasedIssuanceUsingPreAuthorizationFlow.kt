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

import com.nimbusds.jose.jwk.Curve
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.ensure
import kotlinx.coroutines.runBlocking
import java.net.URI

fun main(): Unit = runBlocking {
    val vciConfig = OpenId4VCIConfig(
        clientId = "218232426",
        authFlowRedirectionURI = URI.create("urn:ietf:wg:oauth:2.0:oob"),
        keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
        CredentialResponseEncryptionPolicy.SUPPORTED,
    )
    val credentialOfferUrl =
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Ftrial.authlete.net" +
            "%2Fapi%2Foffer%2F8pggPQOduiocIajQONmvh1iJdDue8zFhg9R9joDDOPc"
    val txCode = "112233"

    println("[[Scenario: Issuance based on credential offer url: $credentialOfferUrl]] ")

    val resolver = CredentialOfferRequestResolver(ktorHttpClientFactory = ::createHttpClient)
    val credentialOffer = resolver.resolve(credentialOfferUrl).getOrThrow()

    ensure(credentialOffer.grants is Grants.PreAuthorizedCode || credentialOffer.grants is Grants.Both) {
        IllegalStateException("Offer does not have expected grants (PreAuthorizedCode | Both)")
    }

    val issuer = Issuer.make(
        config = vciConfig,
        credentialOffer = credentialOffer,
    ).getOrThrow()

    authorizationLog("Using pre-authorized code flow to authorize with txCode $txCode")
    val authorizedRequest = issuer.authorizeWithPreAuthorizationCode(txCode).getOrThrow()
    authorizationLog("Authorization retrieved: $authorizedRequest")

    val credentials = when (authorizedRequest) {
        is AuthorizedRequest.NoProofRequired -> credentialOffer.credentialConfigurationIdentifiers.map { credentialId ->
            issuanceLog("Requesting issuance of '$credentialId'")
            val credential = submitProvidingNoProofs(issuer, authorizedRequest, credentialId)
            credentialId.value to credential
        }

        is AuthorizedRequest.ProofRequired -> credentialOffer.credentialConfigurationIdentifiers.map { credentialId ->
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
                    authorized.handleInvalidProof(submittedRequest.cNonce, "client_id"),
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
