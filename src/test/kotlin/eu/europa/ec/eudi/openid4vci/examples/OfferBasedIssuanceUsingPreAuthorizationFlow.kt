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
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.proofsSpecForEcKeys
import eu.europa.ec.eudi.openid4vci.internal.ensure
import kotlinx.coroutines.runBlocking
import java.net.URI

fun main(): Unit = runBlocking {
    val vciConfig = OpenId4VCIConfig(
        client = Client.Public("218232426"),
        authFlowRedirectionURI = URI.create("urn:ietf:wg:oauth:2.0:oob"),
        keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
        credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
    )
    val credentialOfferUrl =
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Ftrial.authlete.net" +
            "%2Fapi%2Foffer%2F8pggPQOduiocIajQONmvh1iJdDue8zFhg9R9joDDOPc"
    val txCode = "112233"

    println("[[Scenario: Issuance based on credential offer url: $credentialOfferUrl]] ")
    createHttpClient().use { httpClient ->

        val issuer = Issuer.make(
            config = vciConfig,
            credentialOfferUri = credentialOfferUrl,
            httpClient = httpClient,
        ).getOrThrow()

        val credentialOffer = issuer.credentialOffer
        ensure(credentialOffer.grants is Grants.PreAuthorizedCode || credentialOffer.grants is Grants.Both) {
            IllegalStateException("Offer does not have expected grants (PreAuthorizedCode | Both)")
        }

        authorizationLog("Using pre-authorized code flow to authorize with txCode $txCode")
        var authorizedRequest = issuer.authorizeWithPreAuthorizationCode(txCode).getOrThrow()
        authorizationLog("Authorization retrieved: $authorizedRequest")

        val credentials =
            credentialOffer.credentialConfigurationIdentifiers.map { credentialId ->
                issuanceLog("Requesting issuance of '$credentialId'")
                val (newAuthorizedRequest, credential) = submit(issuer, authorizedRequest, credentialId)
                authorizedRequest = newAuthorizedRequest
                credentialId.value to credential
            }

        println("--> Issued credentials :")
        credentials.onEach { (credentialId, credential) ->
            println("\t [$credentialId] : $credential")
        }
    }
}

private suspend fun submit(
    issuer: Issuer,
    authorized: AuthorizedRequest,
    credentialConfigurationId: CredentialConfigurationIdentifier,
): AuthorizedRequestAnd<List<IssuedCredential>> {
    with(issuer) {
        val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
        val (newAuthorized, outcome) =
            authorized.request(requestPayload, proofsSpecForEcKeys(Curve.P_256)).getOrThrow()

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
