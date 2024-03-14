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

private val CredentialIssuer_URL = "https://trial.authlete.net"

fun main(): Unit = runBlocking {

    offerBasedIssuance(
        credentialOfferUrl = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Ftrial.authlete.net%2Fapi%2Foffer%2FZIERWe-fL35jD6OaJnpvaQFqxk687qhZcC5X1a6Osp0",
        txCode = "112233",
        vciConfig = OpenId4VCIConfig(
            clientId = "218232426",
            authFlowRedirectionURI = URI.create("urn:ietf:wg:oauth:2.0:oob"),
            keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
        )
    )

    credentialConfigurationBasedIssuance(
        credentialIssuerIdentifier = CredentialIssuer_URL,
        credentialConfigurationId = PID_SdJwtVC_config_id,
        txCode = "112233",
        vciConfig = OpenId4VCIConfig(
            clientId = "218232426",
            authFlowRedirectionURI = URI.create("urn:ietf:wg:oauth:2.0:oob"),
            keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
        )
    )

}

suspend fun offerBasedIssuance(
    credentialOfferUrl: String,
    txCode: String,
    vciConfig: OpenId4VCIConfig = DefaultOpenId4VCIConfig,
) {
    println("[[Scenario: Issuance based on credential offer url: $credentialOfferUrl]] ")

    val credentialOfferRequestResolver = CredentialOfferRequestResolver(ktorHttpClientFactory = ::httpClientFactory)
    val credentialOffer = credentialOfferRequestResolver.resolve(credentialOfferUrl).getOrThrow()

    ensure(credentialOffer.grants is Grants.PreAuthorizedCode || credentialOffer.grants is Grants.Both) {
        IllegalStateException("Offer does not have expected grants (PreAuthorizedCode | Both)")
    }

    val issuer = Issuer.make(
        config = vciConfig,
        credentialOffer = credentialOffer,
    )

    authorizationLog("Using pre-authorized code flow to authorize with txCode $txCode")
    val authorizedRequest = issuer.authorizeWithPreAuthorizationCode(txCode).getOrThrow()
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

suspend fun credentialConfigurationBasedIssuance(
    credentialIssuerIdentifier: String,
    credentialConfigurationId: String,
    txCode: String,
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

    authorizationLog("Using pre-authorized code flow to authorize with txCode $txCode")
    val authorizedRequest = issuer.authorizeWithPreAuthorizationCode(txCode).getOrThrow()
    authorizationLog("Authorization retrieved: $authorizedRequest")

    issuanceLog("Requesting issuance of '$credentialIssuerIdentifier'")
    val outcome = when (authorizedRequest) {
        is AuthorizedRequest.NoProofRequired -> noProofRequiredSubmissionUseCase(issuer, authorizedRequest, credentialIdentifier)
        is AuthorizedRequest.ProofRequired -> proofRequiredSubmissionUseCase(issuer, authorizedRequest, credentialIdentifier)
    }

    println("--> Issued credential: $outcome \n")
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
