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
import io.ktor.client.*
import io.ktor.client.engine.apache.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.plugins.logging.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.Json
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.ssl.SSLContextBuilder
import org.junit.jupiter.api.assertDoesNotThrow
import java.net.URI
import kotlin.test.assertNotNull
import kotlin.test.fail

internal fun createHttpClient(enableLogging: Boolean = true): HttpClient = HttpClient(Apache) {
    install(ContentNegotiation) {
        json(
            json = Json { ignoreUnknownKeys = true },
        )
    }
    install(HttpCookies)
    if (enableLogging) {
        install(Logging) {
            logger = Logger.DEFAULT
            level = LogLevel.ALL
        }
    }
    engine {
        customizeClient {
            followRedirects = true
            setSSLContext(
                SSLContextBuilder.create().loadTrustMaterial(TrustSelfSignedStrategy()).build(),
            )
            setSSLHostnameVerifier(NoopHostnameVerifier())
        }
    }
}

internal fun authorizationLog(message: String) {
    println("--> [AUTHORIZATION] $message")
}

internal fun issuanceLog(message: String) {
    println("--> [ISSUANCE] $message")
}

//
// Issuer extensions
//

fun Issuer.popSigner(
    credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
    popSignerPreference: ProofTypeMetaPreference = ProofTypeMetaPreference.FavorJWT,
): PopSigner {
    val credentialConfigurationsSupported =
        credentialOffer.credentialIssuerMetadata.credentialConfigurationsSupported
    val credentialConfiguration =
        checkNotNull(credentialConfigurationsSupported[credentialConfigurationIdentifier])
    val popSigner = CryptoGenerator.popSigner(credentialConfiguration = credentialConfiguration, preference = popSignerPreference)
    return checkNotNull(popSigner) { "No signer can be generated for $credentialConfigurationIdentifier" }
}

suspend fun Issuer.submitCredentialRequest(
    authorizedRequest: AuthorizedRequest,
    credentialConfigurationId: CredentialConfigurationIdentifier =
        credentialOffer.credentialConfigurationIdentifiers.first(),
    claimSet: ClaimSet? = null,
    popSignerPreference: ProofTypeMetaPreference,
): SubmissionOutcome {
    val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, claimSet)
    return when (authorizedRequest) {
        is AuthorizedRequest.ProofRequired -> {
            with(authorizedRequest) {
                val popSigner = popSigner(credentialConfigurationId, popSignerPreference)
                requestSingle(requestPayload, popSigner).getOrThrow()
            }
        }

        is AuthorizedRequest.NoProofRequired -> with(authorizedRequest) { requestSingle(requestPayload).getOrThrow() }
    }
}

suspend fun <ENV, USER> Issuer.authorizeUsingAuthorizationCodeFlow(
    env: ENV,
    enableHttpLogging: Boolean = false,
): AuthorizedRequest
    where
          ENV : HasTestUser<USER>,
          ENV : CanAuthorizeIssuance<USER> =
    coroutineScope {
        val authorizationRequestPrepared = prepareAuthorizationRequest(walletState = null).getOrThrow()
        with(authorizationRequestPrepared) {
            val testUser = env.testUser
            val (authorizationCode, serverState) = env.loginUserAndGetAuthCode(
                authorizationRequestPrepared,
                testUser,
                enableHttpLogging,
            )
            authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState).getOrThrow()
        }
    }

/**
 *
 */
suspend fun <ENV, USER> Issuer.testIssuanceWithAuthorizationCodeFlow(
    env: ENV,
    enableHttpLogging: Boolean,
    credCfgId: CredentialConfigurationIdentifier = credentialOffer.credentialConfigurationIdentifiers.first(),
    claimSetToRequest: ClaimSet? = null,
    popSignerPreference: ProofTypeMetaPreference,
) where
      ENV : HasTestUser<USER>,
      ENV : CanAuthorizeIssuance<USER> =
    coroutineScope {
        val outcome = run {
            val authorizedRequest = authorizeUsingAuthorizationCodeFlow(env, enableHttpLogging)
            val outcome = submitCredentialRequest(authorizedRequest, credCfgId, claimSetToRequest, popSignerPreference)
            // If authorization server doesn't provide c_nonce in its token response
            // there is the chance that provides c_nonce via credential endpoint
            if (authorizedRequest is AuthorizedRequest.NoProofRequired && outcome is SubmissionOutcome.InvalidProof) {
                val proofRequired = authorizedRequest.withCNonce(outcome.cNonce)
                submitCredentialRequest(proofRequired, credCfgId, claimSetToRequest, popSignerPreference)
            } else outcome
        }

        ensureIssued(outcome)
        Unit
    }

suspend fun Issuer.testIssuanceWithPreAuthorizedCodeFlow(
    txCode: String?,
    credCfgId: CredentialConfigurationIdentifier,
    claimSetToRequest: ClaimSet?,
    popSignerPreference: ProofTypeMetaPreference,
) = coroutineScope {
    val (authorized, outcome) = run {
        val authorizedRequest = authorizeWithPreAuthorizationCode(txCode).getOrThrow()
        val outcome = submitCredentialRequest(authorizedRequest, credCfgId, claimSetToRequest, popSignerPreference)
        // If authorization server doesn't provide c_nonce in its token response,
        // there is the chance that provides c_nonce via credential endpoint
        if (authorizedRequest is AuthorizedRequest.NoProofRequired && outcome is SubmissionOutcome.InvalidProof) {
            val proofRequired = authorizedRequest.withCNonce(outcome.cNonce)
            proofRequired to submitCredentialRequest(proofRequired, credCfgId, claimSetToRequest, popSignerPreference)
        } else authorizedRequest to outcome
    }

    val issuedCredentials = ensureIssued(outcome)
    check(outcome is SubmissionOutcome.Success)
    issuedCredentials.filterIsInstance<IssuedCredential.Issued>().forEach { println(it) }
    issuedCredentials.filterIsInstance<IssuedCredential.Deferred>().forEach { deferred ->
        handleDeferred(authorized, deferred).also { println(it) }
    }
}

fun ensureIssued(outcome: SubmissionOutcome): List<IssuedCredential> =
    when (outcome) {
        is SubmissionOutcome.Failed -> {
            fail("Issuer rejected request. Reason :${outcome.error.message}")
        }

        is SubmissionOutcome.InvalidProof -> {
            val (_, error) = outcome
            fail("Issuer rejected proof. Reason: ${error ?: "n/a"}")
        }

        is SubmissionOutcome.Success -> {
            outcome.credentials
        }
    }

suspend fun Issuer.handleDeferred(
    authorized: AuthorizedRequest,
    deferred: IssuedCredential.Deferred,
): String {
    issuanceLog(
        "Got a deferred issuance response from server with transaction_id ${deferred.transactionId.value}. Retrying issuance...",
    )
    return when (val outcome = authorized.queryForDeferredCredential(deferred).getOrThrow()) {
        is DeferredCredentialQueryOutcome.Issued -> outcome.credential.credential
        is DeferredCredentialQueryOutcome.IssuancePending -> throw RuntimeException(
            "Credential not ready yet. Try after ${outcome.interval}",
        )
        is DeferredCredentialQueryOutcome.Errored -> throw RuntimeException(outcome.error)
    }
}

//
// ENV extensions
//

/**
 * Test the issuance of [credCfgId] using authorize code flow
 *
 * 1) Places a request for a [CredentialOffer]
 * 2) Creates an [Issuer]
 * 3) Uses the above to run execute the issuance
 *
 *
 */
suspend fun <ENV, USER> ENV.testIssuanceWithAuthorizationCodeFlow(
    credCfgId: CredentialConfigurationIdentifier,
    enableHttpLogging: Boolean = false,
    popSignerPreference: ProofTypeMetaPreference = ProofTypeMetaPreference.FavorCWT,
    claimSetToRequest: (CredentialConfiguration) -> ClaimSet? = { null },
) where
      ENV : HasTestUser<USER>,
      ENV : CanAuthorizeIssuance<USER>,
      ENV : CanBeUsedWithVciLib,
      ENV : CanRequestForCredentialOffer<USER> {
    val credentialOfferUri = requestAuthorizationCodeGrantOffer(credCfgIds = setOf(credCfgId))
    val issuer = assertDoesNotThrow {
        createIssuer(credentialOfferUri.toString(), enableHttpLogging)
    }

    with(issuer) {
        val credCfg = credentialOffer.credentialIssuerMetadata.credentialConfigurationsSupported[credCfgId]
        assertNotNull(credCfg)
        testIssuanceWithAuthorizationCodeFlow(
            env = this@testIssuanceWithAuthorizationCodeFlow,
            enableHttpLogging = enableHttpLogging,
            popSignerPreference = popSignerPreference,
            claimSetToRequest = claimSetToRequest.invoke(credCfg),
        )
    }
}

suspend fun <ENV, USER> ENV.testIssuanceWithPreAuthorizedCodeFlow(
    txCode: String?,
    credCfgId: CredentialConfigurationIdentifier,
    credentialOfferEndpoint: String? = null,
    enableHttpLogging: Boolean = false,
    popSignerPreference: ProofTypeMetaPreference = ProofTypeMetaPreference.FavorCWT,
    claimSetToRequest: (CredentialConfiguration) -> ClaimSet? = { null },
) where ENV : CanBeUsedWithVciLib, ENV : HasTestUser<USER>, ENV : CanRequestForCredentialOffer<USER> {
    val credentialOfferUri = requestPreAuthorizedCodeGrantOffer(
        setOf(credCfgId),
        txCode = txCode,
        credentialOfferEndpoint = credentialOfferEndpoint,
    )
    val issuer = assertDoesNotThrow {
        createIssuer(credentialOfferUri.toString(), enableHttpLogging)
    }
    with(issuer) {
        val credCfg = credentialOffer.credentialIssuerMetadata.credentialConfigurationsSupported[credCfgId]
        assertNotNull(credCfg)
        testIssuanceWithPreAuthorizedCodeFlow(txCode, credCfgId, claimSetToRequest(credCfg), popSignerPreference)
    }
}

/**
 * Given that a [Credential Issuer][ENV] [HasTestUser] and [CanRequestForCredentialOffer]
 * the method places a request for a [CredentialOffer] that uses the authorization code grant
 */
suspend fun <ENV, USER> ENV.requestAuthorizationCodeGrantOffer(
    credCfgIds: Set<CredentialConfigurationIdentifier>,
    issuerStateIncluded: Boolean = true,
    credentialOfferEndpoint: String? = null,
): URI
    where
          ENV : HasTestUser<USER>,
          ENV : CanRequestForCredentialOffer<USER> {
    val form = CredentialOfferForm.authorizationCodeGrant(
        user = testUser,
        credCfgIds,
        issuerStateIncluded,
        credentialOfferEndpoint,
    )
    return requestCredentialOffer(form)
}

/**
 * Given that a [Credential Issuer][ENV] [HasTestUser] and [CanRequestForCredentialOffer]
 * the method places a request for a [CredentialOffer] that uses the pre-authorized code grant
 */
suspend fun <ENV, USER> ENV.requestPreAuthorizedCodeGrantOffer(
    credCfgIds: Set<CredentialConfigurationIdentifier>,
    txCode: String?,
    credentialOfferEndpoint: String? = null,
): URI
    where
          ENV : HasTestUser<USER>,
          ENV : CanRequestForCredentialOffer<USER> {
    val form = CredentialOfferForm.preAuthorizedCodeGrant(
        testUser,
        credCfgIds,
        txCode,
        credentialOfferEndpoint,
    )
    return requestCredentialOffer(form)
}

suspend fun <ENV : HasIssuerId> ENV.testMetaDataResolution(
    enableHttpLogging: Boolean = false,
): Pair<CredentialIssuerMetadata, List<CIAuthorizationServerMetadata>> = coroutineScope {
    createHttpClient(enableHttpLogging).use { httpClient ->
        try {
            Issuer.metaData(httpClient, issuerId)
        } catch (t: Throwable) {
            when {
                t is CredentialIssuerMetadataError -> fail("Credential Issuer Metadata error", cause = t.cause)
                t is AuthorizationServerMetadataResolutionException -> fail("Authorization Server Metadata resolution error", t.cause)
                else -> fail(cause = t)
            }
        }
    }
}
