/*
 * Copyright (c) 2023-2026 European Commission
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
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.attestationProofSpec
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.keyAttestationJwtProofsSpec
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.noKeyAttestationJwtProofsSpec
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
import kotlin.math.min
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

sealed interface BatchOption {
    data object DontUse : BatchOption
    data class Specific(val proofsNo: Int) : BatchOption
    data object MaxProofs : BatchOption
}

sealed interface ProofsType {
    val batchOption: BatchOption

    @JvmInline
    value class JwtProofsNoKeyAttestation(override val batchOption: BatchOption) : ProofsType

    @JvmInline
    value class JwtProofWithKeyAttestation(override val batchOption: BatchOption) : ProofsType

    @JvmInline
    value class AttestationProof(override val batchOption: BatchOption) : ProofsType
}

suspend fun Issuer.submitCredentialRequest(
    authorizedRequest: AuthorizedRequest,
    credentialConfigurationId: CredentialConfigurationIdentifier =
        credentialOffer.credentialConfigurationIdentifiers.first(),
    proofsType: ProofsType,
): AuthorizedRequestAnd<SubmissionOutcome> {
    val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
    val batchOption = proofsType.batchOption
    val proofsNo =
        when (batchOption) {
            BatchOption.DontUse -> 1
            BatchOption.MaxProofs -> when (val batchIssuance = credentialOffer.credentialIssuerMetadata.batchCredentialIssuance) {
                BatchCredentialIssuance.NotSupported -> 1
                is BatchCredentialIssuance.Supported -> batchIssuance.batchSize
            }

            is BatchOption.Specific -> when (val batchIssuance = credentialOffer.credentialIssuerMetadata.batchCredentialIssuance) {
                BatchCredentialIssuance.NotSupported -> 1
                is BatchCredentialIssuance.Supported -> min(batchIssuance.batchSize, batchOption.proofsNo)
            }
        }

    val proofSpec: ProofsSpecification = when (proofsType) {
        is ProofsType.JwtProofsNoKeyAttestation -> noKeyAttestationJwtProofsSpec(Curve.P_256, proofsNo)
        is ProofsType.JwtProofWithKeyAttestation -> keyAttestationJwtProofsSpec(Curve.P_256, proofsNo)
        is ProofsType.AttestationProof -> attestationProofSpec(keysNo = proofsNo)
    }
    return authorizedRequest.request(requestPayload, proofSpec).getOrThrow()
}

suspend fun <ENV, USER> Issuer.authorizeUsingAuthorizationCodeFlow(
    env: ENV,
    httpClient: HttpClient,
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
                httpClient,
            )
            authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState).getOrThrow()
        }
    }

/**
 *
 */
suspend fun <ENV, USER> Issuer.testIssuanceWithAuthorizationCodeFlow(
    env: ENV,
    credCfgId: CredentialConfigurationIdentifier = credentialOffer.credentialConfigurationIdentifiers.first(),
    proofsType: ProofsType,
    httpClient: HttpClient,
) where
      ENV : HasTestUser<USER>,
      ENV : CanAuthorizeIssuance<USER> =
    coroutineScope {
        val authorizedReq = authorizeUsingAuthorizationCodeFlow(env, httpClient)
        val (updatedAuthorizedReq, outcome) =
            submitCredentialRequest(authorizedReq, credCfgId, proofsType)

        ensureIssued(updatedAuthorizedReq, outcome, httpClient)
    }

suspend fun Issuer.testIssuanceWithPreAuthorizedCodeFlow(
    txCode: String?,
    credCfgId: CredentialConfigurationIdentifier,
    proofsType: ProofsType,
    httpClient: HttpClient,
) = coroutineScope {
    val (authorized, outcome) = run {
        val authorizedRequest = authorizeWithPreAuthorizationCode(txCode).getOrThrow()
        submitCredentialRequest(authorizedRequest, credCfgId, proofsType)
    }
    ensureIssued(authorized, outcome, httpClient)
}

suspend fun Issuer.ensureIssued(
    authorized: AuthorizedRequest,
    outcome: SubmissionOutcome,
    httpClient: HttpClient,
) {
    when (outcome) {
        is SubmissionOutcome.Failed -> {
            fail("Issuer rejected request. Reason :${outcome.error.message}")
        }
        is SubmissionOutcome.Deferred -> {
            issuanceLog(
                "Got a deferred issuance response from server with transaction_id ${outcome.transactionId.value}. Retrying issuance...",
            )
            val deferredCtx = authorized.deferredContext(outcome)
            handleDeferred(deferredCtx, httpClient).onEach(::println)
        }
        is SubmissionOutcome.Success -> {
            outcome.credentials.forEach(::println)
        }
    }
}

suspend fun handleDeferred(
    initialContext: DeferredIssuanceContext,
    httpClient: HttpClient,
): List<IssuedCredential> {
    var ctx = initialContext
    var cred: List<IssuedCredential>
    do {
        val (newCtx, outcome) = DeferredIssuer.queryForDeferredCredential(
            ctx = ctx,
            httpClient = httpClient,
            responseEncryptionKey = null,
        ).getOrThrow()

        ctx = newCtx ?: ctx
        cred = when (outcome) {
            is DeferredCredentialQueryOutcome.Errored -> error(outcome.error)
            is DeferredCredentialQueryOutcome.IssuancePending -> emptyList()
            is DeferredCredentialQueryOutcome.Issued -> outcome.credentials
        }
    } while (cred.isEmpty())
    return cred
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
    proofsType: ProofsType = ProofsType.JwtProofsNoKeyAttestation(batchOption = BatchOption.DontUse),
    httpClient: HttpClient,
) where
      ENV : HasTestUser<USER>,
      ENV : CanAuthorizeIssuance<USER>,
      ENV : CanBeUsedWithVciLib,
      ENV : CanRequestForCredentialOffer<USER> {
    val credentialOfferUri = requestAuthorizationCodeGrantOffer(credCfgIds = setOf(credCfgId))
    val issuer = assertDoesNotThrow {
        createIssuer(credentialOfferUri.toString(), httpClient)
    }

    with(issuer) {
        val credCfg = credentialOffer.credentialIssuerMetadata.credentialConfigurationsSupported[credCfgId]
        assertNotNull(credCfg)
        testIssuanceWithAuthorizationCodeFlow(
            env = this@testIssuanceWithAuthorizationCodeFlow,
            proofsType = proofsType,
            httpClient = httpClient,
        )
    }
}

suspend fun <ENV, USER> ENV.testIssuanceWithPreAuthorizedCodeFlow(
    txCode: String?,
    credCfgId: CredentialConfigurationIdentifier,
    credentialOfferEndpoint: String? = null,
    proofsOptions: ProofsType,
    httpClient: HttpClient,
) where ENV : CanBeUsedWithVciLib, ENV : HasTestUser<USER>, ENV : CanRequestForCredentialOffer<USER> {
    val credentialOfferUri = requestPreAuthorizedCodeGrantOffer(
        setOf(credCfgId),
        txCode = txCode,
        credentialOfferEndpoint = credentialOfferEndpoint,
    )
    val issuer = assertDoesNotThrow {
        createIssuer(credentialOfferUri.toString(), httpClient)
    }
    with(issuer) {
        val credCfg = credentialOffer.credentialIssuerMetadata.credentialConfigurationsSupported[credCfgId]
        assertNotNull(credCfg)
        testIssuanceWithPreAuthorizedCodeFlow(
            txCode = txCode,
            credCfgId = credCfgId,
            proofsType = proofsOptions,
            httpClient = httpClient,
        )
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
            Issuer.metaData(httpClient, issuerId, IssuerMetadataPolicy.IgnoreSigned)
        } catch (t: Throwable) {
            when (t) {
                is CredentialIssuerMetadataError -> fail("Credential Issuer Metadata error", cause = t.cause)
                is AuthorizationServerMetadataResolutionException -> fail(
                    "Authorization Server Metadata resolution error",
                    t.cause,
                )

                else -> fail(cause = t)
            }
        }
    }
}
