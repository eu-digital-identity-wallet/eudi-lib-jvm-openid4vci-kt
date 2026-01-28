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
package eu.europa.ec.eudi.openid4vci.internal.http

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEEncrypter
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWEDecryptionKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.InvalidResponseContentType
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.UnexpectedTransactionId
import eu.europa.ec.eudi.openid4vci.internal.CredentialIssuanceRequest
import eu.europa.ec.eudi.openid4vci.internal.SubmissionOutcomeInternal
import eu.europa.ec.eudi.openid4vci.internal.ensure
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*

internal class CredentialEndpointClient(
    private val credentialEndpoint: CredentialIssuerEndpoint,
    private val dPoPJwtFactory: DPoPJwtFactory?,
    private val httpClient: HttpClient,
) {
    /**
     * Method that submits a request to credential issuer for the issuance of a single credential.
     *
     * @param accessToken Access token authorizing the request
     * @param resourceServerDpopNonce Nonce value for DPoP provided by the Resource Server
     * @param request The single credential issuance request
     * @return credential issuer's response
     */
    suspend fun placeIssuanceRequest(
        accessToken: AccessToken,
        resourceServerDpopNonce: Nonce?,
        request: CredentialIssuanceRequest,
    ): Result<Pair<SubmissionOutcomeInternal, Nonce?>> =
        runCatchingCancellable {
            placeIssuanceRequestInternal(accessToken, resourceServerDpopNonce, request, false)
        }

    private suspend fun placeIssuanceRequestInternal(
        accessToken: AccessToken,
        resourceServerDpopNonce: Nonce?,
        request: CredentialIssuanceRequest,
        retried: Boolean,
    ): Pair<SubmissionOutcomeInternal, Nonce?> {
        val url = credentialEndpoint.value
        val jwt = if (accessToken is AccessToken.DPoP && dPoPJwtFactory != null) {
            dPoPJwtFactory.createDPoPJwt(Htm.POST, url, accessToken, resourceServerDpopNonce).getOrThrow()
                .serialize()
        } else null

        val response = httpClient.post(url) {
            bearerOrDPoPAuth(accessToken, jwt)
            encryptRequest(
                requestTO = CredentialRequestTO.from(request),
                requestEncryptionSpec = request.encryptionSpecs.requestEncryptionSpec,
                transferObjectToJwtClaims = { CredentialRequestTO.toJwtClaimsSet(it) },
            )
        }

        return if (response.status.isSuccess()) {
            val submissionOutcome = responsePossiblyEncrypted(
                response,
                request.encryptionSpecs.responseEncryptionSpec,
                fromTransferObject = { it.toDomain() },
                transferObjectFromJwtClaims = { CredentialResponseSuccessTO.from(it) },
            )
            val newResourceServerDpopNonce = response.dpopNonce()
            submissionOutcome to (newResourceServerDpopNonce ?: resourceServerDpopNonce)
        } else {
            val newResourceServerDpopNonce = response.dpopNonce()
            if (response.isResourceServerDpopNonceRequired() && newResourceServerDpopNonce != null && !retried) {
                placeIssuanceRequestInternal(accessToken, newResourceServerDpopNonce, request, true)
            } else {
                val error = response.body<GenericErrorResponseTO>()
                SubmissionOutcomeInternal.Failed(error.toIssuanceError()) to (
                    newResourceServerDpopNonce
                        ?: resourceServerDpopNonce
                    )
            }
        }
    }
}

internal class DeferredEndPointClient(
    private val deferredCredentialEndpoint: CredentialIssuerEndpoint,
    private val dPoPJwtFactory: DPoPJwtFactory?,
    private val httpClient: HttpClient,
) {
    /**
     * Method that submits a request to credential issuer's Deferred Credential Endpoint
     *
     * @param accessToken Access token authorizing the request
     * @param resourceServerDpopNonce Nonce value for DPoP provided by the Resource Server
     * @param transactionId The identifier of the Deferred Issuance transaction
     * @param exchangeEncryptionSpecification Encryption specifications for deferred request and response encryption
     * @return response from issuer. Can be either positive if a credential is issued or error in case issuance is still pending
     */
    suspend fun placeDeferredCredentialRequest(
        accessToken: AccessToken,
        resourceServerDpopNonce: Nonce?,
        transactionId: TransactionId,
        exchangeEncryptionSpecification: ExchangeEncryptionSpecification,
    ): Result<Pair<DeferredCredentialQueryOutcome, Nonce?>> =
        runCatchingCancellable {
            placeDeferredCredentialRequestInternal(
                accessToken,
                resourceServerDpopNonce,
                transactionId,
                exchangeEncryptionSpecification,
                false,
            )
        }

    private suspend fun placeDeferredCredentialRequestInternal(
        accessToken: AccessToken,
        resourceServerDpopNonce: Nonce?,
        transactionId: TransactionId,
        exchangeEncryptionSpecification: ExchangeEncryptionSpecification,
        retried: Boolean,
    ): Pair<DeferredCredentialQueryOutcome, Nonce?> {
        val url = deferredCredentialEndpoint.value
        val jwt = if (accessToken is AccessToken.DPoP && dPoPJwtFactory != null) {
            dPoPJwtFactory.createDPoPJwt(Htm.POST, url, accessToken, resourceServerDpopNonce).getOrThrow()
                .serialize()
        } else null

        val deferredRequestTO = DeferredRequestTO(
            transactionId = transactionId.value,
            credentialResponseEncryption = exchangeEncryptionSpecification.responseEncryptionSpec?.let {
                CredentialResponseEncryptionSpecTO.from(it)
            },
        )

        val response = httpClient.post(url) {
            bearerOrDPoPAuth(accessToken, jwt)
            encryptRequest(
                requestTO = deferredRequestTO,
                requestEncryptionSpec = exchangeEncryptionSpecification.requestEncryptionSpec,
                transferObjectToJwtClaims = { DeferredRequestTO.toJwtClaimsSet(it) },
            )
        }

        return if (response.status.isSuccess()) {
            val outcome =
                responsePossiblyEncrypted<DeferredIssuanceSuccessResponseTO, DeferredCredentialQueryOutcome>(
                    response,
                    exchangeEncryptionSpecification.responseEncryptionSpec,
                    fromTransferObject = { it.toDomain() },
                    transferObjectFromJwtClaims = { DeferredIssuanceSuccessResponseTO.from(it) },
                )
            if (outcome is DeferredCredentialQueryOutcome.IssuancePending) {
                outcome.ensureTransactionId(transactionId)
            }
            val newResourceServerDpopNonce = response.dpopNonce()
            outcome to (newResourceServerDpopNonce ?: resourceServerDpopNonce)
        } else {
            val newResourceServerDpopNonce = response.dpopNonce()
            if (response.isResourceServerDpopNonceRequired() && newResourceServerDpopNonce != null && !retried) {
                placeDeferredCredentialRequestInternal(
                    accessToken,
                    newResourceServerDpopNonce,
                    transactionId,
                    exchangeEncryptionSpecification,
                    true,
                )
            } else {
                val responsePayload = response.body<GenericErrorResponseTO>()
                val errored = DeferredCredentialQueryOutcome.Errored(responsePayload.error, responsePayload.errorDescription)
                errored to (newResourceServerDpopNonce ?: resourceServerDpopNonce)
            }
        }
    }
}

private inline fun <reified RequestTO> HttpRequestBuilder.encryptRequest(
    requestTO: RequestTO,
    requestEncryptionSpec: EncryptionSpec?,
    transferObjectToJwtClaims: (RequestTO) -> JWTClaimsSet,
) =
    when (requestEncryptionSpec) {
        null -> {
            contentType(ContentType.Application.Json)
            setBody(requestTO)
        }
        else -> {
            contentType(ContentType("application", "jwt"))

            val claimsSet = transferObjectToJwtClaims(requestTO)
            val encryptedRequest = requestEncryptionSpec.encrypt(claimsSet)

            setBody(encryptedRequest)
        }
    }

private fun EncryptionSpec.encrypt(jwtClaimSet: JWTClaimsSet): String {
    fun EncryptionSpec.jweHeader() =
        JWEHeader.Builder(algorithm, encryptionMethod).apply {
            jwk(recipientKey)
            type(JOSEObjectType.JWT)
            recipientKey.keyID?.let { keyID(it) }
            compressionAlgorithm?.let { compressionAlgorithm(it) }
        }.build()

    return EncryptedJWT(jweHeader(), jwtClaimSet)
        .apply { encrypt(recipientKey) }
        .serialize()
}

private fun EncryptedJWT.encrypt(jwk: JWK) {
    val encrypter: JWEEncrypter = when (jwk) {
        is RSAKey -> RSAEncrypter(jwk)
        is ECKey -> ECDHEncrypter(jwk)
        else -> error("unsupported 'kty': '${jwk.keyType.value}'")
    }
    encrypt(encrypter)
}

private suspend inline fun <reified ResponseTO, Response> responsePossiblyEncrypted(
    response: HttpResponse,
    encryptionSpec: EncryptionSpec?,
    fromTransferObject: (ResponseTO) -> Response,
    transferObjectFromJwtClaims: (JWTClaimsSet) -> ResponseTO,
): Response {
    check(response.status.isSuccess())
    val responseJson = when (encryptionSpec) {
        null -> {
            response.ensureContentType(ContentType.Application.Json)
            response.body<ResponseTO>()
        }

        else -> {
            val applicationJwt = ContentType("application", "jwt")
            response.ensureContentType(applicationJwt)
            val jwt = response.body<String>()
            val jwtProcessor = DefaultJWTProcessor<SecurityContext>().apply {
                jweKeySelector = JWEDecryptionKeySelector(
                    encryptionSpec.algorithm,
                    encryptionSpec.encryptionMethod,
                    ImmutableJWKSet(JWKSet(encryptionSpec.recipientKey)),
                )
            }
            val jwtClaimSet = jwtProcessor.process(jwt, null)
            transferObjectFromJwtClaims(jwtClaimSet)
        }
    }
    return fromTransferObject(responseJson)
}

private fun HttpResponse.ensureContentType(expectedContentType: ContentType) {
    ensure(contentType()?.withoutParameters() == expectedContentType) {
        InvalidResponseContentType(
            expectedContentType = expectedContentType.toString(),
            invalidContentType = contentType().toString(),
        )
    }
}

private fun DeferredCredentialQueryOutcome.IssuancePending.ensureTransactionId(expectedTransactionId: TransactionId) {
    ensure(expectedTransactionId == transactionId) {
        UnexpectedTransactionId(expected = expectedTransactionId, actual = transactionId)
    }
}
