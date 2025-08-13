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
package eu.europa.ec.eudi.openid4vci.internal.http

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWEDecryptionKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.InvalidResponseContentType
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
        runCatching {
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
            contentType(ContentType.Application.Json)
            setBody(CredentialRequestTO.from(request))
        }
        return if (response.status.isSuccess()) {
            val submissionOutcome = responsePossiblyEncrypted(
                response,
                request.encryption,
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
     * @param responseEncryptionSpec The response encryption information as specified when placing the issuance request. If initial request
     *      had specified response encryption then the issuer response is expected to be encrypted by the encryption details of the initial
     *      issuance request.
     * @return response from issuer. Can be either positive if a credential is issued or error in case issuance is still pending
     */
    suspend fun placeDeferredCredentialRequest(
        accessToken: AccessToken,
        resourceServerDpopNonce: Nonce?,
        transactionId: TransactionId,
        responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
    ): Result<Pair<DeferredCredentialQueryOutcome, Nonce?>> =
        runCatching {
            placeDeferredCredentialRequestInternal(
                accessToken,
                resourceServerDpopNonce,
                transactionId,
                responseEncryptionSpec,
                false,
            )
        }

    private suspend fun placeDeferredCredentialRequestInternal(
        accessToken: AccessToken,
        resourceServerDpopNonce: Nonce?,
        transactionId: TransactionId,
        responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
        retried: Boolean,
    ): Pair<DeferredCredentialQueryOutcome, Nonce?> {
        val url = deferredCredentialEndpoint.value
        val jwt = if (accessToken is AccessToken.DPoP && dPoPJwtFactory != null) {
            dPoPJwtFactory.createDPoPJwt(Htm.POST, url, accessToken, resourceServerDpopNonce).getOrThrow()
                .serialize()
        } else null

        val response = httpClient.post(url) {
            bearerOrDPoPAuth(accessToken, jwt)
            contentType(ContentType.Application.Json)
            setBody(
                DeferredRequestTO(
                    transactionId = transactionId.value,
                    credentialResponseEncryption = responseEncryptionSpec?.let { CredentialResponseEncryptionSpecTO.from(it) },
                ),
            )
        }

        return if (response.status.isSuccess()) {
            val outcome =
                responsePossiblyEncrypted<DeferredIssuanceSuccessResponseTO, DeferredCredentialQueryOutcome>(
                    response,
                    responseEncryptionSpec,
                    fromTransferObject = { it.toDomain() },
                    transferObjectFromJwtClaims = { DeferredIssuanceSuccessResponseTO.from(it) },
                )
            val newResourceServerDpopNonce = response.dpopNonce()
            outcome to (newResourceServerDpopNonce ?: resourceServerDpopNonce)
        } else {
            val newResourceServerDpopNonce = response.dpopNonce()
            if (response.isResourceServerDpopNonceRequired() && newResourceServerDpopNonce != null && !retried) {
                placeDeferredCredentialRequestInternal(
                    accessToken,
                    newResourceServerDpopNonce,
                    transactionId,
                    responseEncryptionSpec,
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

private suspend inline fun <reified ResponseTO, Response> responsePossiblyEncrypted(
    response: HttpResponse,
    encryptionSpec: IssuanceResponseEncryptionSpec?,
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
                    encryptionSpec.encryptionKeyAlgorithm,
                    encryptionSpec.encryptionMethod,
                    ImmutableJWKSet(JWKSet(encryptionSpec.jwk)),
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
