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
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*

internal class CredentialEndpointClient(
    private val credentialEndpoint: CredentialIssuerEndpoint,
    private val dPoPJwtFactory: DPoPJwtFactory?,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) {

    /**
     * Method that submits a request to credential issuer for the issuance of a single credential.
     *
     * @param accessToken Access token authorizing the request
     * @param request The single credential issuance request
     * @return credential issuer's response
     */
    suspend fun placeIssuanceRequest(
        accessToken: AccessToken,
        request: CredentialIssuanceRequest,
    ): Result<SubmissionOutcomeInternal> = runCatching {
        ktorHttpClientFactory().use { client ->
            val url = credentialEndpoint.value
            val response = client.post(url) {
                bearerOrDPoPAuth(dPoPJwtFactory, url, Htm.POST, accessToken)
                contentType(ContentType.Application.Json)
                setBody(CredentialRequestTO.from(request))
            }
            if (response.status.isSuccess()) {
                responsePossiblyEncrypted(
                    response,
                    request.encryption,
                    fromTransferObject = { it.toDomain() },
                    transferObjectFromJwtClaims = { CredentialResponseSuccessTO.from(it) },
                )
            } else {
                val error = response.body<GenericErrorResponseTO>()
                SubmissionOutcomeInternal.Failed(error.toIssuanceError())
            }
        }
    }
}

internal class DeferredEndPointClient(
    private val deferredCredentialEndpoint: CredentialIssuerEndpoint,
    private val dPoPJwtFactory: DPoPJwtFactory?,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) {
    /**
     * Method that submits a request to credential issuer's Deferred Credential Endpoint
     *
     * @param accessToken Access token authorizing the request
     * @param transactionId The identifier of the Deferred Issuance transaction
     * @param responseEncryptionSpec The response encryption information as specified when placing the issuance request. If initial request
     *      had specified response encryption then the issuer response is expected to be encrypted by the encryption details of the initial
     *      issuance request.
     * @return response from issuer. Can be either positive if a credential is issued or error in case issuance is still pending
     */
    suspend fun placeDeferredCredentialRequest(
        accessToken: AccessToken,
        transactionId: TransactionId,
        responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
    ): Result<DeferredCredentialQueryOutcome> = runCatching {
        ktorHttpClientFactory().use { client ->
            val url = deferredCredentialEndpoint.value
            val response = client.post(url) {
                bearerOrDPoPAuth(dPoPJwtFactory, url, Htm.POST, accessToken)
                contentType(ContentType.Application.Json)
                setBody(DeferredRequestTO(transactionId.value))
            }
            if (response.status.isSuccess()) {
                responsePossiblyEncrypted<DeferredIssuanceSuccessResponseTO, DeferredCredentialQueryOutcome.Issued>(
                    response,
                    responseEncryptionSpec,
                    fromTransferObject = { it.toDomain() },
                    transferObjectFromJwtClaims = { DeferredIssuanceSuccessResponseTO.from(it) },
                )
            } else {
                val responsePayload = response.body<GenericErrorResponseTO>()
                responsePayload.toDeferredCredentialQueryOutcome()
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
                    encryptionSpec.algorithm,
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
