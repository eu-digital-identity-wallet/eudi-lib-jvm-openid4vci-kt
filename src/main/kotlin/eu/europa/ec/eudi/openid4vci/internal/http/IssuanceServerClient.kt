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
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.*
import eu.europa.ec.eudi.openid4vci.internal.*
import eu.europa.ec.eudi.openid4vci.internal.CredentialIssuanceRequest
import eu.europa.ec.eudi.openid4vci.internal.DPoPJwtFactory
import eu.europa.ec.eudi.openid4vci.internal.Htm
import eu.europa.ec.eudi.openid4vci.internal.bearerOrDPoPAuth
import eu.europa.ec.eudi.openid4vci.internal.ensureNotNull
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*

internal class IssuanceServerClient(
    private val issuerMetadata: CredentialIssuerMetadata,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
    private val dPoPJwtFactory: DPoPJwtFactory?,
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
        request: CredentialIssuanceRequest.SingleRequest,
    ): Result<CredentialIssuanceResponse> = runCatching {
        ktorHttpClientFactory().use { client ->
            val url = issuerMetadata.credentialEndpoint.value.value
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
                throw error.toIssuanceError()
            }
        }
    }

    /**
     * Method that submits a request to credential issuer for the batch issuance of credentials.
     *
     * @param accessToken Access token authorizing the request
     * @param request The batch credential issuance request
     * @return credential issuer's response
     */
    suspend fun placeBatchIssuanceRequest(
        accessToken: AccessToken,
        request: CredentialIssuanceRequest.BatchRequest,
    ): Result<CredentialIssuanceResponse> = runCatching {
        ensureNotNull(issuerMetadata.batchCredentialEndpoint) { IssuerDoesNotSupportBatchIssuance }
        ktorHttpClientFactory().use { client ->
            val url = issuerMetadata.batchCredentialEndpoint.value.value
            val response = client.post(url) {
                bearerOrDPoPAuth(dPoPJwtFactory, url, Htm.POST, accessToken)
                contentType(ContentType.Application.Json)
                setBody(BatchCredentialRequestTO.from(request))
            }
            if (response.status.isSuccess()) {
                responsePossiblyEncrypted(
                    response,
                    request.encryption,
                    fromTransferObject = { it.toDomain() },
                    transferObjectFromJwtClaims = { BatchCredentialResponseSuccessTO.from(it) },
                )
            } else {
                val error = response.body<GenericErrorResponseTO>()
                throw error.toIssuanceError()
            }
        }
    }

    /**
     * Method that submits a request to credential issuer's Deferred Credential Endpoint
     *
     * @param accessToken Access token authorizing the request
     * @param deferredCredential The identifier of the Deferred Issuance transaction
     * @return response from issuer. Can be either positive if a credential is issued or error in case issuance is still pending
     */
    suspend fun placeDeferredCredentialRequest(
        accessToken: AccessToken,
        deferredCredential: IssuedCredential.Deferred,
        responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
    ): Result<DeferredCredentialQueryOutcome> = runCatching {
        ensureNotNull(issuerMetadata.deferredCredentialEndpoint) { IssuerDoesNotSupportDeferredIssuance }
        ktorHttpClientFactory().use { client ->
            val url = issuerMetadata.deferredCredentialEndpoint.value.value
            val response = client.post(url) {
                bearerOrDPoPAuth(dPoPJwtFactory, url, Htm.POST, accessToken)
                contentType(ContentType.Application.Json)
                setBody(DeferredRequestTO.from(deferredCredential, responseEncryptionSpec))
            }
            if (response.status.isSuccess()) {
                responsePossiblyEncrypted<DeferredIssuanceSuccessResponseTO, DeferredCredentialQueryOutcome.Issued>(
                    response,
                    null, // Replace with responseEncryptionSpec value as soon VCI spec decide on this
                    fromTransferObject = { it.toDomain() },
                    transferObjectFromJwtClaims = { DeferredIssuanceSuccessResponseTO.from(it) },
                )
            } else {
                val responsePayload = response.body<GenericErrorResponseTO>()
                responsePayload.toDeferredCredentialQueryOutcome()
            }
        }
    }

    suspend fun notifyIssuer(
        accessToken: AccessToken,
        event: CredentialIssuanceEvent,
    ): Result<Unit> = runCatching {
        ensureNotNull(issuerMetadata.notificationEndpoint) { IssuerDoesNotSupportNotifications }
        ktorHttpClientFactory().use { client ->
            val url = issuerMetadata.notificationEndpoint.value.value
            val response = client.post(url) {
                bearerOrDPoPAuth(dPoPJwtFactory, url, Htm.POST, accessToken)
                contentType(ContentType.Application.Json)
                setBody(NotificationTO.from(event))
            }
            if (response.status.isSuccess()) {
                Unit
            } else {
                val errorResponse = response.body<GenericErrorResponseTO>()
                throw NotificationFailed(errorResponse.error)
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
        null -> response.body<ResponseTO>()
        else -> {
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
