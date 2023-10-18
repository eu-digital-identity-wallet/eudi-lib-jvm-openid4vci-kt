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
package eu.europa.ec.eudi.openid4vci

import eu.europa.ec.eudi.openid4vci.internal.issuance.CredentialRequestTO
import eu.europa.ec.eudi.openid4vci.internal.issuance.DefaultIssuanceRequester
import eu.europa.ec.eudi.openid4vci.internal.issuance.ktor.KtorHttpClientFactory
import eu.europa.ec.eudi.openid4vci.internal.issuance.ktor.KtorIssuanceRequester
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

/**
 * Interface that specifies the interaction with a Credentials Issuer required to handle the issuance of a credential
 */
interface IssuanceRequester {

    val issuerMetadata: CredentialIssuerMetadata

    /**
     * Method that submits a request to credential issuer for the issuance of single credential.
     *
     * @param request The single credential issuance request
     * @return credential issuer's response
     */
    suspend fun placeIssuanceRequest(
        accessToken: IssuanceAccessToken,
        request: CredentialIssuanceRequest.SingleCredential,
    ): Result<IssuanceResponse.Single>

    /**
     * Method that submits a request to credential issuer for the batch issuance of credentials.
     *
     * @param request The batch credential issuance request
     * @return credential issuer's response
     */
    suspend fun placeBatchIssuanceRequest(
        accessToken: IssuanceAccessToken,
        request: CredentialIssuanceRequest.BatchCredentials,
    ): Result<IssuanceResponse.Batch>

    /**
     * Method that submits a request to credential issuer's Deferred Credential Endpoint
     *
     * @param request The deferred credential request
     * @return response from issuer. Can be either positive if credential is issued or errored in case issuance is still pending
     */
    suspend fun placeDeferredCredentialRequest(
        accessToken: IssuanceAccessToken,
        request: DeferredCredentialRequest,
    ): IssuanceResponse.Single

    companion object {
        fun make(
            issuerMetadata: CredentialIssuerMetadata,
            postIssueRequest: HttpPost<CredentialRequestTO, IssuanceResponse.Single, IssuanceResponse.Single>,
        ): IssuanceRequester =
            DefaultIssuanceRequester(
                issuerMetadata = issuerMetadata,
                postIssueRequest = postIssueRequest,
            )
        fun ktor(
            issuerMetadata: CredentialIssuerMetadata,
            coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            httpClientFactory: KtorHttpClientFactory = KtorIssuanceRequester.DefaultFactory,
        ): IssuanceRequester =
            KtorIssuanceRequester(
                issuerMetadata = issuerMetadata,
                coroutineDispatcher = coroutineDispatcher,
                httpClientFactory = httpClientFactory,
            )
    }
}
