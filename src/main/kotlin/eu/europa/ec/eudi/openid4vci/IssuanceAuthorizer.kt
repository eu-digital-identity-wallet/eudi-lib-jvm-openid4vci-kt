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

import eu.europa.ec.eudi.openid4vci.internal.issuance.DefaultIssuanceAuthorizer
import eu.europa.ec.eudi.openid4vci.internal.issuance.KtorHttpClientFactory
import eu.europa.ec.eudi.openid4vci.internal.issuance.KtorIssuanceAuthorizer
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

sealed interface PushedAuthorizationRequestResponse {
    @Serializable
    data class Success(
        @SerialName("request_uri") val requestURI: String,
        @SerialName("expires_in") val expiresIn: Long = 5,
    ) : PushedAuthorizationRequestResponse

    @Serializable
    data class Failure(
        @SerialName("error") val error: String,
        @SerialName("error_description") val errorDescription: String?,
    ) : PushedAuthorizationRequestResponse
}

sealed interface AccessTokenRequestResponse {
    @Serializable
    data class Success(
        @SerialName("access_token") val accessToken: String,
        @SerialName("expires_in") val expiresIn: Long,
        @SerialName("scope") val scope: String,
        // ?? refreshToken, tokenType ??
    ) : AccessTokenRequestResponse

    @Serializable
    data class Failure(
        @SerialName("error") val error: String,
        @SerialName("error_description") val errorDescription: String?,
    ) : AccessTokenRequestResponse
}

interface IssuanceAuthorizer {

    suspend fun submitPushedAuthorizationRequest(
        scopes: List<String>,
        state: String,
        issuerState: String?,
    ): Result<Pair<PKCEVerifier, GetAuthorizationCodeURL>>

    suspend fun requestAccessTokenAuthFlow(
        authorizationCode: String,
        codeVerifier: String,
    ): Result<String>

    suspend fun requestAccessTokenPreAuthFlow(
        preAuthorizedCode: String,
        pin: String,
    ): Result<String>

    companion object {
        fun make(
            authorizationServerMetadata: CIAuthorizationServerMetadata,
            config: WalletOpenId4VCIConfig,
            postPar: HttpFormPost<PushedAuthorizationRequestResponse>,
            getAccessToken: HttpFormPost<AccessTokenRequestResponse>,
        ): IssuanceAuthorizer =
            DefaultIssuanceAuthorizer(
                authorizationServerMetadata = authorizationServerMetadata,
                config = config,
                postPar = postPar,
                getAccessToken = getAccessToken,
            )

        fun ktor(
            authorizationServerMetadata: CIAuthorizationServerMetadata,
            config: WalletOpenId4VCIConfig,
            coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            httpClientFactory: KtorHttpClientFactory = KtorIssuanceAuthorizer.DefaultFactory,
        ): IssuanceAuthorizer =
            KtorIssuanceAuthorizer(
                authorizationServerMetadata = authorizationServerMetadata,
                config = config,
                coroutineDispatcher = coroutineDispatcher,
                httpClientFactory = httpClientFactory,
            )
    }
}
