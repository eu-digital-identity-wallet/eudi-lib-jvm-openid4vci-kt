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
package eu.europa.ec.eudi.openid4vci

/**
 * Service for refreshing the [AccessToken] and [RefreshAccessToken] of an [AuthorizedRequest].
 */
interface RefreshAccessToken {

    /**
     * Performs a `refresh_token` grant against the Token Endpoint of the Authorization Server to fetch a new Access Token, and Refresh Token.
     */
    suspend fun AuthorizedRequest.refresh(): Result<AuthorizedRequest>

    /**
     * Performs a `refresh_token` grant against the Token Endpoint of the Authorization Server to fetch a new Access Token, and Refresh Token,
     * in case the current Access Token is expired.
     */
    suspend fun AuthorizedRequest.refreshIfNeeded(): Result<AuthorizedRequest>
}
