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

import eu.europa.ec.eudi.openid4vci.AttestationBasedClientAuthenticationSpec
import eu.europa.ec.eudi.openid4vci.Nonce
import eu.europa.ec.eudi.openid4vci.runCatchingCancellable
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.expectSuccess
import io.ktor.client.request.accept
import io.ktor.client.request.post
import io.ktor.http.ContentType
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URL

internal class ChallengeEndpointClient(
    private val challengeEndpoint: URL,
    private val httpClient: HttpClient,
) {
    suspend fun getChallenge(): Result<Nonce> = runCatchingCancellable {
        val challenge = httpClient.post(challengeEndpoint) {
            expectSuccess = true
            accept(ContentType.Application.Json)
        }.body<ChallengeTO>()

        Nonce(challenge.challenge)
    }
}

@Serializable
private data class ChallengeTO(
    @Required @SerialName(AttestationBasedClientAuthenticationSpec.ATTESTATION_CHALLENGE) val challenge: String,
)
