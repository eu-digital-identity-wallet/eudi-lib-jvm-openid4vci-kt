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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.JsonSupport
import eu.europa.ec.eudi.openid4vci.internal.use
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

class WalletProviderProvisionClientAttestation(
    private val httpClient: HttpClient,
    private val url: Url,
) : ProvisionClientAttestation {
    override val algorithm: JwsAlgorithm = JwsAlgorithm(JWSAlgorithm.ES256.name)

    override val popAlgorithm: JwsAlgorithm = JwsAlgorithm(JWSAlgorithm.ES256.name)

    override suspend fun invoke(
        authorizationServer: HttpsUrl,
        preferredClientStatusPeriod: PositiveDuration?,
    ): ProvisionClientAttestation.Provisioned {
        val signer = CryptoGenerator.ecSigner(curve = Curve.P_256, alg = JWSAlgorithm.ES256)
        val jwk = signer.publicKeyMaterial()
        val response = httpClient.post(url) {
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            header(HttpHeaders.Accept, ContentType.Application.Json.toString())
            setBody(
                buildJsonObject {
                    put("jwk", JsonSupport.parseToJsonElement(jwk.toJSONString()))
                    if (null != preferredClientStatusPeriod) {
                        put("preferredClientStatusPeriod", preferredClientStatusPeriod.value.toSeconds())
                    }
                },
            )
        }.body<JsonObject>()
        val clientAttestationJWT = ClientAttestationJWT(checkNotNull(response["walletInstanceAttestation"]).jsonPrimitive.content)
        return ProvisionClientAttestation.Provisioned(clientAttestationJWT, signer)
    }
}

private suspend fun <T : Any> Signer<T>.publicKeyMaterial(): T = use { it.publicMaterial }
