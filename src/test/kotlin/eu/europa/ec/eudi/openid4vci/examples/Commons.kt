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
package eu.europa.ec.eudi.openid4vci.examples

import com.nimbusds.jose.jwk.Curve
import eu.europa.ec.eudi.openid4vci.CredentialResponseEncryptionPolicy
import eu.europa.ec.eudi.openid4vci.CryptoGenerator
import eu.europa.ec.eudi.openid4vci.KeyGenerationConfig
import eu.europa.ec.eudi.openid4vci.OpenId4VCIConfig
import io.ktor.client.*
import io.ktor.client.engine.apache.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.Json
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.ssl.SSLContextBuilder
import java.net.URI

const val PID_SdJwtVC_config_id = "eu.europa.ec.eudiw.pid_vc_sd_jwt"
const val PID_MsoMdoc_config_id = "eu.europa.ec.eudiw.pid_mso_mdoc"
const val MDL_config_id = "org.iso.18013.5.1.mDL"

internal class ActingUser(
    val username: String,
    val password: String,
)

val DefaultProofSignersMap = mapOf(
    PID_SdJwtVC_config_id to CryptoGenerator.rsaProofSigner(),
    PID_MsoMdoc_config_id to CryptoGenerator.ecProofSigner(),
    MDL_config_id to CryptoGenerator.ecProofSigner(),
)

val DefaultOpenId4VCIConfig = OpenId4VCIConfig(
    clientId = "wallet-dev",
    authFlowRedirectionURI = URI.create("urn:ietf:wg:oauth:2.0:oob"),
    keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
    CredentialResponseEncryptionPolicy.SUPPORTED,
)

internal fun httpClientFactory(): HttpClient = HttpClient(Apache) {
    install(ContentNegotiation) {
        json(
            json = Json { ignoreUnknownKeys = true },
        )
    }
    install(HttpCookies)
    engine {
        customizeClient {
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
