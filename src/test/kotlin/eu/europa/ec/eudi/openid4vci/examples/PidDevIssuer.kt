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
import eu.europa.ec.eudi.openid4vci.*
import java.net.URI

typealias ActingUser = KeycloakUser

internal object PidDevIssuer : CanAuthorizeIssuance<ActingUser> by Keycloak {
    private const val BASE_URL = "https://dev.issuer-backend.eudiw.dev"
    private const val WALLET_CLIENT_ID = "wallet-dev"
    private val WalletRedirectURI = URI.create("urn:ietf:wg:oauth:2.0:oob")
    val IssuerId = CredentialIssuerId(BASE_URL).getOrThrow()
    val TestUser = ActingUser("tneal", "password")

    val PID_SdJwtVC_config_id = CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt")
    val PID_MsoMdoc_config_id = CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_mso_mdoc")
    val MDL_config_id = CredentialConfigurationIdentifier("org.iso.18013.5.1.mDL")

    val AllCredentialConfigurationIds = listOf(
        PID_SdJwtVC_config_id,
        PID_MsoMdoc_config_id,
        MDL_config_id,
    )

    val Cfg = OpenId4VCIConfig(
        clientId = WALLET_CLIENT_ID,
        authFlowRedirectionURI = WalletRedirectURI,
        keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
        credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
        dPoPSigner = CryptoGenerator.ecProofSigner(),
    )
}
