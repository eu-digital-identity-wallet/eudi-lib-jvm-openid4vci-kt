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

import com.nimbusds.jose.jwk.Curve
import java.net.URI
import java.util.*

const val CREDENTIAL_ISSUER_PUBLIC_URL = "https://credential-issuer.example.com"
const val PID_SdJwtVC = "eu.europa.ec.eudiw.pid_vc_sd_jwt"
const val PID_MsoMdoc = "eu.europa.ec.eudiw.pid_mso_mdoc"

val CREDENTIAL_OFFER_NO_GRANTS = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credential_configuration_ids": ["$PID_SdJwtVC", "$PID_MsoMdoc"]          
        }
""".trimIndent()

val CredentialOfferMsoMdoc_NO_GRANTS = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credential_configuration_ids": ["$PID_MsoMdoc"]          
        }
""".trimIndent()

val CredentialOfferWithSdJwtVc_NO_GRANTS = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credential_configuration_ids": ["$PID_SdJwtVC"]          
        }
""".trimIndent()

val OpenId4VCIConfiguration = OpenId4VCIConfig(
    clientId = "MyWallet_ClientId",
    authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
    keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
)

suspend fun authorizeRequestForCredentialOffer(
    ktorHttpClientFactory: KtorHttpClientFactory,
    credentialOfferStr: String,
    config: OpenId4VCIConfig? = OpenId4VCIConfiguration,
    responseEncryptionSpecFactory: ResponseEncryptionSpecFactory? = null,
): Triple<CredentialOffer, AuthorizedRequest, Issuer> {
    val offer = CredentialOfferRequestResolver(ktorHttpClientFactory = ktorHttpClientFactory)
        .resolve("https://$CREDENTIAL_ISSUER_PUBLIC_URL/credentialoffer?credential_offer=$credentialOfferStr")
        .getOrThrow()

    val issuer = responseEncryptionSpecFactory?.let {
        Issuer.make(
            config = config.takeIf { config != null } ?: OpenId4VCIConfiguration,
            credentialOffer = offer,
            ktorHttpClientFactory = ktorHttpClientFactory,
            responseEncryptionSpecFactory = responseEncryptionSpecFactory,
        )
    } ?: Issuer.make(
        config = config.takeIf { config != null } ?: OpenId4VCIConfiguration,
        credentialOffer = offer,
        ktorHttpClientFactory = ktorHttpClientFactory,
    )

    val authorizedRequest = with(issuer) {
        val authRequestPrepared = prepareAuthorizationRequest().getOrThrow()
        val authorizationCode = UUID.randomUUID().toString()
        authRequestPrepared.authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode)).getOrThrow()
    }
    return Triple(offer, authorizedRequest, issuer)
}
