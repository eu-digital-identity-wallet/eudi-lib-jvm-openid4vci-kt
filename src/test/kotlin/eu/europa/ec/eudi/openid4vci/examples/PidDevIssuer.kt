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

private const val BASE_URL = "https://dev.issuer-backend.eudiw.dev"
private val IssuerId = CredentialIssuerId(BASE_URL).getOrThrow()

internal object PidDevIssuer :
    HasIssuerId,
    HasTestUser<KeycloakUser>,
    CanAuthorizeIssuance<KeycloakUser> by Keycloak,
    CanBeUsedWithVciLib,
    CanRequestForCredentialOffer<KeycloakUser> by CanRequestForCredentialOffer.onlyStatelessAuthorizationCode(IssuerId) {

    private const val WALLET_CLIENT_ID = "wallet-dev"

    override val issuerId = IssuerId
    override val testUser = KeycloakUser("tneal", "password")
    override val cfg = OpenId4VCIConfig(
        clientAuthentication = ClientAuthentication.None(WALLET_CLIENT_ID),
        authFlowRedirectionURI = Keycloak.DebugRedirectUri,
        encryptionSupportConfig = EncryptionSupportConfig(Curve.P_256, 2048, CredentialResponseEncryptionPolicy.SUPPORTED),
        authorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
        parUsage = ParUsage.IfSupported,
        dPoPSigner = CryptoGenerator.ecSigner(),
    )

    val PID_SdJwtVC_config_id = CredentialConfigurationIdentifier("eu.europa.ec.eudi.pid_vc_sd_jwt")
    val PID_MsoMdoc_config_id = CredentialConfigurationIdentifier("eu.europa.ec.eudi.pid_mso_mdoc")
    val MDL_config_id = CredentialConfigurationIdentifier("org.iso.18013.5.1.mDL")
    val EHIC_JwsJson_config_id = CredentialConfigurationIdentifier("urn:eudi:ehic:1:dc+sd-jwt-jws-json")
    val EHIC_Compact_config_id = CredentialConfigurationIdentifier("urn:eudi:ehic:1:dc+sd-jwt-compact")
    val LearningCredential_SdJwtVcCompact_Config_Id =
        CredentialConfigurationIdentifier("urn:eu.europa.ec.eudi:learning:credential:1:dc+sd-jwt-compact")

    val AllCredentialConfigurationIds = listOf(
        PID_SdJwtVC_config_id,
        PID_MsoMdoc_config_id,
        MDL_config_id,
        EHIC_JwsJson_config_id,
        EHIC_Compact_config_id,
        LearningCredential_SdJwtVcCompact_Config_Id,
    )
}
