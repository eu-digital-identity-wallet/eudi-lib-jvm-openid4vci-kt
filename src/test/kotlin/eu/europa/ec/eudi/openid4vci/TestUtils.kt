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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.ecSigner
import io.ktor.client.*
import io.ktor.client.request.HttpRequestData
import java.net.URI
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

const val CREDENTIAL_ISSUER_PUBLIC_URL = "https://credential-issuer.example.com"
const val PID_SdJwtVC = "eu.europa.ec.eudiw.pid_vc_sd_jwt"
const val PID_MsoMdoc = "eu.europa.ec.eudiw.pid_mso_mdoc"
const val DEGREE_JwtVcJson = "UniversityDegree_jwt_vc_json"
const val MDL_MsoMdoc = "MobileDrivingLicense_msoMdoc"

val CredentialOfferMixedDocTypes_NO_GRANTS = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credential_configuration_ids": ["$PID_SdJwtVC", "$PID_MsoMdoc", "$DEGREE_JwtVcJson"]          
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

val CredentialOfferWithMDLMdoc_NO_GRANTS = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credential_configuration_ids": ["$MDL_MsoMdoc"]
        }
""".trimIndent()

val CredentialOfferMixedDocTypes_PRE_AUTH_GRANT = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credential_configuration_ids": ["$PID_MsoMdoc", "eu.europa.ec.eudiw.pid_vc_sd_jwt"],
          "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
              "pre-authorized_code": "eyJhbGciOiJSU0EtFYUaBy",
              "tx_code": {
                "input_mode": "numeric",
                "length": 4
              }
            }
          }
        }
""".trimIndent()

val CredentialOfferMixedDocTypes_AUTH_GRANT = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credential_configuration_ids": ["eu.europa.ec.eudiw.pid_mso_mdoc", "eu.europa.ec.eudiw.pid_vc_sd_jwt"],
          "grants": {
            "authorization_code": {
              "issuer_state": "eyJhbGciOiJSU0EtFYUaBy"
            }
          }
        }
""".trimIndent()

val OpenId4VCIConfiguration = OpenId4VCIConfig(
    clientAuthentication = ClientAuthentication.None("MyWallet_ClientId"),
    authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
    encryptionSupportConfig = EncryptionSupportConfig(Curve.P_256, 2048, CredentialResponseEncryptionPolicy.SUPPORTED),
)

val OpenId4VCIConfigurationWithDpopSigner = OpenId4VCIConfig(
    clientAuthentication = ClientAuthentication.None("MyWallet_ClientId"),
    dPoPUsage = DPoPUsage.IfSupported(
        object : ProvisionDPoPSigner {
            override val popAlgorithm: JwsAlgorithm = JwsAlgorithm(JWSAlgorithm.ES256.name)
            override suspend fun invoke(authorizationServer: HttpsUrl): Signer<JWK> = ecSigner(Curve.P_256, JWSAlgorithm.ES256)
        },
    ),
    authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
    encryptionSupportConfig = EncryptionSupportConfig(Curve.P_256, 2048, CredentialResponseEncryptionPolicy.SUPPORTED),

)

suspend fun authorizeRequestForCredentialOffer(
    config: OpenId4VCIConfig? = OpenId4VCIConfiguration,
    credentialOfferStr: String,
    responseEncryptionSpecFactory: ResponseEncryptionSpecFactory = ResponseEncryptionSpecFactory.DEFAULT,
    requestEncryptionSpecFactory: RequestEncryptionSpecFactory = RequestEncryptionSpecFactory.DEFAULT,
    httpClient: HttpClient,
): Pair<AuthorizedRequest, Issuer> {
    val issuer = Issuer.make(
        config = config.takeIf { config != null } ?: OpenId4VCIConfiguration,
        credentialOfferUri = "openid-credential-offer://?credential_offer=$credentialOfferStr",
        httpClient = httpClient,
        responseEncryptionSpecFactory = responseEncryptionSpecFactory,
        requestEncryptionSpecFactory = requestEncryptionSpecFactory,
    ).getOrThrow()

    val authorizedRequest =
        with(issuer) {
            val authRequestPrepared = prepareAuthorizationRequest().getOrThrow()
            with(authRequestPrepared) {
                val authorizationCode = AuthorizationCode(UUID.randomUUID().toString())
                val serverState = authRequestPrepared.state
                authorizeWithAuthorizationCode(authorizationCode, serverState).getOrThrow()
            }
        }
    return authorizedRequest to issuer
}

suspend fun preAuthorizeRequestForCredentialOffer(
    config: OpenId4VCIConfig? = OpenId4VCIConfiguration,
    credentialOfferStr: String,
    responseEncryptionSpecFactory: ResponseEncryptionSpecFactory = ResponseEncryptionSpecFactory.DEFAULT,
    httpClient: HttpClient,
    txCode: String = "1234",
): Pair<AuthorizedRequest, Issuer> {
    val issuer = Issuer.make(
        config = config.takeIf { config != null } ?: OpenId4VCIConfiguration,
        credentialOfferUri = "openid-credential-offer://?credential_offer=$credentialOfferStr",
        httpClient = httpClient,
        responseEncryptionSpecFactory = responseEncryptionSpecFactory,
    ).getOrThrow()

    val authorizedRequest = issuer.authorizeWithPreAuthorizationCode(txCode).getOrThrow()

    return authorizedRequest to issuer
}

fun CredentialReusePolicy.effectiveBatchSize(supportedReusePolicies: CredentialReusePolicies): Int? =
    when (this) {
        is CredentialReusePolicy.EUDI -> {
            options
                .filter { it.isSupported(supportedReusePolicies) }
                .firstNotNullOfOrNull { it.batchSize }
        }

        CredentialReusePolicy.None -> null
    }

internal fun HttpRequestData.verifyDPoPProof(dPoPSigningKey: ECKey, dpopNonce: Nonce) {
    val dpopProof = SignedJWT.parse(assertNotNull(headers["DPoP"]))
    val jwtProcessor = DefaultJWTProcessor<SecurityContext>()
        .apply {
            jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(setOf(JOSEObjectType("dpop+jwt")))
            jwsKeySelector = SingleKeyJWSKeySelector(dpopProof.header.algorithm, dPoPSigningKey.toPublicKey())
            jwtClaimsSetVerifier = DefaultJWTClaimsVerifier(
                JWTClaimsSet.Builder()
                    .claim("nonce", dpopNonce.value)
                    .build(),
                setOf("jti", "htm", "htu", "iat", "nonce"),
            )
        }
    jwtProcessor.process(dpopProof, null)
    assertEquals(dPoPSigningKey.toPublicJWK().computeThumbprint(), dpopProof.header.jwk.computeThumbprint())
}
