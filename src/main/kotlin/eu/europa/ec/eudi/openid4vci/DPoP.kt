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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.dpop.DPoPUtils
import com.nimbusds.oauth2.sdk.id.JWTID
import eu.europa.ec.eudi.openid4vci.internal.JWTClaimsSetSerializer
import eu.europa.ec.eudi.openid4vci.internal.JsonSupport
import eu.europa.ec.eudi.openid4vci.internal.JwtSigner
import eu.europa.ec.eudi.openid4vci.internal.toJoseAlg
import eu.europa.ec.eudi.openid4vci.internal.use
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.put
import java.net.URL
import java.time.Clock
import java.util.*
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory as NimbusDPoPProofFactory
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken as NimbusDPoPAccessToken
import com.nimbusds.openid.connect.sdk.Nonce as NimbusNonce

const val DPoP = "DPoP"

enum class Htm {
    GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE
}

/**
 * Factory class to generate DPoP JWTs to be added as a request header `DPoP` based on spec https://datatracker.ietf.org/doc/rfc9449/
 */
class DPoPJwtFactory(
    val signer: Signer<JWK>,
    private val jtiByteLength: Int = NimbusDPoPProofFactory.MINIMAL_JTI_BYTE_LENGTH,
    private val clock: Clock,
) {

    init {
        require(jtiByteLength > 0) { "jtiByteLength must be greater than zero" }
    }

    suspend fun createDPoPJwt(
        htm: Htm,
        htu: URL,
        accessToken: AccessToken.DPoP? = null,
        nonce: Nonce? = null,
    ): Result<SignedJWT> = runCatchingCancellable {
        val jwtClaimsSet = DPoPUtils.createJWTClaimsSet(
            jti(),
            htm.name,
            htu.toURI(),
            now(),
            accessToken?.let {
                NimbusDPoPAccessToken(it.accessToken)
            },
            nonce?.let { NimbusNonce(it.value) },
        )

        val signedJwt = signer.use { signOperation ->
            JwtSigner(
                serializer = JWTClaimsSetSerializer,
                signOperation = signOperation,
                algorithm = signer.javaAlgorithm.toJoseAlg(),
                customizeHeader = { key -> dpopJwtHeader(key) },
            ).sign(jwtClaimsSet)
        }
        SignedJWT.parse(signedJwt)
    }

    private fun JsonObjectBuilder.dpopJwtHeader(jwk: JWK) {
        put("typ", NimbusDPoPProofFactory.TYPE.type)
        put("jwk", JsonSupport.parseToJsonElement(jwk.toJSONString()))
    }

    private fun now(): Date = Date.from(clock.instant())
    private fun jti(): JWTID = JWTID(jtiByteLength)

    companion object {

        /**
         * Tries to create a [DPoPJwtFactory] given a [dPoPUsage] and the [oauthServerMetadata]
         * of the OAuth 2.0 authorization server.
         *
         * If the Wallet doesn't support DPoP, no factory is created.
         *
         * If the Wallet supports or requires DPoP, a factory is created when:
         *   1. The Authorization Server supports DPoP (indicated by a non-empty array `dpop_signing_alg_values_supported`)
         *   2. The DPoP signer provided by the Wallet uses a signing algorithm supported by the Authorization Server
         *
         * If the Wallet requires DPoP, but the Authorization Server doesn't support it, an error is raised.
         */
        fun createForServer(
            dPoPUsage: DPoPUsage,
            jtiByteLength: Int = NimbusDPoPProofFactory.MINIMAL_JTI_BYTE_LENGTH,
            clock: Clock,
            oauthServerMetadata: CIAuthorizationServerMetadata,
        ): Result<DPoPJwtFactory?> =
            create(dPoPUsage, jtiByteLength, clock, oauthServerMetadata.dPoPJWSAlgs.orEmpty())

        /**
         * Tries to create a [DPoPJwtFactory] given a [dPoPUsage] and the
         * [supportedDPopAlgorithms] of the OAuth 2.0 Authorization Server.
         *
         * If the Wallet doesn't support DPoP, no factory is created.
         *
         * If the Wallet supports or requires DPoP, a factory is created when:
         *   1. The Authorization Server supports DPoP (indicated by a non-empty [supportedDPopAlgorithms])
         *   2. The DPoP signer provided by the Wallet uses a signing algorithm supported by the Authorization Server
         *
         * If the Wallet requires DPoP, but the Authorization Server doesn't support it, an error is raised.
         */
        fun create(
            dPoPUsage: DPoPUsage,
            jtiByteLength: Int = NimbusDPoPProofFactory.MINIMAL_JTI_BYTE_LENGTH,
            clock: Clock,
            supportedDPopAlgorithms: List<JWSAlgorithm>,
        ): Result<DPoPJwtFactory?> = runCatching {
            when (dPoPUsage) {
                DPoPUsage.Never -> null

                is DPoPUsage.IfSupported -> {
                    val signer = dPoPUsage.dPoPSigner
                    val signerAlg = signer.javaAlgorithm.toJoseAlg()
                    if (supportedDPopAlgorithms.isNotEmpty()) {
                        require(signerAlg in supportedDPopAlgorithms) {
                            "DPoP signer uses $signerAlg which is not dpop_signing_alg_values_supported=  $supportedDPopAlgorithms"
                        }
                        DPoPJwtFactory(signer, jtiByteLength, clock)
                    } else null
                }

                is DPoPUsage.Required -> {
                    require(supportedDPopAlgorithms.isNotEmpty()) {
                        "Wallet requires DPoP but the Authorization Server doesn't support it"
                    }
                    val signer = dPoPUsage.dPoPSigner
                    val signerAlg = signer.javaAlgorithm.toJoseAlg()
                    require(signerAlg in supportedDPopAlgorithms) {
                        "DPoP signer uses $signerAlg which is not dpop_signing_alg_values_supported=  $supportedDPopAlgorithms"
                    }
                    DPoPJwtFactory(signer, jtiByteLength, clock)
                }
            }
        }
    }
}

/**
 * Utility method to be used to set properly the DPoP header on the request under construction, targeted on the URL passed as [htu].
 * Based on the passed [accessToken] DPoP header will be added if it is of type DPoP.
 */
fun HttpRequestBuilder.bearerOrDPoPAuth(
    accessToken: AccessToken,
    dpopJwt: String?,
) {
    when (accessToken) {
        is AccessToken.Bearer -> {
            bearerAuth(accessToken)
        }
        is AccessToken.DPoP -> {
            if (dpopJwt != null) {
                header(DPoP, dpopJwt)
                dpopAuth(accessToken)
            } else {
                bearerAuth(AccessToken.Bearer(accessToken.accessToken, accessToken.expiresIn))
            }
        }
    }
}

private fun HttpRequestBuilder.dpopAuth(accessToken: AccessToken.DPoP) {
    header(HttpHeaders.Authorization, "$DPoP ${accessToken.accessToken}")
}

private fun HttpRequestBuilder.bearerAuth(accessToken: AccessToken.Bearer) {
    bearerAuth(accessToken.accessToken)
}
