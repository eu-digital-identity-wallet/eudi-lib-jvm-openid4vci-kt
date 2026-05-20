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
import eu.europa.ec.eudi.openid4vci.internal.*
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
    private val jtiByteLength: Int = NimbusDPoPProofFactory.MINIMAL_JTI_BYTE_LENGTH,
    private val clock: Clock,
    private val signer: Signer<JWK>,
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
        operator fun invoke(
            jtiByteLength: Int = NimbusDPoPProofFactory.MINIMAL_JTI_BYTE_LENGTH,
            clock: Clock,
            dPoPCtx: DPoPCtx,
            signer: Signer<JWK>,
        ): DPoPJwtFactory {
            check(dPoPCtx.algorithm.toNimbus() == signer.javaAlgorithm.toJoseAlg())

            return DPoPJwtFactory(
                jtiByteLength = jtiByteLength,
                clock = clock,
                signer = signer,
            )
        }
    }
}

@JvmInline
value class DPoPCtx private constructor(val algorithm: JwsAlgorithm) {
    companion object {
        fun createForServer(
            dPoPUsage: DPoPUsage<JwsAlgorithm>,
            oauthServerMetadata: CIAuthorizationServerMetadata,
        ): Result<DPoPCtx?> =
            create(dPoPUsage, oauthServerMetadata.dPoPJWSAlgs.orEmpty())

        fun create(
            dPoPUsage: DPoPUsage<JwsAlgorithm>,
            supportedDPopAlgorithms: List<JWSAlgorithm>,
        ): Result<DPoPCtx?> = runCatching {
            when (dPoPUsage) {
                DPoPUsage.Never -> null

                is DPoPUsage.IfSupported -> {
                    val signerAlg = dPoPUsage.value.toNimbus()
                    if (supportedDPopAlgorithms.isNotEmpty()) {
                        require(signerAlg in supportedDPopAlgorithms) {
                            "DPoP signer uses $signerAlg which is not dpop_signing_alg_values_supported=  $supportedDPopAlgorithms"
                        }
                        DPoPCtx(dPoPUsage.value)
                    } else null
                }

                is DPoPUsage.Required -> {
                    require(supportedDPopAlgorithms.isNotEmpty()) {
                        "Wallet requires DPoP but the Authorization Server doesn't support it"
                    }
                    val signerAlg = dPoPUsage.value.toNimbus()
                    require(signerAlg in supportedDPopAlgorithms) {
                        "DPoP signer uses $signerAlg which is not dpop_signing_alg_values_supported=  $supportedDPopAlgorithms"
                    }
                    DPoPCtx(dPoPUsage.value)
                }
            }
        }
    }
}

/**
 * Utility method to be used to set properly the DPoP header on the request under construction, targeted on the URL passed as.
 * Based on the passed [accessToken] DPoP header will be added if it is of type DPoP.
 */
internal suspend fun HttpRequestBuilder.bearerOrDPoPAuth(
    accessToken: AccessToken,
    dPoPJwtFactory: DPoPJwtFactory?,
    dPoPNonce: Nonce?,
) {
    when (accessToken) {
        is AccessToken.Bearer -> {
            bearerAuth(accessToken)
        }

        is AccessToken.DPoP -> {
            checkNotNull(dPoPJwtFactory) { "dPoPJwtFactory is required when using DPoP access tokens" }
            val dPoPProof =
                dPoPJwtFactory.createDPoPJwt(method.htm, url.build().toURI().toURL(), accessToken, dPoPNonce)
                    .getOrThrow()
                    .serialize()
            dpopAuth(accessToken)
            header(DPoP, dPoPProof)
        }
    }
}

private val HttpMethod.htm: Htm
    get() = when (this) {
        HttpMethod.Get -> Htm.GET
        HttpMethod.Head -> Htm.HEAD
        HttpMethod.Post -> Htm.POST
        HttpMethod.Put -> Htm.PUT
        HttpMethod.Delete -> Htm.DELETE
        HttpMethod("CONNECT") -> Htm.CONNECT
        HttpMethod.Options -> Htm.OPTIONS
        HttpMethod("TRACE") -> Htm.TRACE
        else -> throw IllegalArgumentException("Unsupported HTTP method: $this")
    }

private fun HttpRequestBuilder.dpopAuth(accessToken: AccessToken.DPoP) {
    header(HttpHeaders.Authorization, "$DPoP ${accessToken.accessToken}")
}

private fun HttpRequestBuilder.bearerAuth(accessToken: AccessToken.Bearer) {
    bearerAuth(accessToken.accessToken)
}
