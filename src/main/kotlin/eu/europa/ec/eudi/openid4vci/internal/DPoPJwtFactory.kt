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
package eu.europa.ec.eudi.openid4vci.internal

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.dpop.DPoPUtils
import com.nimbusds.oauth2.sdk.id.JWTID
import com.nimbusds.openid.connect.sdk.Nonce
import eu.europa.ec.eudi.openid4vci.AccessToken
import eu.europa.ec.eudi.openid4vci.BindingKey
import eu.europa.ec.eudi.openid4vci.ProofSigner
import io.ktor.client.request.*
import io.ktor.http.*
import java.net.URI
import java.net.URL
import java.time.Clock
import java.util.*
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory as NimbusDPoPProofFactory
import com.nimbusds.oauth2.sdk.token.AccessToken as NimbusAccessToken
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken as NimbusDPoPAccessToken

internal enum class Htm {
    GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE
}

/**
 * https://datatracker.ietf.org/doc/rfc9449/
 */
internal class DPoPJwtFactory(
    signer: ProofSigner,
    private val jtiByteLength: Int = NimbusDPoPProofFactory.MINIMAL_JTI_BYTE_LENGTH,
    private val clock: Clock,
) {
    init {
        require(jtiByteLength > 0) { "jtiByteLength must be greater than zero" }
    }

    private val delegate: NimbusDPoPProofFactory = createNimbusFactory(signer)

    fun createDPoPJwt(
        htm: Htm,
        htu: URL,
        accessToken: AccessToken.DPoP? = null,
        nonce: String? = null,
    ): Result<SignedJWT> = runCatching {
        delegate.createDPoPJWT(
            jti(),
            htm.name,
            htu.toURI(),
            now(),
            accessToken?.let {
                NimbusDPoPAccessToken(it.accessToken)
            },
            nonce?.let { Nonce(it) },
        )
    }

    private fun now(): Date = Date.from(clock.instant())
    private fun jti(): JWTID = JWTID(jtiByteLength)
}

internal fun HttpRequestBuilder.bearerOrDPoPAuth(
    factory: DPoPJwtFactory?,
    htu: URL,
    htm: Htm,
    accessToken: AccessToken,
) {
    when (accessToken) {
        is AccessToken.Bearer -> {
            bearerAuth(accessToken)
        }

        is AccessToken.DPoP -> {
            if (factory != null) {
                dpop(factory, htu, htm, accessToken, nonce = null)
                dpopAuth(accessToken)
            } else {
                bearerAuth(AccessToken.Bearer(accessToken.accessToken))
            }
        }
    }
}

internal fun HttpRequestBuilder.dpop(
    factory: DPoPJwtFactory,
    htu: URL,
    htm: Htm,
    accessToken: AccessToken.DPoP?,
    nonce: String?,
) {
    val jwt = factory.createDPoPJwt(htm, htu, accessToken, nonce).getOrThrow().serialize()
    header(DPoP, jwt)
}

private fun HttpRequestBuilder.dpopAuth(accessToken: AccessToken.DPoP) {
    header(HttpHeaders.Authorization, "$DPoP ${accessToken.accessToken}")
}

private fun HttpRequestBuilder.bearerAuth(accessToken: AccessToken.Bearer) {
    bearerAuth(accessToken.accessToken)
}

internal const val DPoP = "DPoP"

internal fun createNimbusFactory(signer: ProofSigner): NimbusDPoPProofFactory = object : NimbusDPoPProofFactory {

    private val publicJwk = run {
        val bk = signer.getBindingKey()
        require(bk is BindingKey.Jwk) { "Only JWK binding key is supported" }
        bk.jwk
    }

    @Throws(JOSEException::class)
    override fun createDPoPJWT(
        htm: String?,
        htu: URI?,
    ): SignedJWT = createDPoPJWT(htm, htu, null, null)

    @Throws(JOSEException::class)
    override fun createDPoPJWT(
        htm: String?,
        htu: URI?,
        nonce: Nonce?,
    ): SignedJWT = createDPoPJWT(htm, htu, null, nonce)

    @Throws(JOSEException::class)
    override fun createDPoPJWT(
        htm: String?,
        htu: URI?,
        accessToken: NimbusAccessToken?,
    ): SignedJWT = createDPoPJWT(htm, htu, accessToken, null)

    @Throws(JOSEException::class)
    override fun createDPoPJWT(
        htm: String?,
        htu: URI?,
        accessToken: NimbusAccessToken?,
        nonce: Nonce?,
    ): SignedJWT =
        createDPoPJWT(JWTID(NimbusDPoPProofFactory.MINIMAL_JTI_BYTE_LENGTH), htm, htu, Date(), accessToken, nonce)

    @Deprecated(
        message = "Deprecated in Java",
        replaceWith = ReplaceWith("createDPoPJWT(jti, htm, htu, iat, accessToken, null)"),
    )
    @Throws(JOSEException::class)
    override fun createDPoPJWT(
        jti: JWTID?,
        htm: String?,
        htu: URI?,
        iat: Date?,
        accessToken: NimbusAccessToken?,
    ): SignedJWT = createDPoPJWT(jti, htm, htu, iat, accessToken, null)

    @Throws(JOSEException::class)
    override fun createDPoPJWT(
        jti: JWTID?,
        htm: String?,
        htu: URI?,
        iat: Date?,
        accessToken: NimbusAccessToken?,
        nonce: Nonce?,
    ): SignedJWT {
        val jwsHeader: JWSHeader = JWSHeader.Builder(signer.getAlgorithm())
            .type(NimbusDPoPProofFactory.TYPE)
            .jwk(publicJwk)
            .build()

        val jwtClaimsSet = DPoPUtils.createJWTClaimsSet(jti, htm, htu, iat, accessToken, nonce)
        val signedJWT = SignedJWT(jwsHeader, jwtClaimsSet)
        signedJWT.sign(signer)
        return signedJWT
    }
}
