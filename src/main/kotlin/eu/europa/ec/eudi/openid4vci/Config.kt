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

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.Curve
import java.net.URI

typealias ClientId = String

/**
 * Configuration object to pass configuration properties to the issuance components.
 *
 * @param clientId  The authorization client's identifier.
 * @param authFlowRedirectionURI  Redirect url to be passed as the 'redirect_url' parameter to the authorization request.
 * @param keyGenerationConfig   Configuration related to generation of encryption keys and encryption algorithms per algorithm family.
 * @param credentialResponseEncryptionPolicy Wallet's policy for Credential Response encryption
 */
data class OpenId4VCIConfig(
    val clientId: ClientId,
    val authFlowRedirectionURI: URI,
    val keyGenerationConfig: KeyGenerationConfig,
    val credentialResponseEncryptionPolicy: CredentialResponseEncryptionPolicy,
    val authorizeIssuanceConfig: AuthorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
)

/**
 * Wallet's policy concerning Credential Response encryption.
 */
enum class CredentialResponseEncryptionPolicy {

    /**
     * The Wallet requires Credential Responses to be encrypted.
     */
    REQUIRED,

    /**
     * The Wallet supports encrypted Credential Responses,
     * but can accept unencrypted Credential Responses as well.
     */
    SUPPORTED,
}

data class KeyGenerationConfig(
    val ecConfig: EcConfig?,
    val rsaConfig: RsaConfig?,
) {
    companion object {
        operator fun invoke(
            ecKeyCurve: Curve,
            rcaKeySize: Int,
        ): KeyGenerationConfig = KeyGenerationConfig(EcConfig(ecKeyCurve), RsaConfig(rcaKeySize))

        fun ecOnly(
            ecKeyCurve: Curve,
            supportedJWEAlgorithms: List<JWEAlgorithm> = JWEAlgorithm.Family.ECDH_ES.toList(),
        ): KeyGenerationConfig = KeyGenerationConfig(EcConfig(ecKeyCurve, supportedJWEAlgorithms), null)
    }
}

data class RsaConfig(
    val rcaKeySize: Int,
    val supportedJWEAlgorithms: List<JWEAlgorithm> = JWEAlgorithm.Family.RSA.toList(),
) {
    init {
        require(JWEAlgorithm.Family.RSA.containsAll(supportedJWEAlgorithms)) {
            "Provided algorithms that are not part of RSA family"
        }
    }
}

data class EcConfig(
    val ecKeyCurve: Curve,
    val supportedJWEAlgorithms: List<JWEAlgorithm> = JWEAlgorithm.Family.ECDH_ES.toList(),
) {
    init {
        require(JWEAlgorithm.Family.ECDH_ES.containsAll(supportedJWEAlgorithms)) {
            "Provided algorithms that are not part of ECDH_ES family"
        }
    }
}

enum class AuthorizeIssuanceConfig {
    FAVOR_SCOPES,
    AUTHORIZATION_DETAILS,
}
