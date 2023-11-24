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

typealias ClientId = String

/**
 * Configuration object to pass configuration properties to the issuance components.
 *
 * @param clientId  The authorization client's identifier
 * @param authFlowRedirectionURI  Redirect url to be passed as the 'redirect_url' parameter to the authorization request.
 */
data class OpenId4VCIConfig(
    val clientId: ClientId,
    val authFlowRedirectionURI: URI,
    val keyGenerationConfig: KeyGenerationConfig,
)

data class KeyGenerationConfig(
    val ecKeyCurve: Curve,
    val rcaKeySize: Int,
)
