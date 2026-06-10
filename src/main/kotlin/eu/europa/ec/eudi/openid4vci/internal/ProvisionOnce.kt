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
package eu.europa.ec.eudi.openid4vci.internal

import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.DPoPConfig
import eu.europa.ec.eudi.openid4vci.DPoPJwtFactory
import eu.europa.ec.eudi.openid4vci.HttpsUrl
import eu.europa.ec.eudi.openid4vci.JwsAlgorithm
import eu.europa.ec.eudi.openid4vci.ProvisionDPoPSigner
import eu.europa.ec.eudi.openid4vci.Signer
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.time.Clock

internal class ProvisionOnce<V : Any>(private val provision: suspend () -> V) : suspend () -> V {

    @Volatile
    private var provisioned = false

    private val mutex = Mutex()
    private var value: V? = null

    override suspend fun invoke(): V {
        val value =
            if (!provisioned)
                mutex.withLock {
                    if (!provisioned) {
                        val provisioned = provision()
                        value = provisioned
                        this.provisioned = true
                    }
                    value
                }
            else value
        return checkNotNull(value)
    }
}

internal fun dPoPJwtFactory(
    clock: Clock,
    authorizationServer: HttpsUrl,
    config: DPoPConfig,
): ProvisionOnce<DPoPJwtFactory> =
    ProvisionOnce {
        fun ProvisionDPoPSigner.ensureValid(signer: Signer<JWK>) {
            val signerAlgorithm = JwsAlgorithm(signer.javaAlgorithm.toJoseAlg().name)
            check(popAlgorithm == signerAlgorithm) {
                "DPoP Signer algorithm mismatch: expected ${popAlgorithm.name}, got ${signerAlgorithm.name}"
            }
        }

        val provisionDPoPSigner = config.provisionDPoPSigner
        val dPoPSigner = provisionDPoPSigner(authorizationServer)
        provisionDPoPSigner.ensureValid(dPoPSigner)
        DPoPJwtFactory(clock = clock, signer = dPoPSigner)
    }
