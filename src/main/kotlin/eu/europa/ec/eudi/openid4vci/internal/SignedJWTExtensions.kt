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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jwt.SignedJWT

internal fun SignedJWT.ensureSignedOrVerified() {
    require(state == JWSObject.State.SIGNED || state == JWSObject.State.VERIFIED) {
        "Provided JWT is not signed"
    }
}

internal fun SignedJWT.ensureSignedWithAllowedAlgorithm(allowedAlgorithms: Set<JWSAlgorithm>) {
    require(header.algorithm in allowedAlgorithms) {
        "Signature algorithm must be one of $allowedAlgorithms"
    }
}

internal inline fun <reified T : Any> SignedJWT.ensureValidClaimsSet(): T =
    jwtClaimsSet.decodeAs<T>().getOrElse { throw IllegalArgumentException("Invalid Claims Set.", it) }

internal fun SignedJWT.ensureSignedNotMAC() {
    ensureSignedOrVerified()
    val alg = requireNotNull(header.algorithm) { "Invalid JWT misses header alg" }
    requireIsNotMAC(alg)
}

internal fun requireIsNotMAC(alg: JWSAlgorithm) =
    require(!alg.isMACSigning()) { "MAC signing algorithm not allowed" }

internal fun JWSAlgorithm.isMACSigning(): Boolean = this in MACSigner.SUPPORTED_ALGORITHMS

internal fun SignedJWT.ensureType(expectedType: JOSEObjectType) {
    require(expectedType == header.type) {
        "Expected SignedJWT `typ` to be '${expectedType.type}', but found '${header.type?.type}' instead"
    }
}
