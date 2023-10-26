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

import java.util.*

fun DisplayObject.toDomain(): Display {
    fun DisplayObject.LogoObject.toLogo(): Display.Logo =
        Display.Logo(
            url?.let { HttpsUrl(it).getOrThrow() },
            alternativeText,
        )

    return Display(
        name,
        locale?.let { Locale.forLanguageTag(it) },
        logo?.toLogo(),
        description,
        backgroundColor,
        textColor,
    )
}

fun List<String>.toCryptographicBindingMethods() =
    this.map {
        when (it) {
            "jwk" -> CryptographicBindingMethod.JWK
            "cose_key" -> CryptographicBindingMethod.COSE
            "mso" -> CryptographicBindingMethod.MSO
            else ->
                if (it.startsWith("did")) {
                    CryptographicBindingMethod.DID(it)
                } else {
                    throw IllegalArgumentException("Unknown Cryptographic Binding Method '$it'")
                }
        }
    }

fun List<String>?.toProofTypes() =
    this?.map {
        when (it) {
            "jwt" -> ProofType.JWT
            "cwt" -> ProofType.CWT
            else -> throw IllegalArgumentException("Unknown Proof Type '$it'")
        }
    } ?: emptyList<ProofType>()
        .ifEmpty {
            listOf(ProofType.JWT)
        }
