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
package eu.europa.ec.eudi.openid4vci.internal.formats

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.CredentialSupportedDisplayTO
import eu.europa.ec.eudi.openid4vci.internal.LogoObject
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.JsonClassDiscriminator
import java.util.*

/**
 * The metadata of a Credentials that can be issued by a Credential Issuer.
 */
@OptIn(ExperimentalSerializationApi::class)
@kotlinx.serialization.Serializable
@JsonClassDiscriminator("format")
internal sealed interface CredentialSupportedTO {

    val format: String
    val scope: String?
    val cryptographicBindingMethodsSupported: List<String>?
    val cryptographicSuitesSupported: List<String>?
    val proofTypesSupported: List<String>?
    val display: List<CredentialSupportedDisplayTO>?

    fun toDomain(): CredentialSupported
}

/**
 * Utility method to convert a [CredentialSupportedDisplayTO] transfer object to the respective [Display] domain object.
 */
internal fun CredentialSupportedDisplayTO.toDomain(): Display {
    fun LogoObject.toLogo(): Display.Logo =
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

/**
 * Utility method to convert a list of string to a list of [CryptographicBindingMethod].
 */
internal fun List<String>.toCryptographicBindingMethods(): List<CryptographicBindingMethod> =
    map {
        when (it) {
            "jwk" -> CryptographicBindingMethod.JWK
            "cose_key" -> CryptographicBindingMethod.COSE
            "mso" -> CryptographicBindingMethod.MSO
            else ->
                if (it.startsWith("did")) {
                    CryptographicBindingMethod.DID(it)
                } else {
                    error("Unknown Cryptographic Binding Method '$it'")
                }
        }
    }

/**
 * Utility method to convert a list of string to a list of [ProofType].
 */
internal fun List<String>?.toProofTypes(): List<ProofType> =
    this?.map {
        when (it) {
            "jwt" -> ProofType.JWT
            "cwt" -> ProofType.CWT
            else -> error("Unknown Proof Type '$it'")
        }
    } ?: emptyList<ProofType>()
        .ifEmpty {
            listOf(ProofType.JWT)
        }
