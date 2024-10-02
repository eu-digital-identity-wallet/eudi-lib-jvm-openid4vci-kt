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
package eu.europa.ec.eudi.openid4vci.internal.http

import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail
import com.nimbusds.oauth2.sdk.rar.AuthorizationType
import com.nimbusds.oauth2.sdk.rar.Location
import eu.europa.ec.eudi.openid4vci.CredentialConfigurationIdentifier
import eu.europa.ec.eudi.openid4vci.CredentialIssuerId
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import java.net.URLEncoder

internal const val OPENID_CREDENTIAL = "openid_credential"

internal fun CredentialConfigurationIdentifier.toNimbusAuthDetail(
    includeLocations: Boolean,
    credentialIssuerId: CredentialIssuerId,
): AuthorizationDetail =
    with(AuthorizationDetail.Builder(AuthorizationType(OPENID_CREDENTIAL))) {
        if (includeLocations) {
            val locations = listOf(Location(credentialIssuerId.value.value.toURI()))
            locations(locations)
        }
        field("credential_configuration_id", value)
    }.build()

internal fun List<AuthorizationDetail>.toFormParamString(): String =
    URLEncoder.encode(
        JsonArray(map { it.toJSONObject().toKotlinxJsonObject() }).toString(),
        "UTF-8",
    )

internal fun Map<String, Any?>.toKotlinxJsonObject(): JsonObject {
    val jsonString = JSONObjectUtils.toJSONString(this)
    return Json.decodeFromString(jsonString)
}
