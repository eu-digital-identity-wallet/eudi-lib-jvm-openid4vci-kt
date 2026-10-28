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

@JvmInline
value class AdditionalParameters(
    val params: Map<String, String>,
) {
    init {
        val notAllowedKeys = params.keys.filter { it in FORBIDDEN_KEYS }
        require(notAllowedKeys.isEmpty()) {
            val forbiddenKeys = notAllowedKeys.joinToString(", ")
            "The following parameter are library-managed: $forbiddenKeys"
        }
    }

    private companion object {
        val FORBIDDEN_KEYS =
            setOf(
                "response_type",
                "client_id",
                "redirect_uri",
                "scope",
                "state",
                "code_challenge",
                "request_uri",
                "dpop_jkt",
                "authorization_details",
                "issuer_state",
            )
    }
}
