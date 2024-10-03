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
import eu.europa.ec.eudi.openid4vci.internal.http.TokenEndpointForm
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

val parPostApplyAssertionsAndGetFormData: HttpRequestData.(expectIssuerState: Boolean) -> FormDataContent = { expectIssuerState ->
    kotlin.test.assertEquals(
        "application/x-www-form-urlencoded; charset=UTF-8",
        body.contentType?.toString(),
        "Wrong content-type, expected application/x-www-form-urlencoded but was ${headers["Content-Type"]}",
    )
    val form = assertIs<FormDataContent>(body, "Not a form post")

    if (!expectIssuerState) {
        assertNull(
            form.formData["issuer_state"],
            "No issuer_state expected when issuance starts from wallet",
        )
    }
    assertNotNull(
        form.formData["code_challenge"],
        "PKCE code challenge was expected but not sent.",
    )
    assertNotNull(
        form.formData["code_challenge_method"],
        "PKCE code challenge method was expected but not sent.",
    )

    form
}

val tokenPostApplyAuthFlowAssertionsAndGetFormData: HttpRequestData.() -> FormDataContent = {
    assertTrue(
        "Wrong content-type, expected application/x-www-form-urlencoded but was ${headers["Content-Type"]}",
    ) {
        body.contentType?.toString() == "application/x-www-form-urlencoded; charset=UTF-8"
    }

    val form = assertIs<FormDataContent>(body, "Not a form post")
    assertNotNull(
        form.formData[TokenEndpointForm.CODE_VERIFIER_PARAM],
        "PKCE code verifier was expected but not sent.",
    )
    assertNotNull(
        form.formData[TokenEndpointForm.AUTHORIZATION_CODE_PARAM],
        "Parameter ${TokenEndpointForm.AUTHORIZATION_CODE_PARAM} was expected but not sent.",
    )
    assertNotNull(
        form.formData[TokenEndpointForm.REDIRECT_URI_PARAM],
        "Parameter ${TokenEndpointForm.REDIRECT_URI_PARAM} was expected but not sent.",
    )
    assertNotNull(
        form.formData[TokenEndpointForm.CLIENT_ID_PARAM],
        "Parameter ${TokenEndpointForm.CLIENT_ID_PARAM} was expected but not sent.",
    )
    val grantType = form.formData[TokenEndpointForm.GRANT_TYPE_PARAM]
    assertNotNull(
        grantType,
        "Parameter ${TokenEndpointForm.GRANT_TYPE_PARAM} was expected but not sent.",
    )
    kotlin.test.assertEquals(
        TokenEndpointForm.AUTHORIZATION_CODE_GRANT,
        grantType,
        "Expected grant_type is ${TokenEndpointForm.AUTHORIZATION_CODE_GRANT} but instead sent $grantType.",
    )
    form
}

val tokenPostApplyPreAuthFlowAssertionsAndGetFormData: HttpRequestData.() -> FormDataContent = {
    assertTrue(
        "Wrong content-type, expected application/x-www-form-urlencoded but was ${headers["Content-Type"]}",
    ) {
        body.contentType?.toString() == "application/x-www-form-urlencoded; charset=UTF-8"
    }
    assertTrue("Not a form post") {
        body is FormDataContent
    }
    val form = body as FormDataContent

    assertTrue("PKCE code verifier was not expected but sent.") {
        form.formData["code_verifier"] == null
    }
    assertTrue("Parameter ${TokenEndpointForm.PRE_AUTHORIZED_CODE_PARAM} was expected but not sent.") {
        form.formData[TokenEndpointForm.PRE_AUTHORIZED_CODE_PARAM] != null
    }
    assertTrue("Parameter ${TokenEndpointForm.TX_CODE_PARAM} was expected but not sent.") {
        form.formData[TokenEndpointForm.TX_CODE_PARAM] != null
    }
    val grantType = form.formData[TokenEndpointForm.GRANT_TYPE_PARAM]
    assertTrue("Parameter ${TokenEndpointForm.GRANT_TYPE_PARAM} was expected but not sent.") {
        grantType != null
    }
    assertTrue(
        "Expected grant_type is ${TokenEndpointForm.PRE_AUTHORIZED_CODE_GRANT} but got $grantType.",
    ) {
        grantType == TokenEndpointForm.PRE_AUTHORIZED_CODE_GRANT
    }
    form
}
