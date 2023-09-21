package eu.europa.ec.eudi.openid4vci

import org.junit.jupiter.api.Assertions
import java.net.URL
import kotlin.test.Test

internal class CredentialIssuerIdTest {

    @Test
    internal fun `Fails with non https URL`() {
        val maybeId = CredentialIssuerId("ftp://issuer")
        Assertions.assertTrue(maybeId.isFailure, "Parsing CredentialIssuerId should have failed")
    }

    @Test
    internal fun `Fails with https URL with fragment`() {
        val maybeId = CredentialIssuerId("ftp://issuer#fragment")
        Assertions.assertTrue(maybeId.isFailure, "Parsing CredentialIssuerId should have failed")
    }

    @Test
    internal fun `Fails with https URL with query parameters`() {
        val maybeId = CredentialIssuerId("ftp://issuer?param1=true&param2=true")
        Assertions.assertTrue(maybeId.isFailure, "Parsing CredentialIssuerId should have failed")
    }

    @Test
    internal fun `Parsing succeeds`() {
        val value = URL("https://issuer")
        val maybeId = CredentialIssuerId(value.toExternalForm())
        Assertions.assertTrue(maybeId.isSuccess, "Parsing CredentialIssuerId should have succeeded")
        Assertions.assertEquals(value, maybeId.getOrThrow().value.value)
    }
}