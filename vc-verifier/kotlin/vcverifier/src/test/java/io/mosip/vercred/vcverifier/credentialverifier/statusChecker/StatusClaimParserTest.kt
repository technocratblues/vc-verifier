package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode
import io.mosip.vercred.vcverifier.exception.StatusCheckException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.util.Base64

class StatusClaimParserTest {

    private val uri = "https://example.com/statuslists/1"

    @Test
    fun `reads idx and uri from a JWT`() {
        val credential = jwt("""{"status":{"status_list":{"idx":5,"uri":"$uri"}}}""")
        assertEquals(StatusListReference(5, uri), StatusClaimParser.parse(credential))
    }

    @Test
    fun `reads idx and uri from an SD-JWT`() {
        val credential = jwt("""{"status":{"status_list":{"idx":0,"uri":"$uri"}}}""") + "~WyJhIiwiYiJd~"
        assertEquals(StatusListReference(0, uri), StatusClaimParser.parse(credential))
    }

    @Test
    fun `big idx is supported`() {
        val credential = jwt("""{"status":{"status_list":{"idx":5000000000,"uri":"$uri"}}}""")
        assertEquals(5_000_000_000L, StatusClaimParser.parse(credential)?.idx)
    }

    @Test
    fun `no status claim gives null`() {
        assertNull(StatusClaimParser.parse(jwt("""{"iss":"https://example.com"}""")))
    }

    @Test
    fun `status without status_list gives null`() {
        assertNull(StatusClaimParser.parse(jwt("""{"status":{"other":{}}}""")))
    }

    @Test
    fun `missing idx is rejected`() {
        assertError(StatusCheckErrorCode.INVALID_INDEX, """{"status":{"status_list":{"uri":"$uri"}}}""")
    }

    @Test
    fun `negative idx is rejected`() {
        assertError(StatusCheckErrorCode.INVALID_INDEX, """{"status":{"status_list":{"idx":-1,"uri":"$uri"}}}""")
    }

    @Test
    fun `idx as text is rejected`() {
        assertError(StatusCheckErrorCode.INVALID_INDEX, """{"status":{"status_list":{"idx":"5","uri":"$uri"}}}""")
    }

    @Test
    fun `missing uri is rejected`() {
        assertError(StatusCheckErrorCode.INVALID_CREDENTIAL_STATUS, """{"status":{"status_list":{"idx":1}}}""")
    }

    @Test
    fun `uri that is not a URI is rejected`() {
        assertError(StatusCheckErrorCode.INVALID_CREDENTIAL_STATUS, """{"status":{"status_list":{"idx":1,"uri":"not a uri"}}}""")
    }

    @Test
    fun `status that is not an object is rejected`() {
        assertError(StatusCheckErrorCode.INVALID_CREDENTIAL_STATUS, """{"status":"revoked"}""")
    }

    @Test
    fun `text that is not a JWT is rejected`() {
        val ex = assertThrows(StatusCheckException::class.java) { StatusClaimParser.parse("not-a-jwt") }
        assertEquals(StatusCheckErrorCode.INVALID_CREDENTIAL_STATUS, ex.errorCode)
    }

    // ---- helpers ----

    private fun assertError(code: StatusCheckErrorCode, payload: String) {
        val ex = assertThrows(StatusCheckException::class.java) { StatusClaimParser.parse(jwt(payload)) }
        assertEquals(code, ex.errorCode)
    }

    /** A JWT with a fake signature. The parser only reads claims, it does not verify. */
    private fun jwt(payloadJson: String): String {
        val encoder = Base64.getUrlEncoder().withoutPadding()
        return encoder.encodeToString("""{"alg":"ES256"}""".toByteArray()) + "." +
                encoder.encodeToString(payloadJson.toByteArray()) + "." +
                encoder.encodeToString("sig".toByteArray())
    }
}