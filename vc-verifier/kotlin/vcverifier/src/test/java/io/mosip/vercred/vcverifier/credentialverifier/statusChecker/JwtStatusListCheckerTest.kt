package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Base64

class JwtStatusListCheckerTest {

    private lateinit var server: MockWebServer
    private lateinit var uri: String
    private val fetcher = StatusListFetcher(allowHttp = true) // MockWebServer uses http

    // 2 bit list from the spec: statuses 1,2,0,3,0,1,0,1,1,2,3,3 (idx 0 to 11)
    private val lst = "eNo76fITAAPfAgc"

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
        uri = server.url("/statuslists/1").toString()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `status 0 is valid for both purposes`() {
        server.enqueue(statusListResponse(statusListToken()))

        val results = checker().getStatuses(credential(idx = 2))

        assertTrue(results.getValue("revocation").isValid)
        assertTrue(results.getValue("suspension").isValid)
        assertEquals("/statuslists/1", server.takeRequest().path)
    }

    @Test
    fun `status 1 is revoked`() {
        server.enqueue(statusListResponse(statusListToken()))

        val results = checker().getStatuses(credential(idx = 0))

        assertFalse(results.getValue("revocation").isValid)
        assertNull(results.getValue("revocation").error)
        assertTrue(results.getValue("suspension").isValid)
    }

    @Test
    fun `status 2 is suspended`() {
        server.enqueue(statusListResponse(statusListToken()))

        val results = checker().getStatuses(credential(idx = 1))

        assertTrue(results.getValue("revocation").isValid)
        assertFalse(results.getValue("suspension").isValid)
        assertNull(results.getValue("suspension").error)
    }

    @Test
    fun `works for an SD-JWT with disclosures`() {
        server.enqueue(statusListResponse(statusListToken()))

        val results = checker().getStatuses(credential(idx = 0) + "~WyJhIiwiYiJd~")

        assertFalse(results.getValue("revocation").isValid)
    }

    @Test
    fun `only the asked purposes are returned`() {
        server.enqueue(statusListResponse(statusListToken()))

        val results = checker().getStatuses(credential(idx = 0), listOf("revocation"))

        assertEquals(setOf("revocation"), results.keys)
    }

    @Test
    fun `credential without a status claim gives an empty map`() {
        val results = checker().getStatuses(jwt("""{"iss":"https://example.com"}"""))

        assertTrue(results.isEmpty())
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `status value that is not supported is rejected`() {
        server.enqueue(statusListResponse(statusListToken()))

        val results = checker().getStatuses(credential(idx = 3)) // status 3

        assertAllFailed(results, StatusCheckErrorCode.STATUS_VERIFICATION_ERROR)
    }

    @Test
    fun `idx outside the list is rejected`() {
        server.enqueue(statusListResponse(statusListToken()))

        val results = checker().getStatuses(credential(idx = 12))

        assertAllFailed(results, StatusCheckErrorCode.RANGE_ERROR)
    }

    @Test
    fun `bad signature is rejected`() {
        server.enqueue(statusListResponse(statusListToken()))

        val results = checker(signatureOk = false).getStatuses(credential(idx = 2))

        assertAllFailed(results, StatusCheckErrorCode.STATUS_VERIFICATION_ERROR)
    }

    @Test
    fun `sub of the token that does not match the uri is rejected`() {
        server.enqueue(statusListResponse(statusListToken(sub = "https://evil.example.com/statuslists/1")))

        val results = checker().getStatuses(credential(idx = 2))

        assertAllFailed(results, StatusCheckErrorCode.STATUS_VERIFICATION_ERROR)
    }

    @Test
    fun `server error is rejected`() {
        server.enqueue(MockResponse().setResponseCode(500))

        val results = checker().getStatuses(credential(idx = 2))

        assertAllFailed(results, StatusCheckErrorCode.STATUS_RETRIEVAL_ERROR)
    }

    @Test
    fun `malformed status claim is rejected`() {
        val results = checker().getStatuses(jwt("""{"status":{"status_list":{"idx":-1,"uri":"$uri"}}}"""))

        assertAllFailed(results, StatusCheckErrorCode.INVALID_INDEX)
        assertEquals(0, server.requestCount)
    }

    // ---- helpers ----

    private fun checker(signatureOk: Boolean = true) = JwtStatusListChecker({ signatureOk }, fetcher)

    private fun assertAllFailed(results: Map<String, CredentialStatusResult>, code: StatusCheckErrorCode) {
        assertEquals(setOf("revocation", "suspension"), results.keys)
        results.values.forEach {
            assertFalse(it.isValid)
            assertEquals(code, it.error?.errorCode)
        }
    }

    private fun statusListResponse(token: String) =
        MockResponse().setBody(token).setHeader("Content-Type", "application/statuslist+jwt")

    private fun credential(idx: Long) = jwt("""{"status":{"status_list":{"idx":$idx,"uri":"$uri"}}}""")

    private fun statusListToken(sub: String = uri): String {
        val iat = System.currentTimeMillis() / 1000 - 1000
        val header = """{"alg":"ES256","typ":"statuslist+jwt"}"""
        val payload = """{"sub":"$sub","iat":$iat,"ttl":43200,"status_list":{"bits":2,"lst":"$lst"}}"""
        return fakeJwt(header, payload)
    }

    private fun jwt(payloadJson: String) = fakeJwt("""{"alg":"ES256"}""", payloadJson)

    /** A JWT with a fake signature. The signature check is replaced in these tests. */
    private fun fakeJwt(headerJson: String, payloadJson: String): String {
        val encoder = Base64.getUrlEncoder().withoutPadding()
        return encoder.encodeToString(headerJson.toByteArray()) + "." +
                encoder.encodeToString(payloadJson.toByteArray()) + "." +
                encoder.encodeToString("sig".toByteArray())
    }
}