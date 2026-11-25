package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode
import io.mosip.vercred.vcverifier.exception.StatusCheckException
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class StatusListFetcherTest {

    private lateinit var server: MockWebServer
    private val fetcher = StatusListFetcher(allowHttp = true) // MockWebServer uses http

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `returns the token and sends the Accept header`() {
        server.enqueue(statusListResponse("aaa.bbb.ccc\n"))

        val token = fetcher.fetch(server.url("/statuslists/1").toString())

        assertEquals("aaa.bbb.ccc", token)
        assertEquals("application/statuslist+jwt", server.takeRequest().getHeader("Accept"))
    }

    @Test
    fun `non 2xx response is rejected`() {
        server.enqueue(MockResponse().setResponseCode(404))
        assertError { fetcher.fetch(server.url("/statuslists/1").toString()) }
    }

    @Test
    fun `wrong content type is rejected`() {
        server.enqueue(MockResponse().setBody("aaa.bbb.ccc").setHeader("Content-Type", "application/json"))
        assertError { fetcher.fetch(server.url("/statuslists/1").toString()) }
    }

    @Test
    fun `missing content type is rejected`() {
        server.enqueue(MockResponse().setBody("aaa.bbb.ccc"))
        assertError { fetcher.fetch(server.url("/statuslists/1").toString()) }
    }

    @Test
    fun `too large response is rejected`() {
        val tooLarge = "a".repeat(10 * 1024 * 1024 + 1)
        server.enqueue(statusListResponse(tooLarge))
        assertError { fetcher.fetch(server.url("/statuslists/1").toString()) }
    }

    @Test
    fun `http uri is rejected by default`() {
        server.enqueue(statusListResponse("aaa.bbb.ccc"))
        assertError { StatusListFetcher().fetch(server.url("/statuslists/1").toString()) }
    }

    @Test
    fun `text that is not a url is rejected`() {
        assertError { fetcher.fetch("not a url") }
    }

    @Test
    fun `server that is not reachable is rejected`() {
        val url = server.url("/statuslists/1").toString()
        server.shutdown()
        assertError { fetcher.fetch(url) }
    }

    // ---- helpers ----

    private fun statusListResponse(body: String) =
        MockResponse().setBody(body).setHeader("Content-Type", "application/statuslist+jwt")

    private fun assertError(block: () -> Unit) {
        val ex = assertThrows(StatusCheckException::class.java) { block() }
        assertEquals(StatusCheckErrorCode.STATUS_RETRIEVAL_ERROR, ex.errorCode)
    }
}