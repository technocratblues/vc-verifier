package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Base64

/**
 * Uses the real examples from the spec (draft-ietf-oauth-status-list-21):
 *  - the Referenced Token (SD-JWT) from section 6.2: idx 0, uri https://example.com/statuslists/1
 *  - the Status List Token from section 8.2: bits 1, lst eNrbuRgAAhcBXQ
 *
 * The spec does not publish the public key (kid 12), so the signature check is replaced here.
 * The download is also replaced: a test hook answers for https://example.com/statuslists/1.
 */
class SpecExampleTest {

    private val specUri = "https://example.com/statuslists/1"

    // Section 6.2, the issuer signed part of the SD-JWT (disclosures are not needed for the status)
    private val specCredential =
        "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2Qi" +
                "OiBbIkh2cktYNmZQVjB2OUtfeUNWRkJpTEZIc01heGNEXzExNEVtNlZUOHgxbGci" +
                "XSwgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsICJpYXQiOiAx" +
                "NjgzMDAwMDAwLCAiZXhwIjogMTg4MzAwMDAwMCwgInN1YiI6ICI2YzVjMGE0OS1i" +
                "NTg5LTQzMWQtYmFlNy0yMTkxMjJhOWVjMmMiLCAic3RhdHVzIjogeyJzdGF0dXNf" +
                "bGlzdCI6IHsiaWR4IjogMCwgInVyaSI6ICJodHRwczovL2V4YW1wbGUuY29tL3N0" +
                "YXR1c2xpc3RzLzEifX0sICJfc2RfYWxnIjogInNoYS0yNTYifQ.-kgS-R-Z4DEDl" +
                "qb8kb6381_gHHNatsoF1fcVKZk3M06CrnV8F8k9d2w2V_YAOvgcb0f11FqDFezXB" +
                "XH30d4vcw" + "~"

    // Section 8.2
    private val specStatusListToken =
        "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyIiwidHlwIjoic3RhdHVzbGlzdCtqd3Qi" +
                "fQ.eyJleHAiOjIyOTE3MjAxNzAsImlhdCI6MTY4NjkyMDE3MCwiaXNzIjoiaHR0c" +
                "HM6Ly9leGFtcGxlLmNvbSIsInN0YXR1c19saXN0Ijp7ImJpdHMiOjEsImxzdCI6I" +
                "mVOcmJ1UmdBQWhjQlhRIn0sInN1YiI6Imh0dHBzOi8vZXhhbXBsZS5jb20vc3Rhd" +
                "HVzbGlzdHMvMSIsInR0bCI6NDMyMDB9.2lKUUNG503R9htu4aHAYi7vjmr3sgApb" +
                "foDvPrl65N3URUO1EYqqQl45Jfzd-Av4QzlKa3oVALpLwOEUOq-U_g"

    // Section 4.1: statuses of the 16 entries in the example list
    private val expectedStatuses = listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1)

    /** Answers every request for the spec uri with the spec token, no real network. */
    private val fakeNetwork = OkHttpClient.Builder()
        .addInterceptor { chain ->
            val request = chain.request()
            assertEquals(specUri, request.url.toString())
            assertEquals("application/statuslist+jwt", request.header("Accept"))
            Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body(specStatusListToken.toResponseBody("application/statuslist+jwt".toMediaType()))
                .build()
        }
        .build()

    private val checker = JwtStatusListChecker({ true }, StatusListFetcher(fakeNetwork))

    @Test
    fun `the spec credential is revoked, as the spec list says for idx 0`() {
        val results = checker.getStatuses(specCredential)

        assertFalse(results.getValue("revocation").isValid)
        assertNull(results.getValue("revocation").error)
        assertTrue(results.getValue("suspension").isValid)
    }

    @Test
    fun `every idx of the spec list gives the status the spec shows`() {
        expectedStatuses.forEachIndexed { idx, status ->
            val results = checker.getStatuses(credentialWithIdx(idx.toLong()))

            val revoked = status == 1
            assertEquals(!revoked, results.getValue("revocation").isValid, "idx $idx")
            assertTrue(results.getValue("suspension").isValid, "idx $idx")
        }
    }

    @Test
    fun `idx 16 is outside the spec list and is rejected`() {
        val results = checker.getStatuses(credentialWithIdx(16))

        results.values.forEach {
            assertFalse(it.isValid)
            assertEquals(StatusCheckErrorCode.RANGE_ERROR, it.error?.errorCode)
        }
    }

    // ---- helpers ----

    /** Same status uri as the spec, but another idx. The checker does not verify the credential itself. */
    private fun credentialWithIdx(idx: Long): String {
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val payload = """{"status":{"status_list":{"idx":$idx,"uri":"$specUri"}}}"""
        return encoder.encodeToString("""{"alg":"ES256"}""".toByteArray()) + "." +
                encoder.encodeToString(payload.toByteArray()) + "." +
                encoder.encodeToString("sig".toByteArray())
    }
}