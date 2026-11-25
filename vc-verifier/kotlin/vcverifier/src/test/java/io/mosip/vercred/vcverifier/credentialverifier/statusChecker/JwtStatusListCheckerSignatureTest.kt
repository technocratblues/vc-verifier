package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.mosip.vercred.vcverifier.credentialverifier.verifier.JwtVerifier
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
import java.util.Date

/**
 * Same flow as JwtStatusListCheckerTest, but the status list token is really signed
 * and checked by the real JwtVerifier (public key taken from the 'jwk' header).
 */
class JwtStatusListCheckerSignatureTest {

    private lateinit var server: MockWebServer
    private lateinit var uri: String
    private val fetcher = StatusListFetcher(allowHttp = true) // MockWebServer uses http

    // 2 bit list from the spec: statuses 1,2,0,3,0,1,0,1,1,2,3,3 (idx 0 is status 1 = revoked)
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
    fun `token signed with the key in its header is accepted`() {
        val key = ECKeyGenerator(Curve.P_256).generate()
        server.enqueue(statusListResponse(signedToken(headerKey = key, signingKey = key)))

        val results = JwtStatusListChecker(JwtVerifier()::verify, fetcher).getStatuses(credential(idx = 0))

        // status 1 means revoked. Getting this answer (and no error) means the signature was accepted.
        assertFalse(results.getValue("revocation").isValid)
        assertNull(results.getValue("revocation").error)
        assertTrue(results.getValue("suspension").isValid)
    }

    @Test
    fun `token signed with another key than the one in its header is rejected`() {
        val headerKey = ECKeyGenerator(Curve.P_256).generate()
        val attackerKey = ECKeyGenerator(Curve.P_256).generate()
        server.enqueue(statusListResponse(signedToken(headerKey = headerKey, signingKey = attackerKey)))

        val results = JwtStatusListChecker(JwtVerifier()::verify, fetcher).getStatuses(credential(idx = 0))

        assertEquals(setOf("revocation", "suspension"), results.keys)
        results.values.forEach {
            assertFalse(it.isValid)
            assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, it.error?.errorCode)
        }
    }

    // ---- helpers ----

    private fun statusListResponse(token: String) =
        MockResponse().setBody(token).setHeader("Content-Type", "application/statuslist+jwt")

    /** [headerKey] goes into the 'jwk' header, [signingKey] makes the signature. */
    private fun signedToken(headerKey: ECKey, signingKey: ECKey): String {
        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("statuslist+jwt"))
            .jwk(headerKey.toPublicJWK())
            .build()
        val claims = JWTClaimsSet.Builder()
            .subject(uri)
            .issueTime(Date(System.currentTimeMillis() - 1_000_000))
            .claim("ttl", 43200)
            .claim("status_list", mapOf("bits" to 2, "lst" to lst))
            .build()
        return SignedJWT(header, claims).apply { sign(ECDSASigner(signingKey)) }.serialize()
    }

    /** The checker does not verify the credential itself, so a fake signature is fine here. */
    private fun credential(idx: Long): String {
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val payload = """{"status":{"status_list":{"idx":$idx,"uri":"$uri"}}}"""
        return encoder.encodeToString("""{"alg":"ES256"}""".toByteArray()) + "." +
                encoder.encodeToString(payload.toByteArray()) + "." +
                encoder.encodeToString("sig".toByteArray())
    }
}