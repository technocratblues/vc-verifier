package io.mosip.vercred.vcverifier.credentialverifier.verifier

import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import testutils.mockHttpResponse
import testutils.readClasspathFile
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import org.junit.jupiter.api.assertThrows
import org.springframework.util.ResourceUtils
import java.net.InetAddress
import java.nio.file.Files
import okio.Buffer


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CwtVerifierTest {

    // x5u test CWTs require a real HTTP listener because X5uPublicKeyResolver fetches certificates directly via OkHttp, bypassing the existing MockK/NetworkManagerClient setup
    private var x5uServer: MockWebServer? = null

    @BeforeAll
    fun setup() {
        mockkObject(NetworkManagerClient.Companion)
        loadMockPublicKeys()
        startX5uCertServer()
    }

    @AfterAll
    fun teardown() {
        x5uServer?.shutdown()
    }

    private fun startX5uCertServer() {
        val certBytes = Files.readAllBytes(
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "cwt_vc/x5u-leaf-cert.der").toPath()
        )
        x5uServer = MockWebServer().apply {
            // x5u test fixtures are signed against http://127.0.0.1:18081, so the server must bind to that fixed port to keep the embedded x5u URI valid.
            start(InetAddress.getByName("127.0.0.1"), 18081)
            enqueue(MockResponse().setResponseCode(200).setBody(Buffer().write(certBytes)))
            // second enqueue for the second test (invalid-x5u-cwt.hex hits the same URL)
            enqueue(MockResponse().setResponseCode(200).setBody(Buffer().write(certBytes)))
        }
    }

    @Test
    fun `should verify valid CWT via x5u COSE header`() {
        val coseHex = readClasspathFile("cwt_vc/valid-x5u-cwt.hex")
            .replace("\\s".toRegex(), "")

        assertTrue(CwtVerifier().verify(coseHex))
    }

    @Test
    fun `should fail when x5u-resolved CWT has wrong signature`() {
        val coseHex = readClasspathFile("cwt_vc/invalid-x5u-cwt.hex")
            .replace("\\s".toRegex(), "")

        assertThrows<SignatureVerificationException> {
            CwtVerifier().verify(coseHex)
        }
    }

    @Test
    fun `should verify valid EC signed CWT`() {
        val coseHex = readClasspathFile("cwt_vc/valid-ec-cwt.hex")
            .replace("\\s".toRegex(), "")

        assertTrue(CwtVerifier().verify(coseHex))
    }

    @Test
    fun `should fail when EC CWT is verified with wrong public key`() {


        val coseHex = readClasspathFile("cwt_vc/invalid-ec-cwt.hex")
            .replace("\\s".toRegex(), "")

        assertThrows<SignatureVerificationException> {
            CwtVerifier().verify(coseHex)
        }

    }


    private fun loadMockPublicKeys() {
        mockHttpResponse("https://221f38cc3ffc.ngrok-free.app/v1/certify/.well-known/jwks.json", readClasspathFile("cwt_vc/public_key/jwksECkey.json"))
        mockHttpResponse("https://9c65dc69fafc.ngrok-free.app/v1/certify/.well-known/jwks.json", readClasspathFile("cwt_vc/public_key/jwksinvalidECkey.json"))
    }
}