package io.mosip.vercred.vcverifier.keyResolver.types.x509

import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.networkManager.FetchedResource
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.assertThrows
import org.springframework.util.ResourceUtils
import java.net.URI
import java.nio.file.Files

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class X5uPublicKeyResolverTest {

    private val x5u = "https://issuer.example.com/leaf-cert.der"
    private val issuer = URI("https://issuer.example.com")

    // Taken from `openssl x509 -outform DER | openssl dgst -sha256` on x5u-leaf-cert.der, not from the code under test.
    private val leafSha256 = hexToBytes("b6ff8639ed5b86dd9d0ed9b8cc84383ae0598e082d7ba50ea21708c44ca5ca21")

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @BeforeAll
    fun setup() {
        mockkObject(NetworkManagerClient.Companion)
        val certBytes = Files.readAllBytes(
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "cwt_vc/x5u-leaf-cert.der").toPath()
        )
        every { NetworkManagerClient.sendHTTPRequestForResource(x5u) } returns FetchedResource("application/pkix-cert", certBytes)
        every { NetworkManagerClient.sendHTTPRequestForResource(urlFor("p7")) } returns
                FetchedResource("application/pkcs7-mime; smime-type=\"certs-only\"", classpathBytes("cwt_vc/x5u-leaf-cert.p7b"))
        every { NetworkManagerClient.sendHTTPRequestForResource(urlFor("cose")) } returns
                FetchedResource("application/cose-x509", classpathBytes("cwt_vc/x5u-leaf-cert.cose"))
        every { NetworkManagerClient.sendHTTPRequestForResource(urlFor("cose-chain")) } returns
                FetchedResource("application/cose-x509; usage=chain", classpathBytes("cwt_vc/x5u-leaf-cert.cose"))
        every { NetworkManagerClient.sendHTTPRequestForResource(urlFor("pem-type")) } returns
                FetchedResource("application/x-pem-file", certBytes)
        every { NetworkManagerClient.sendHTTPRequestForResource(urlFor("no-type")) } returns
                FetchedResource(null, certBytes)
        every { NetworkManagerClient.sendHTTPRequestForResource(urlFor("pem-body")) } returns
                FetchedResource("application/pkix-cert", pemOf(certBytes).toByteArray())
        every { NetworkManagerClient.sendHTTPRequestForResource(urlFor("two-certs")) } returns
                FetchedResource("application/cose-x509", classpathBytes("cwt_vc/x5u-leaf-cert.cose") + classpathBytes("cwt_vc/x5u-leaf-cert.cose"))
    }

    private fun urlFor(name: String) = "https://issuer.example.com/$name"

    private fun classpathBytes(path: String): ByteArray =
        Files.readAllBytes(ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + path).toPath())

    private fun pemOf(der: ByteArray): String =
        "-----BEGIN CERTIFICATE-----\n" + java.util.Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der) +
                "\n-----END CERTIFICATE-----\n"

    @Test
    fun `returns key when x5t matches the fetched cert`() {
        assertNotNull(X5uPublicKeyResolver().resolve(x5u, issuer, X5tHash(-16L, leafSha256)))
    }

    @Test
    fun `accepts text sha-256 algorithm name`() {
        assertNotNull(X5uPublicKeyResolver().resolve(x5u, issuer, X5tHash("sha-256", leafSha256)))
    }

    @Test
    fun `still resolves when no x5t is present`() {
        assertNotNull(X5uPublicKeyResolver().resolve(x5u, issuer))
    }

    @Test
    fun `rejects cert whose hash differs from x5t`() {
        val tampered = leafSha256.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertThrows<PublicKeyNotFoundException> {
            X5uPublicKeyResolver().resolve(x5u, issuer, X5tHash(-16L, tampered))
        }
    }

    @Test
    fun `accepts pkcs7-mime certs-only`() {
        assertNotNull(X5uPublicKeyResolver().resolve(urlFor("p7"), issuer, X5tHash(-16L, leafSha256)))
    }

    @Test
    fun `accepts cose-x509 and cose-x509 with usage chain`() {
        assertNotNull(X5uPublicKeyResolver().resolve(urlFor("cose"), issuer, X5tHash(-16L, leafSha256)))
        assertNotNull(X5uPublicKeyResolver().resolve(urlFor("cose-chain"), issuer, X5tHash(-16L, leafSha256)))
    }

    @Test
    fun `rejects media types outside the RFC 9360 list`() {
        assertThrows<PublicKeyNotFoundException> { X5uPublicKeyResolver().resolve(urlFor("pem-type"), issuer, X5tHash(-16L, leafSha256)) }
        assertThrows<PublicKeyNotFoundException> { X5uPublicKeyResolver().resolve(urlFor("no-type"), issuer, X5tHash(-16L, leafSha256)) }
    }

    @Test
    fun `rejects a PEM body served as pkix-cert`() {
        assertThrows<PublicKeyNotFoundException> { X5uPublicKeyResolver().resolve(urlFor("pem-body"), issuer, X5tHash(-16L, leafSha256)) }
    }

    @Test
    fun `rejects several certificates when there is no x5t to pick one`() {
        assertThrows<PublicKeyNotFoundException> { X5uPublicKeyResolver().resolve(urlFor("two-certs"), issuer) }
        assertNotNull(X5uPublicKeyResolver().resolve(urlFor("two-certs"), issuer, X5tHash(-16L, leafSha256)))
    }

    @Test
    fun `rejects unsupported x5t hash algorithm`() {
        assertThrows<PublicKeyNotFoundException> {
            X5uPublicKeyResolver().resolve(x5u, issuer, X5tHash(-43L, leafSha256))
        }
    }
}