package io.mosip.vercred.vcverifier.keyResolver.types.x509

import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import java.io.ByteArrayInputStream
import java.net.URI
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.logging.Logger

class X5uPublicKeyResolver {

    private val logger = Logger.getLogger(X5uPublicKeyResolver::class.java.name)

    // Until trust anchor checks exist, x5u must live on the same host as iss, so a token cannot point at an arbitrary certificate.
    private fun requireSameHostAsIssuer(x5u: String, issuer: URI) {
        val x5uHost = try {
            URI(x5u).host
        } catch (e: Exception) {
            null
        }
        if (x5uHost.isNullOrBlank() || issuer.host.isNullOrBlank() || !x5uHost.equals(issuer.host, ignoreCase = true)) {
            throw PublicKeyNotFoundException("x5u host must match the issuer (iss) host")
        }
    }

    // A plain-http x5u lets anyone on the path swap the certificate, so only https is accepted.
    private fun requireHttps(x5u: String) {
        val scheme = try {
            URI(x5u).scheme
        } catch (e: Exception) {
            null
        }
        if (!"https".equals(scheme, ignoreCase = true)) {
            throw PublicKeyNotFoundException("x5u must be an https URL")
        }
    }
    // The four media types RFC 9360 allows an x5u URI to return. Anything else (like PEM) is refused.
    private fun parseCertificates(contentType: String?, body: ByteArray): List<X509Certificate> {
        val mediaType = contentType?.substringBefore(';')?.trim()?.lowercase()
        val params = contentType.orEmpty().lowercase().replace(Regex("[\\s\"]"), "")
        val factory = CertificateFactory.getInstance("X.509")
        val certs = when {
            mediaType == "application/pkix-cert" -> {
                // pkix-cert is DER; a text/PEM body must not slip through the lenient JDK parser.
                if (body.isEmpty() || body[0] != DER_SEQUENCE_TAG) throw IllegalArgumentException("pkix-cert body is not DER")
                listOf(factory.generateCertificate(ByteArrayInputStream(body)))
            }
            mediaType == "application/pkcs7-mime" && "smime-type=certs-only" in params ->
                factory.generateCertificates(ByteArrayInputStream(body)).toList()
            mediaType == "application/cose-x509" ->
                parseCborByteStrings(body).map { factory.generateCertificate(ByteArrayInputStream(it)) }
            else -> throw IllegalArgumentException("Unsupported x5u media type: $contentType")
        }
        if (certs.isEmpty() || certs.size > MAX_CERTIFICATES) throw IllegalArgumentException("Unexpected number of certificates: ${certs.size}")
        return certs.map { it as X509Certificate }
    }

    // application/cose-x509 is a CBOR sequence of byte strings (RFC 9360 section 4.3), one DER certificate each.
    private fun parseCborByteStrings(data: ByteArray): List<ByteArray> {
        val items = mutableListOf<ByteArray>()
        var i = 0
        while (i < data.size) {
            val head = data[i++].toInt() and 0xFF
            require(head shr 5 == 2) { "cose-x509 item must be a CBOR byte string" }
            val info = head and 0x1F
            val length: Int = when {
                info < 24 -> info
                info in 24..26 -> {
                    val width = 1 shl (info - 24)
                    require(i + width <= data.size) { "Truncated CBOR length" }
                    var value = 0L
                    repeat(width) { value = (value shl 8) or (data[i++].toLong() and 0xFF) }
                    require(value <= data.size) { "CBOR length exceeds input" }
                    value.toInt()
                }
                else -> throw IllegalArgumentException("Unsupported CBOR length encoding")
            }
            require(i + length <= data.size) { "Truncated CBOR byte string" }
            items.add(data.copyOfRange(i, i + length))
            i += length
        }
        return items
    }

    // x5t picks the end-entity certificate out of a bundle. With no x5t only a single certificate is unambiguous.
    private fun selectEndEntity(certs: List<X509Certificate>, x5t: X5tHash?): X509Certificate {
        if (x5t != null) {
            return certs.firstOrNull { X5tCertificateMatcher.matches(it, x5t) }
                ?: throw PublicKeyNotFoundException("x5u certificate does not match the x5t thumbprint")
        }
        if (certs.size != 1) throw PublicKeyNotFoundException("x5u returned several certificates and no x5t to pick one")
        return certs[0]
    }

    fun resolve(uri: String, issuer: URI, x5t: X5tHash? = null): PublicKey {
        requireHttps(uri)
        requireSameHostAsIssuer(uri, issuer)
        val certs = try {
            val resource = NetworkManagerClient.sendHTTPRequestForResource(uri)
            parseCertificates(resource.contentType, resource.body)
        } catch (exception: Exception) {
            logger.severe("Error while resolving public key from x5u certificate: ${exception.message}")
            throw PublicKeyNotFoundException(
                "Unable to extract public key from x5u certificate: ${exception.message}"
            )
        }
        val cert = selectEndEntity(certs, x5t)
        try {
            cert.checkValidity()
        } catch (exception: Exception) {
            throw PublicKeyNotFoundException("x5u certificate is not valid: ${exception.message}")
        }
        return cert.publicKey
    }

    private companion object {
        const val DER_SEQUENCE_TAG: Byte = 0x30
        const val MAX_CERTIFICATES = 10
    }
}