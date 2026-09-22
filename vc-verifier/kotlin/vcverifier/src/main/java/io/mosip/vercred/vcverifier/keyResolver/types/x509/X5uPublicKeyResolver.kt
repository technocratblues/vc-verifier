package io.mosip.vercred.vcverifier.keyResolver.types.x509

import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.ByteArrayInputStream
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.util.logging.Logger

class X5uPublicKeyResolver {

    private val logger = Logger.getLogger(X5uPublicKeyResolver::class.java.name)

    fun resolve(uri: String): PublicKey {
        return try {
            val client = OkHttpClient.Builder().build()
            val request = Request.Builder().url(uri).get().build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw PublicKeyNotFoundException("x5u fetch failed with HTTP ${response.code} for $uri")
                }
                val certBytes = response.body?.bytes()
                    ?: throw PublicKeyNotFoundException("x5u response body was empty for $uri")

                val certFactory = CertificateFactory.getInstance("X.509")
                certFactory.generateCertificate(ByteArrayInputStream(certBytes)).publicKey
            }
        } catch (exception: Exception) {
            logger.severe("Error while resolving public key from x5u certificate: ${exception.message}")
            throw PublicKeyNotFoundException(
                "Unable to extract public key from x5u certificate: ${exception.message}"
            )
        }
    }
}