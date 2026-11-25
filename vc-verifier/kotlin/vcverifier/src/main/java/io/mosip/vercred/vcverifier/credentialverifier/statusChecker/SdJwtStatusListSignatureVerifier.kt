package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jwt.SignedJWT
import io.mosip.vercred.vcverifier.credentialverifier.verifier.SdJwtVerifier
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import io.mosip.vercred.vcverifier.utils.Util
import io.mosip.vercred.vcverifier.utils.Util.verifyJwt
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import java.security.PublicKey
import java.text.ParseException
import java.util.concurrent.TimeUnit

/**
 * Checks the signature of a Status List Token that belongs to an SD-JWT credential.
 *
 * A list decides revocation, so the key must be tied to the issuer of the credential. In this order:
 * 1. The token header has an 'x5c' certificate: same check as for the credential (SdJwtVerifier).
 * 2. The credential header has an 'x5c' certificate: the token is signed with the same key as the credential.
 * 3. The token 'iss' is an https server that is also the server of the status list uri in the credential
 *    (the credential is signed by the issuer, so the issuer vouches for that server): the key is the one with
 *    the token 'kid' in https://<iss>/.well-known/jwks.json.
 * 4. The key is one of the credential issuer's keys, found with the 'iss' of the CREDENTIAL and the token 'kid'.
 *
 * The 'iss' inside the token alone is never enough to find a key.
 * Spec: draft-ietf-oauth-status-list, section 8.3 (step 4) and the security considerations.
 */
class SdJwtStatusListSignatureVerifier(
    private val sdJwtVerifier: SdJwtVerifier = SdJwtVerifier(),
    private val jwksFetcher: (String) -> String = { url -> downloadJwks(url) }
) {

    fun verify(statusListToken: String, credential: String): Boolean {
        val tokenHeader = JWSObject.parse(statusListToken).header
        val algorithm = tokenHeader.algorithm.name
        val keyId = tokenHeader.keyID

        if (!tokenHeader.x509CertChain.isNullOrEmpty()) {
            return sdJwtVerifier.verify(statusListToken)
        }

        val credentialJwt = parseCredential(credential)
        val failures = mutableListOf<String>()

        // 2. same key as the credential
        val certificateKey = credentialCertificateKey(credentialJwt)
        if (certificateKey != null) {
            if (signedWith(statusListToken, certificateKey, algorithm)) return true
            failures += "not signed with the credential's certificate key"
        }

        // 3. key published by the status list server that the credential points to
        try {
            val serverKey = statusServerKey(statusListToken, credential, keyId)
            if (signedWith(statusListToken, serverKey, algorithm)) return true
            failures += "not signed with the key of the status list server"
        } catch (ex: Exception) {
            failures += "status list server key: ${ex.message}"
        }

        // 4. key of the credential issuer
        try {
            val issuer = credentialJwt.jwtClaimsSet.issuer
                ?: throw IllegalArgumentException("credential has no 'iss' claim")
            val issuerKey = sdJwtVerifier.resolvePublicKeyFromIssuer(issuer, keyId, algorithm)
            if (signedWith(statusListToken, issuerKey, algorithm)) return true
            failures += "not signed with the credential issuer's key"
        } catch (ex: Exception) {
            failures += "issuer key lookup failed: ${ex.message}"
        }

        throw IllegalArgumentException("Status list token could not be verified (${failures.joinToString("; ")})")
    }

    private fun parseCredential(credential: String): SignedJWT =
        try {
            SignedJWT.parse(credential.substringBefore("~"))
        } catch (ex: ParseException) {
            throw IllegalArgumentException("Credential is not a valid JWT")
        }

    /** The key of the first certificate in the credential header, or null if the credential has none. */
    private fun credentialCertificateKey(credentialJwt: SignedJWT): PublicKey? {
        val certBase64 = credentialJwt.header.x509CertChain?.firstOrNull()?.toString() ?: return null
        val certificateBytes = Base64Decoder().decodeFromBase64(certBase64)
        return Util.toX509Certificate(certificateBytes).publicKey
    }

    /**
     * Only if the 'iss' of the token is an https server and the same server as the status list uri
     * of the credential, the key is read from its /.well-known/jwks.json.
     */
    private fun statusServerKey(statusListToken: String, credential: String, keyId: String?): PublicKey {
        val issuer = SignedJWT.parse(statusListToken).jwtClaimsSet.issuer
            ?: throw IllegalArgumentException("token has no 'iss' claim")
        val issuerUrl = issuer.toHttpUrlOrNull()
        if (issuerUrl == null || !issuerUrl.isHttps) {
            throw IllegalArgumentException("token 'iss' is not an https URL")
        }
        val statusUrl = StatusClaimParser.parse(credential)?.uri?.toHttpUrlOrNull()
            ?: throw IllegalArgumentException("credential has no status list uri")
        if (!sameServer(issuerUrl, statusUrl)) {
            throw IllegalArgumentException("token 'iss' is not the server of the status list uri")
        }

        val keys = try {
            JWKSet.parse(jwksFetcher(issuer.trimEnd('/') + "/.well-known/jwks.json")).keys
        } catch (ex: ParseException) {
            throw IllegalArgumentException("keys are not valid JSON Web Key Set")
        }

        val jwk = keys.firstOrNull { keyId != null && it.keyID == keyId }
            ?: keys.singleOrNull().takeIf { keyId == null }
            ?: throw IllegalArgumentException("no key with kid $keyId was found")
        if (jwk.keyUse != null && jwk.keyUse != KeyUse.SIGNATURE) {
            throw IllegalArgumentException("the key is not for signatures")
        }
        return (jwk as? AsymmetricJWK)?.toPublicKey()
            ?: throw IllegalArgumentException("the key is not a public key")
    }

    private fun sameServer(a: HttpUrl, b: HttpUrl) =
        a.scheme == b.scheme && a.host == b.host && a.port == b.port

    private fun signedWith(token: String, key: PublicKey, algorithm: String): Boolean =
        try {
            verifyJwt(token, key, algorithm)
        } catch (ex: Exception) {
            false
        }

    companion object {
        private const val MAX_BYTES = 1L * 1024 * 1024

        private val client: OkHttpClient by lazy {
            OkHttpClient.Builder()
                .callTimeout(15, TimeUnit.SECONDS)
                .followSslRedirects(false) // do not follow a redirect from https to http
                .build()
        }

        /** Downloads a JSON Web Key Set. Only https is accepted by the caller (see statusServerKey). */
        fun downloadJwks(url: String): String {
            val request = Request.Builder().url(url).header("Accept", "application/json").get().build()
            try {
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        throw IllegalArgumentException("keys request failed with HTTP ${response.code}")
                    }
                    val bytes = response.peekBody(MAX_BYTES + 1).bytes()
                    if (bytes.size > MAX_BYTES) {
                        throw IllegalArgumentException("keys response is too large")
                    }
                    return String(bytes, Charsets.UTF_8)
                }
            } catch (ex: IOException) {
                throw IllegalArgumentException("keys could not be downloaded: ${ex.message}")
            }
        }
    }
}