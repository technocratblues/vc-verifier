package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.STATUS_RETRIEVAL_ERROR
import io.mosip.vercred.vcverifier.exception.StatusCheckException
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Downloads a Status List Token (a JWT) from the `uri` in the credential.
 * Spec: draft-ietf-oauth-status-list, section 8.1 and 8.3 (step 2).
 *
 * [allowHttp] is only for tests (MockWebServer). In production the uri must be https.
 */
class StatusListFetcher(
    private val client: OkHttpClient = defaultClient(),
    private val allowHttp: Boolean = false
) {

    fun fetch(uri: String): String {
        val url = uri.toHttpUrlOrNull()
            ?: throw StatusCheckException("Status list uri is not a valid http(s) url", STATUS_RETRIEVAL_ERROR)
        if (!url.isHttps && !allowHttp) {
            throw StatusCheckException("Status list uri must use https", STATUS_RETRIEVAL_ERROR)
        }

        val request = Request.Builder()
            .url(url)
            .header("Accept", STATUS_LIST_JWT)
            .get()
            .build()

        try {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw StatusCheckException(
                        "Status list request failed with HTTP ${response.code}",
                        STATUS_RETRIEVAL_ERROR
                    )
                }

                val contentType = response.body?.contentType()
                if (contentType == null || "${contentType.type}/${contentType.subtype}" != STATUS_LIST_JWT) {
                    throw StatusCheckException(
                        "Status list response must have content type $STATUS_LIST_JWT",
                        STATUS_RETRIEVAL_ERROR
                    )
                }

                // Reads at most MAX_BYTES + 1, so a huge response cannot fill the memory.
                val bytes = response.peekBody(MAX_BYTES + 1).bytes()
                if (bytes.size > MAX_BYTES) {
                    throw StatusCheckException("Status list response is too large", STATUS_RETRIEVAL_ERROR)
                }
                return String(bytes, Charsets.UTF_8).trim()
            }
        } catch (ex: IOException) {
            throw StatusCheckException("Status list could not be downloaded: ${ex.message}", STATUS_RETRIEVAL_ERROR)
        }
    }

    companion object {
        const val STATUS_LIST_JWT = "application/statuslist+jwt"
        private const val MAX_BYTES = 10L * 1024 * 1024

        private fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .callTimeout(15, TimeUnit.SECONDS)
            .followSslRedirects(false) // do not follow a redirect from https to http
            .build()
    }
}