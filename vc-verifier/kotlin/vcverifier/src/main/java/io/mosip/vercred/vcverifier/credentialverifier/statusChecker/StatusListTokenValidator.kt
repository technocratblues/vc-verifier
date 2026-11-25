package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import com.nimbusds.jwt.SignedJWT
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.ENCODED_LIST_MISSING
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.STATUS_VERIFICATION_ERROR
import io.mosip.vercred.vcverifier.exception.StatusCheckException
import java.text.ParseException
import java.util.logging.Logger

/** The useful part of a validated Status List Token. [ttl] is in seconds, null if the issuer did not set it. */
data class StatusList(val bits: Int, val lst: String, val ttl: Long?)

/**
 * Validates a Status List Token (JWT) that was downloaded from the credential's `status.status_list.uri`.
 * Spec: draft-ietf-oauth-status-list, section 5.1 and 8.3 (steps 3 and 4).
 *
 * [verifySignature] is given the whole token and says if the signature is good. Pass the verifier the
 * credential already uses (JwtVerifier or SdJwtVerifier), so the issuer key is found the same way.
 * [nowInSeconds] can be replaced in tests.
 */
class StatusListTokenValidator(
    private val verifySignature: (String) -> Boolean,
    private val nowInSeconds: () -> Long = { System.currentTimeMillis() / 1000 }
) {

    fun validate(token: String, expectedUri: String): StatusList {
        val jwt = try {
            SignedJWT.parse(token)
        } catch (ex: ParseException) {
            throw fail("Status list token is not a valid JWT")
        }

        if (jwt.header.type?.type != STATUS_LIST_JWT_TYPE) {
            throw fail("Status list token header 'typ' must be $STATUS_LIST_JWT_TYPE")
        }

        var failureReason: String? = null
        val signatureOk = try {
            verifySignature(token)
        } catch (ex: Exception) {
            failureReason = ex.message
            false
        }
        if (!signatureOk) {
            logTokenInfo(jwt)
            val reason = failureReason?.let { ": $it" } ?: ""
            throw fail("Status list token signature verification failed$reason")
        }

        val claims = try {
            jwt.jwtClaimsSet
        } catch (ex: ParseException) {
            throw fail("Status list token claims are not valid")
        }

        if (claims.subject != expectedUri) {
            throw fail("Status list token 'sub' does not match the status list uri")
        }
        if (claims.issueTime == null) {
            throw fail("Status list token 'iat' is missing or not valid")
        }
        if (claims.claims.containsKey("exp")) {
            val exp = claims.expirationTime ?: throw fail("Status list token 'exp' is not valid")
            if (exp.time / 1000 <= nowInSeconds()) {
                throw fail("Status list token has expired")
            }
        }

        val ttl = when (val value = claims.getClaim("ttl")) {
            null -> null
            is Int -> value.toLong()
            is Long -> value
            else -> throw fail("Status list token 'ttl' must be an integer")
        }
        if (ttl != null && ttl <= 0) {
            throw fail("Status list token 'ttl' must be positive")
        }

        val statusList = claims.getClaim("status_list") as? Map<*, *>
            ?: throw fail("Status list token 'status_list' is missing")

        val bits = when (val value = statusList["bits"]) {
            is Int -> value
            is Long -> value.toInt()
            else -> throw fail("'bits' must be 1, 2, 4 or 8")
        }
        if (bits !in ALLOWED_BITS) {
            throw fail("'bits' must be 1, 2, 4 or 8")
        }

        val lst = statusList["lst"] as? String
        if (lst.isNullOrEmpty()) {
            throw StatusCheckException("'lst' is missing", ENCODED_LIST_MISSING)
        }

        return StatusList(bits, lst, ttl)
    }

    private fun fail(message: String) = StatusCheckException(message, STATUS_VERIFICATION_ERROR)

    /** Helps to find out why a key could not be found. Logs names only, no signature or certificate content. */
    private fun logTokenInfo(jwt: SignedJWT) {
        try {
            val header = jwt.header
            logger.warning(
                "Status list token: alg=${header.algorithm?.name}, kid=${header.keyID}, " +
                        "headerFields=${header.toJSONObject().keys}, iss=${jwt.jwtClaimsSet.issuer}"
            )
        } catch (ex: Exception) {
            logger.warning("Status list token info could not be read: ${ex.message}")
        }
    }

    private val logger = Logger.getLogger(StatusListTokenValidator::class.java.name)

    companion object {
        const val STATUS_LIST_JWT_TYPE = "statuslist+jwt"
        private val ALLOWED_BITS = setOf(1, 2, 4, 8)
    }
}