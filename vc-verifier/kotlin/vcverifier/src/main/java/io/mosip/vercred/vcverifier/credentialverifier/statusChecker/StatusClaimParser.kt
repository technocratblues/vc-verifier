package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import com.nimbusds.jwt.SignedJWT
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.INVALID_CREDENTIAL_STATUS
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.INVALID_INDEX
import io.mosip.vercred.vcverifier.exception.StatusCheckException
import io.mosip.vercred.vcverifier.utils.Util.isValidUri
import java.text.ParseException

/** Where to find the status of a credential: position [idx] in the Status List Token at [uri]. */
data class StatusListReference(val idx: Long, val uri: String)

/**
 * Reads `status.status_list` (`idx` and `uri`) from a JWT or SD-JWT credential.
 * Spec: draft-ietf-oauth-status-list, section 6.2 and 8.3 (step 1).
 */
object StatusClaimParser {
    private const val STATUS = "status"
    private const val STATUS_LIST = "status_list"
    private const val IDX = "idx"
    private const val URI = "uri"

    /** Returns null when the credential has no Token Status List reference. Throws when it is present but wrong. */
    fun parse(credential: String): StatusListReference? {
        val claims = try {
            // For an SD-JWT only the first part (the issuer signed JWT) is needed.
            SignedJWT.parse(credential.substringBefore("~")).jwtClaimsSet.claims
        } catch (ex: ParseException) {
            throw StatusCheckException("Credential is not a valid JWT", INVALID_CREDENTIAL_STATUS)
        }

        val status = claims[STATUS] ?: return null
        val statusObject = status as? Map<*, *>
            ?: throw StatusCheckException("'status' must be a JSON object", INVALID_CREDENTIAL_STATUS)

        val statusList = statusObject[STATUS_LIST] ?: return null
        val reference = statusList as? Map<*, *>
            ?: throw StatusCheckException("'status_list' must be a JSON object", INVALID_CREDENTIAL_STATUS)

        val idx = when (val value = reference[IDX]) {
            is Int -> value.toLong()
            is Long -> value
            else -> throw StatusCheckException("'idx' must be an integer", INVALID_INDEX)
        }
        if (idx < 0) {
            throw StatusCheckException("'idx' must not be negative", INVALID_INDEX)
        }

        val uri = reference[URI] as? String
            ?: throw StatusCheckException("'uri' is missing or not a string", INVALID_CREDENTIAL_STATUS)
        if (!isValidUri(uri)) {
            throw StatusCheckException("'uri' is not a valid URI", INVALID_CREDENTIAL_STATUS)
        }

        return StatusListReference(idx, uri)
    }
}