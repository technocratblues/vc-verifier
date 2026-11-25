package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.STATUS_VERIFICATION_ERROR
import io.mosip.vercred.vcverifier.exception.StatusCheckException

/**
 * Turns the status number from the list into the result type the verifier already uses.
 * Same keys as the LDP checker: "revocation" and "suspension".
 * Spec: draft-ietf-oauth-status-list, section 7.1.
 */
object TokenStatusMapper {
    const val VALID = 0
    const val INVALID = 1
    const val SUSPENDED = 2

    const val REVOCATION = "revocation"
    const val SUSPENSION = "suspension"

    fun toResults(status: Int, statusPurposes: List<String>? = null): Map<String, CredentialStatusResult> {
        val ok = CredentialStatusResult(true, null)
        val notOk = CredentialStatusResult(false, null)

        val results = when (status) {
            VALID -> mapOf(REVOCATION to ok, SUSPENSION to ok)
            INVALID -> mapOf(REVOCATION to notOk, SUSPENSION to ok)
            SUSPENDED -> mapOf(REVOCATION to ok, SUSPENSION to notOk)
            else -> {
                // 3 and 12-15 are application specific, the rest is reserved: we cannot judge them, so reject.
                val error = StatusCheckException("Unsupported status value $status", STATUS_VERIFICATION_ERROR)
                val failed = CredentialStatusResult(false, error)
                mapOf(REVOCATION to failed, SUSPENSION to failed)
            }
        }

        if (statusPurposes.isNullOrEmpty()) return results
        val wanted = statusPurposes.map { it.lowercase() }.toSet()
        return results.filterKeys { it in wanted }
    }
}