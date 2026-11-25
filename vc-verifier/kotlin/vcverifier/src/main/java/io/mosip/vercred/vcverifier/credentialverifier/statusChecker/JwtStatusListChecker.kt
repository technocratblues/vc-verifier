package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.exception.StatusCheckException
import java.util.logging.Logger

/**
 * Checks the status of a JWT or SD-JWT credential using a Token Status List.
 * Spec: draft-ietf-oauth-status-list, section 8.3.
 *
 * [verifySignature] checks the signature of the downloaded status list token. Pass the verifier the credential
 * already uses (JwtVerifier or SdJwtVerifier), so the issuer key is found the same way.
 *
 * Result keys are the same as the LDP checker: "revocation" and "suspension".
 */
class JwtStatusListChecker(
    private val verifySignature: (String) -> Boolean,
    private val fetcher: StatusListFetcher = StatusListFetcher()
) {
    private val logger = Logger.getLogger(JwtStatusListChecker::class.java.name)

    /**
     * @param credential the JWT, or the SD-JWT with its "~" parts.
     * @param statusPurposes optional filter, for example ["revocation"]. If null or empty, all purposes are returned.
     * @return an empty map if the credential has no status list reference. If a check fails, every purpose is
     * returned as not valid, with the error.
     */
    fun getStatuses(
        credential: String,
        statusPurposes: List<String>? = null
    ): Map<String, CredentialStatusResult> {
        return try {
            val reference = StatusClaimParser.parse(credential)
            if (reference == null) {
                logger.warning("No status list reference present in the credential")
                return emptyMap()
            }

            val token = fetcher.fetch(reference.uri)
            val statusList = StatusListTokenValidator(verifySignature).validate(token, reference.uri)
            val statusBytes = StatusListDecoder.decode(statusList.lst)
            val status = StatusListDecoder.readStatus(statusBytes, statusList.bits, reference.idx)

            logger.info("Status value at index ${reference.idx}: $status")
            TokenStatusMapper.toResults(status, statusPurposes)
        } catch (exception: StatusCheckException) {
            logger.warning("Status check failed: ${exception.message}")
            failedResults(exception, statusPurposes)
        }
    }

    private fun failedResults(
        exception: StatusCheckException,
        statusPurposes: List<String>?
    ): Map<String, CredentialStatusResult> {
        val purposes = if (statusPurposes.isNullOrEmpty()) {
            listOf(TokenStatusMapper.REVOCATION, TokenStatusMapper.SUSPENSION)
        } else {
            statusPurposes.map { it.lowercase() }
        }
        return purposes.associateWith { CredentialStatusResult(false, exception) }
    }
}