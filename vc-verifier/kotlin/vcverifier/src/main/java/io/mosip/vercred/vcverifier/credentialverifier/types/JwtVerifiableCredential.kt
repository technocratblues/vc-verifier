package io.mosip.vercred.vcverifier.credentialverifier.types

import io.mosip.vercred.vcverifier.credentialverifier.VerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.statusChecker.JwtStatusListChecker
import io.mosip.vercred.vcverifier.credentialverifier.validator.JwtValidator
import io.mosip.vercred.vcverifier.credentialverifier.verifier.JwtVerifier
import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.data.ValidationStatus

class JwtVerifiableCredential: VerifiableCredential {
    override fun validate(credential: String): ValidationStatus {
        return JwtValidator().validate(credential)
    }

    override fun verify(credential: String): Boolean {
        return JwtVerifier().verify(credential)
    }

    override fun checkStatus(
        credential: String,
        statusPurposes: List<String>?
    ): Map<String, CredentialStatusResult> {
        // The status list token is verified with the same JwtVerifier, so its key is found the same way.
        return JwtStatusListChecker(JwtVerifier()::verify).getStatuses(credential, statusPurposes)
    }
}