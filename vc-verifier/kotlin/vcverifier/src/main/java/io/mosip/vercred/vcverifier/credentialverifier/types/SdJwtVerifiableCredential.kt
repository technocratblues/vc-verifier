package io.mosip.vercred.vcverifier.credentialverifier.types

import io.mosip.vercred.vcverifier.credentialverifier.VerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.statusChecker.JwtStatusListChecker
import io.mosip.vercred.vcverifier.credentialverifier.statusChecker.SdJwtStatusListSignatureVerifier
import io.mosip.vercred.vcverifier.credentialverifier.validator.SdJwtValidator
import io.mosip.vercred.vcverifier.credentialverifier.verifier.SdJwtVerifier
import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.data.ValidationStatus

class SdJwtVerifiableCredential: VerifiableCredential {
    override fun validate(credential: String): ValidationStatus {
        return validate(credential, validateKeyBindingJwt = false)
    }

    override fun validate(credential: String, validateKeyBindingJwt: Boolean): ValidationStatus {
        return SdJwtValidator().validate(credential, validateKeyBindingJwt)
    }

    override fun verify(credential: String): Boolean {
        return SdJwtVerifier().verify(credential)
    }

    override fun checkStatus(
        credential: String,
        statusPurposes: List<String>?
    ): Map<String, CredentialStatusResult> {
        // The status list token must be signed by the issuer of this credential.
        val checker = JwtStatusListChecker({ statusListToken ->
            SdJwtStatusListSignatureVerifier().verify(statusListToken, credential)
        })
        return checker.getStatuses(credential, statusPurposes)
    }
}