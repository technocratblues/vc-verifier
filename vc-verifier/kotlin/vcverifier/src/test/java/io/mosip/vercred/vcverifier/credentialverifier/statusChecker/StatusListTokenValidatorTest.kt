package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode
import io.mosip.vercred.vcverifier.exception.StatusCheckException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.util.Base64

class StatusListTokenValidatorTest {

    private val uri = "https://example.com/statuslists/1"
    private val now = 1_700_000_000L
    private val lst = "eNrbuRgAAhcBXQ"
    private val validator = StatusListTokenValidator({ true }, { now })

    @Test
    fun `valid token gives bits, lst and ttl`() {
        val result = validator.validate(token(), uri)
        assertEquals(StatusList(1, lst, 43200L), result)
    }

    @Test
    fun `token without ttl is valid and ttl is null`() {
        val result = validator.validate(token(ttl = null), uri)
        assertEquals(null, result.ttl)
    }

    @Test
    fun `exp in the future is accepted`() {
        validator.validate(token(exp = (now + 3600).toString()), uri)
    }

    @Test
    fun `expired token is rejected`() {
        assertError { validator.validate(token(exp = (now - 1).toString()), uri) }
    }

    @Test
    fun `exp that is not a number is rejected`() {
        assertError { validator.validate(token(exp = "\"tomorrow\""), uri) }
    }

    @Test
    fun `wrong typ is rejected`() {
        assertError { validator.validate(token(typ = "JWT"), uri) }
    }

    @Test
    fun `missing typ is rejected`() {
        assertError { validator.validate(token(typ = null), uri) }
    }

    @Test
    fun `bad signature is rejected`() {
        assertError { StatusListTokenValidator({ false }, { now }).validate(token(), uri) }
    }

    @Test
    fun `signature check that throws is rejected`() {
        val throwing = StatusListTokenValidator({ throw IllegalArgumentException("no key") }, { now })
        assertError { throwing.validate(token(), uri) }
    }

    @Test
    fun `sub that does not match the uri is rejected`() {
        assertError { validator.validate(token(sub = "https://evil.example.com/statuslists/1"), uri) }
    }

    @Test
    fun `missing sub is rejected`() {
        assertError { validator.validate(token(sub = null), uri) }
    }

    @Test
    fun `missing iat is rejected`() {
        assertError { validator.validate(token(iat = null), uri) }
    }

    @Test
    fun `ttl of zero is rejected`() {
        assertError { validator.validate(token(ttl = "0"), uri) }
    }

    @Test
    fun `ttl that is not a number is rejected`() {
        assertError { validator.validate(token(ttl = "\"soon\""), uri) }
    }

    @Test
    fun `missing status_list is rejected`() {
        assertError { validator.validate(token(statusList = null), uri) }
    }

    @Test
    fun `bits of 3 is rejected`() {
        assertError { validator.validate(token(statusList = """{"bits":3,"lst":"$lst"}"""), uri) }
    }

    @Test
    fun `bits as text is rejected`() {
        assertError { validator.validate(token(statusList = """{"bits":"1","lst":"$lst"}"""), uri) }
    }

    @Test
    fun `missing lst is rejected`() {
        assertError(StatusCheckErrorCode.ENCODED_LIST_MISSING) {
            validator.validate(token(statusList = """{"bits":1}"""), uri)
        }
    }

    @Test
    fun `text that is not a JWT is rejected`() {
        assertError { validator.validate("not-a-jwt", uri) }
    }

    // ---- helpers ----

    private fun assertError(
        code: StatusCheckErrorCode = StatusCheckErrorCode.STATUS_VERIFICATION_ERROR,
        block: () -> Unit
    ) {
        val ex = assertThrows(StatusCheckException::class.java) { block() }
        assertEquals(code, ex.errorCode)
    }

    /** Builds a status list token with a fake signature. A null value leaves that claim or header out. */
    private fun token(
        typ: String? = "statuslist+jwt",
        sub: String? = uri,
        iat: String? = (now - 1000).toString(),
        exp: String? = null,
        ttl: String? = "43200",
        statusList: String? = """{"bits":1,"lst":"$lst"}"""
    ): String {
        val header = listOfNotNull(
            "\"alg\":\"ES256\"",
            typ?.let { "\"typ\":\"$it\"" }
        ).joinToString(",", "{", "}")

        val payload = listOfNotNull(
            sub?.let { "\"sub\":\"$it\"" },
            iat?.let { "\"iat\":$it" },
            exp?.let { "\"exp\":$it" },
            ttl?.let { "\"ttl\":$it" },
            statusList?.let { "\"status_list\":$it" }
        ).joinToString(",", "{", "}")

        val encoder = Base64.getUrlEncoder().withoutPadding()
        return encoder.encodeToString(header.toByteArray()) + "." +
                encoder.encodeToString(payload.toByteArray()) + "." +
                encoder.encodeToString("sig".toByteArray())
    }
}