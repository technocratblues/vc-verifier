package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class TokenStatusMapperTest {

    @Test
    fun `VALID is valid for both purposes`() {
        val results = TokenStatusMapper.toResults(TokenStatusMapper.VALID)
        assertTrue(results.getValue("revocation").isValid)
        assertTrue(results.getValue("suspension").isValid)
    }

    @Test
    fun `INVALID is revoked`() {
        val results = TokenStatusMapper.toResults(TokenStatusMapper.INVALID)
        assertFalse(results.getValue("revocation").isValid)
        assertNull(results.getValue("revocation").error)
        assertTrue(results.getValue("suspension").isValid)
    }

    @Test
    fun `SUSPENDED is suspended`() {
        val results = TokenStatusMapper.toResults(TokenStatusMapper.SUSPENDED)
        assertTrue(results.getValue("revocation").isValid)
        assertFalse(results.getValue("suspension").isValid)
        assertNull(results.getValue("suspension").error)
    }

    @Test
    fun `unknown status value is rejected with an error`() {
        val results = TokenStatusMapper.toResults(3)
        results.values.forEach {
            assertFalse(it.isValid)
            assertNotNull(it.error)
            assertEquals(StatusCheckErrorCode.STATUS_VERIFICATION_ERROR, it.error?.errorCode)
        }
    }

    @Test
    fun `only the asked purposes are returned`() {
        val results = TokenStatusMapper.toResults(TokenStatusMapper.INVALID, listOf("Revocation"))
        assertEquals(setOf("revocation"), results.keys)
    }
}