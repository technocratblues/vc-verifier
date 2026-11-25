package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode
import io.mosip.vercred.vcverifier.exception.StatusCheckException
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.DeflaterOutputStream

class StatusListDecoderTest {

    // Test vector from the spec, section 4.1 and 4.2 (bits = 1, 16 statuses)
    private val lst1Bit = "eNrbuRgAAhcBXQ"
    private val expected1Bit = listOf(1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1)

    // Test vector from the spec, section 4.1 and 4.2 (bits = 2, 12 statuses)
    private val lst2Bit = "eNo76fITAAPfAgc"
    private val expected2Bit = listOf(1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3)

    @Test
    fun `decode 1 bit list gives the bytes from the spec`() {
        val bytes = StatusListDecoder.decode(lst1Bit)
        assertArrayEquals(byteArrayOf(0xB9.toByte(), 0xA3.toByte()), bytes)
    }

    @Test
    fun `read every status of the 1 bit list`() {
        val bytes = StatusListDecoder.decode(lst1Bit)
        expected1Bit.forEachIndexed { idx, expected ->
            assertEquals(expected, StatusListDecoder.readStatus(bytes, 1, idx.toLong()), "idx $idx")
        }
    }

    @Test
    fun `decode 2 bit list gives the bytes from the spec`() {
        val bytes = StatusListDecoder.decode(lst2Bit)
        assertArrayEquals(byteArrayOf(0xC9.toByte(), 0x44, 0xF9.toByte()), bytes)
    }

    @Test
    fun `read every status of the 2 bit list`() {
        val bytes = StatusListDecoder.decode(lst2Bit)
        expected2Bit.forEachIndexed { idx, expected ->
            assertEquals(expected, StatusListDecoder.readStatus(bytes, 2, idx.toLong()), "idx $idx")
        }
    }

    @Test
    fun `round trip works for 4 bit and 8 bit lists`() {
        val statuses4 = listOf(0, 1, 2, 3, 15, 12, 7, 9, 0, 1)
        val bytes4 = StatusListDecoder.decode(encode(pack(statuses4, 4)))
        statuses4.forEachIndexed { i, s -> assertEquals(s, StatusListDecoder.readStatus(bytes4, 4, i.toLong())) }

        val statuses8 = listOf(0, 1, 2, 3, 255, 128, 77)
        val bytes8 = StatusListDecoder.decode(encode(pack(statuses8, 8)))
        statuses8.forEachIndexed { i, s -> assertEquals(s, StatusListDecoder.readStatus(bytes8, 8, i.toLong())) }
    }

    @Test
    fun `idx outside the list is rejected`() {
        val bytes = StatusListDecoder.decode(lst1Bit) // 2 bytes = indexes 0..15
        assertErrorCode(StatusCheckErrorCode.RANGE_ERROR) { StatusListDecoder.readStatus(bytes, 1, 16) }
    }

    @Test
    fun `negative idx is rejected`() {
        val bytes = StatusListDecoder.decode(lst1Bit)
        assertErrorCode(StatusCheckErrorCode.INVALID_INDEX) { StatusListDecoder.readStatus(bytes, 1, -1) }
    }

    @Test
    fun `bits other than 1, 2, 4, 8 are rejected`() {
        val bytes = StatusListDecoder.decode(lst1Bit)
        assertErrorCode(StatusCheckErrorCode.INVALID_CREDENTIAL_STATUS) { StatusListDecoder.readStatus(bytes, 3, 0) }
    }

    @Test
    fun `bad base64url is rejected`() {
        assertErrorCode(StatusCheckErrorCode.BASE64_DECODE_FAILED) { StatusListDecoder.decode("!!!not-base64!!!") }
    }

    @Test
    fun `data that is not zlib is rejected`() {
        val notZlib = Base64.getUrlEncoder().withoutPadding().encodeToString("hello world".toByteArray())
        assertErrorCode(StatusCheckErrorCode.GZIP_DECOMPRESS_FAILED) { StatusListDecoder.decode(notZlib) }
    }

    // ---- helpers ----

    private fun assertErrorCode(code: StatusCheckErrorCode, block: () -> Unit) {
        val ex = assertThrows(StatusCheckException::class.java) { block() }
        assertEquals(code, ex.errorCode)
    }

    /** Packs statuses into bytes, least significant bit first (same as the spec). */
    private fun pack(statuses: List<Int>, bits: Int): ByteArray {
        val bytes = ByteArray((statuses.size * bits + 7) / 8)
        statuses.forEachIndexed { i, status ->
            val position = i * bits
            bytes[position / 8] = (bytes[position / 8].toInt() or (status shl (position % 8))).toByte()
        }
        return bytes
    }

    /** zlib compress, then base64url without padding. */
    private fun encode(raw: ByteArray): String {
        val out = ByteArrayOutputStream()
        DeflaterOutputStream(out).use { it.write(raw) }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(out.toByteArray())
    }
}