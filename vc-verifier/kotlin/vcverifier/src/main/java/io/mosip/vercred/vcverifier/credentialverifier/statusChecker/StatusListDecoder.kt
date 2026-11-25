package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.BASE64_DECODE_FAILED
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.GZIP_DECOMPRESS_FAILED
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.INVALID_CREDENTIAL_STATUS
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.INVALID_INDEX
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode.RANGE_ERROR
import io.mosip.vercred.vcverifier.exception.StatusCheckException
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.zip.InflaterInputStream

private const val MAX_DECOMPRESSED_BYTES = 32L * 1024 * 1024

/**
 * Decodes the `lst` of a Token Status List and reads one status from it.
 * Spec: draft-ietf-oauth-status-list, section 4.1 (byte array) and 8.3 (steps 5 and 6).
 */
object StatusListDecoder {

    private val ALLOWED_BITS = setOf(1, 2, 4, 8)

    /** Step 1: base64url text -> compressed bytes -> raw status bytes (zlib inflate). */
    fun decode(lst: String): ByteArray {
        val compressed = try {
            Base64Decoder().decodeFromBase64Url(lst)
        } catch (ex: IllegalArgumentException) {
            throw StatusCheckException("Base64url decoding failed", BASE64_DECODE_FAILED)
        }
        return inflate(compressed)
    }

    /**
     * Step 2: read the status at [idx].
     * Bits inside a byte are packed from the least significant bit (0) to the most significant bit (7).
     */
    fun readStatus(statusList: ByteArray, bits: Int, idx: Long): Int {
        if (bits !in ALLOWED_BITS) {
            throw StatusCheckException("bits must be 1, 2, 4 or 8", INVALID_CREDENTIAL_STATUS)
        }
        if (idx < 0) {
            throw StatusCheckException("idx must not be negative", INVALID_INDEX)
        }
        val bitPosition = idx * bits
        val byteIndex = bitPosition / 8
        if (byteIndex >= statusList.size) {
            throw StatusCheckException("idx is outside the status list", RANGE_ERROR)
        }
        val shift = (bitPosition % 8).toInt()
        val mask = (1 shl bits) - 1
        val byteValue = statusList[byteIndex.toInt()].toInt() and 0xFF
        return (byteValue shr shift) and mask
    }

    private fun inflate(compressed: ByteArray): ByteArray {
        try {
            InflaterInputStream(ByteArrayInputStream(compressed)).use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                var total = 0L
                var read: Int
                while (input.read(buffer).also { read = it } != -1) {
                    total += read
                    if (total > MAX_DECOMPRESSED_BYTES) {
                        throw StatusCheckException(
                            "Status list exceeds the decompressed size limit",
                            GZIP_DECOMPRESS_FAILED
                        )
                    }
                    output.write(buffer, 0, read)
                }
                return output.toByteArray()
            }
        } catch (ex: IOException) {
            throw StatusCheckException("Status list decompression failed", GZIP_DECOMPRESS_FAILED)
        }
    }
}