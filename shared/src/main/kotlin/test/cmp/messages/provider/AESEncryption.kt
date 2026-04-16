package test.cmp.messages.provider

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import test.cmp.messages.entity.CBCSpecs
import test.cmp.messages.entity.GCMSpecs
import test.cmp.messages.entity.Specs

internal interface AESEncryption<T : Specs> {
    fun encrypt(key: SecretKey, decrypted: ByteArray, specs: T): ByteArray
    fun decrypt(key: SecretKey, encrypted: ByteArray, specs: T): ByteArray

    companion object {
        val GCM = object : AESEncryption<GCMSpecs> {
            override fun encrypt(
                key: SecretKey,
                decrypted: ByteArray,
                specs: GCMSpecs,
            ): ByteArray {
                val cipher = Cipher.getInstance("aes/gcm/nopadding")
                cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(specs.tagSize, specs.iv))
                return cipher.doFinal(decrypted)
            }

            override fun decrypt(
                key: SecretKey,
                encrypted: ByteArray,
                specs: GCMSpecs,
            ): ByteArray {
                val cipher = Cipher.getInstance("aes/gcm/nopadding")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(specs.tagSize, specs.iv))
                return cipher.doFinal(encrypted)
            }
        }

        val CBC = object : AESEncryption<CBCSpecs> {
            override fun encrypt(
                key: SecretKey,
                decrypted: ByteArray,
                specs: CBCSpecs,
            ): ByteArray {
                val cipher = Cipher.getInstance("aes/cbc/pkcs5padding")
                cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(specs.iv))
                return cipher.doFinal(decrypted)
            }

            override fun decrypt(
                key: SecretKey,
                encrypted: ByteArray,
                specs: CBCSpecs,
            ): ByteArray {
                val cipher = Cipher.getInstance("aes/cbc/pkcs5padding")
                cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(specs.iv))
                return cipher.doFinal(encrypted)
            }
        }
    }
}
