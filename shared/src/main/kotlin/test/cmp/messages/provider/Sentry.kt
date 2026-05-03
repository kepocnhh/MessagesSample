package test.cmp.messages.provider

import test.cmp.messages.entity.CipherMessage
import test.cmp.messages.entity.SentryKey
import java.security.PrivateKey
import java.security.PublicKey

internal interface Sentry {
    fun getPrivateKey(passphrase: String): PrivateKey
    fun toPublicKey(encoded: ByteArray): PublicKey
    fun encrypt(password: String, issuer: PrivateKey): SentryKey
    fun decrypt(password: String, issuer: SentryKey): PrivateKey
    fun encrypt(key: PrivateKey, decrypted: ByteArray, insider: ByteArray): CipherMessage
    fun decrypt(key: PrivateKey, message: CipherMessage, insider: ByteArray): ByteArray
}
