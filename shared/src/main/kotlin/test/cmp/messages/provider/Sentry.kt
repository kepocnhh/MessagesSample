package test.cmp.messages.provider

import java.security.PrivateKey
import java.security.PublicKey
import test.cmp.messages.entity.CipherMessage
import test.cmp.messages.entity.SentryKey

internal interface Sentry {
    fun getPrivateKey(passphrase: String): PrivateKey
    fun toPublicKey(encoded: ByteArray): PublicKey
    fun encrypt(password: String, issuer: PrivateKey): SentryKey
    fun decrypt(password: String, issuer: SentryKey): PrivateKey
    fun encrypt(key: PrivateKey, decrypted: ByteArray): CipherMessage
    fun decrypt(key: PrivateKey, message: CipherMessage): ByteArray
}
