package test.cmp.messages.provider

import java.security.PrivateKey
import javax.crypto.SecretKey
import test.cmp.messages.entity.SentryKey

internal interface Sentry {
    fun getPrivateKey(passphrase: String): PrivateKey
    fun encrypt(sk: SecretKey, issuer: PrivateKey): SentryKey
    fun decrypt(sk: SecretKey, issuer: SentryKey): PrivateKey
}
