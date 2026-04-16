package test.cmp.messages.provider

import java.security.PrivateKey
import test.cmp.messages.entity.SentryKey

internal interface Sentry {
    fun getPrivateKey(passphrase: String): PrivateKey
    fun encrypt(password: String, issuer: PrivateKey): SentryKey
    fun decrypt(password: String, issuer: SentryKey): PrivateKey
}
