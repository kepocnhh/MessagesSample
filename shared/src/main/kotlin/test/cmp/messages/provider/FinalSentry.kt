package test.cmp.messages.provider

import java.security.PrivateKey
import javax.crypto.SecretKey
import test.cmp.messages.entity.SentryKey

internal class FinalSentry : Sentry {
    override fun getPrivateKey(passphrase: String): PrivateKey {
        TODO("Sentry:getPrivateKey")
    }

    override fun encrypt(
        sk: SecretKey,
        issuer: PrivateKey,
    ): SentryKey {
        TODO("Sentry:encrypt")
    }

    override fun decrypt(
        sk: SecretKey,
        issuer: SentryKey,
    ): PrivateKey {
        TODO("Sentry:decrypt")
    }
}
