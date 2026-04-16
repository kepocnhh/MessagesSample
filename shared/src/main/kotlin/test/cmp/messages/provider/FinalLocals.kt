package test.cmp.messages.provider

import java.security.PrivateKey
import test.cmp.messages.entity.SentryKey

internal class FinalLocals : Locals {
    override var sk: SentryKey? = null
    override var pk: PrivateKey? = null
}
