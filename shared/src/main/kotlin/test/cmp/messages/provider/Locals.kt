package test.cmp.messages.provider

import java.security.PrivateKey
import test.cmp.messages.entity.SentryKey

internal interface Locals {
    var sk: SentryKey?
    var pk: PrivateKey?
}
