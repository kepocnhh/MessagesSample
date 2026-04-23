package test.cmp.messages.entity

import sp.kx.secrets.Argon2Specs
import sp.kx.secrets.GCMSpecs
import java.util.UUID

internal class SentryKey(
    val id: UUID,
    val keySpecs: Argon2Specs,
    val specs: GCMSpecs,
    val encrypted: ByteArray,
)
