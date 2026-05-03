package test.cmp.messages.entity

import java.util.UUID
import kotlin.time.Duration

internal class CipheredRequest(
    val sessionId: UUID,
    val requestId: UUID,
    val time: Duration,
    val body: ByteArray,
)
