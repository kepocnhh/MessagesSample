package test.cmp.messages.provider

import kotlin.coroutines.CoroutineContext

internal class Contexts(
    val main: CoroutineContext,
    val default: CoroutineContext,
)
