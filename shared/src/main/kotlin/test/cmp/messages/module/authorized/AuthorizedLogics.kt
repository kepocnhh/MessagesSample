package test.cmp.messages.module.authorized

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import sp.kx.bytes.readLong
import sp.kx.bytes.toByteArray
import sp.kx.logics.Logics
import test.cmp.messages.entity.CipherMessage
import test.cmp.messages.provider.Providers

internal class AuthorizedLogics(
    private val providers: Providers,
) : Logics(providers.contexts.main) {
    sealed interface Event {
        data object OnLock : Event
        class OnEncrypt(val message: CipherMessage) : Event
        class OnDecrypt(val result: Result<Long>) : Event
    }

    private val logger = providers.loggers.create("[Authorized]")
    private val _events = MutableSharedFlow<Event>()
    val events: Flow<Event> = _events.asSharedFlow()
    private val _loading = MutableStateFlow(false)
    val loading = _loading.asStateFlow()

    fun lock() = launch {
        logger.debug("lock")
        _loading.value = true
        withContext(providers.contexts.default) {
            providers.locals.pk = null
        }
        _events.emit(Event.OnLock)
    }

    fun encrypt() = launch {
        logger.debug("encrypt")
        _loading.value = true
        val message = withContext(providers.contexts.default) {
            val pk = providers.locals.pk ?: error("No private key!")
            val time = System.currentTimeMillis()
            logger.debug("time: $time")
            val decrypted = time.toByteArray()
            providers.sentry.encrypt(pk, decrypted = decrypted)
        }
        _loading.value = false
        _events.emit(Event.OnEncrypt(message = message))
    }

    fun decrypt(message: CipherMessage) = launch {
        logger.debug("decrypt")
        _loading.value = true
        val result = withContext(providers.contexts.default) {
            val pk = providers.locals.pk ?: error("No private key!")
            runCatching {
                val decrypted = providers.sentry.decrypt(pk, message = message)
                decrypted.readLong()
            }
        }
        _loading.value = false
        _events.emit(Event.OnDecrypt(result))
    }
}
