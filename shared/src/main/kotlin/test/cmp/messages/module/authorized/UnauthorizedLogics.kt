package test.cmp.messages.module.authorized

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import sp.kx.bytes.hex
import sp.kx.logics.Logics
import test.cmp.messages.provider.Providers

internal class UnauthorizedLogics(
    private val providers: Providers,
) : Logics(providers.contexts.main) {
    sealed interface Event {
        class OnUnlock(val result: Result<Unit>) : Event
        data object OnExit : Event
    }

    private val logger = providers.loggers.create("[Unauthorized]")
    private val _events = MutableSharedFlow<Event>()
    val events: Flow<Event> = _events.asSharedFlow()
    private val _loading = MutableStateFlow(false)
    val loading = _loading.asStateFlow()

    fun unlock(password: String) = launch {
        logger.debug("unlock")
        _loading.value = true
        val result = withContext(providers.contexts.default) {
            runCatching {
                val sk = providers.locals.sk ?: TODO("no sk!")
                logger.debug("id: ${sk.id}")
                val pk = providers.sentry.decrypt(password = password, issuer = sk)
                logger.debug("pk: ${pk.encoded.hex()}")
                providers.locals.pk = pk
            }
        }
        _events.emit(Event.OnUnlock(result = result))
        _loading.value = false
    }

    fun exit() = launch {
        logger.debug("exit")
        _loading.value = true
        withContext(providers.contexts.default) {
            providers.locals.sk = null
        }
        _events.emit(Event.OnExit)
    }
}
