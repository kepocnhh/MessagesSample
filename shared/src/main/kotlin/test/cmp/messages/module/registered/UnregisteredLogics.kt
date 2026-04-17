package test.cmp.messages.module.registered

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import sp.kx.logics.Logics
import test.cmp.messages.provider.Providers

internal class UnregisteredLogics(
    private val providers: Providers,
) : Logics(providers.contexts.main) {
    sealed interface Event {
        data object OnRegister : Event
        data object OnEnter : Event
    }

    private val logger = providers.loggers.create("[Unregistered]")
    private val _events = MutableSharedFlow<Event>()
    val events: Flow<Event> = _events.asSharedFlow()
    private val _loading = MutableStateFlow(false)
    val loading = _loading.asStateFlow()

    fun register(passphrase: String, password: String) = launch {
        logger.debug("register")
        _loading.value = true
        withContext(providers.contexts.default) {
            val pk = providers.sentry.getPrivateKey(passphrase = passphrase)
            logger.debug("pk: ${pk.encoded.toHexString()}")
            val sk = providers.sentry.encrypt(password = password, issuer = pk)
            logger.debug("id: ${sk.id}")
            providers.locals.sk = sk
            providers.locals.pk = pk
        }
        _events.emit(Event.OnRegister)
    }
}
