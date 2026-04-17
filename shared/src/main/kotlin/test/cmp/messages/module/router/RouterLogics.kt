package test.cmp.messages.module.router

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import sp.kx.bytes.hex
import sp.kx.logics.Logics
import test.cmp.messages.provider.Providers

internal class RouterLogics(
    private val providers: Providers,
) : Logics(providers.contexts.main) {
    sealed interface State {
        data object Authorized : State
        data object Unauthorized : State
        data object Unregistered : State
    }

    private val logger = providers.loggers.create("[Router]")
    private val _states = MutableStateFlow<State?>(null)
    val states = _states.asStateFlow()

    fun requestState() = launch {
        logger.debug("request state")
        val sk = withContext(providers.contexts.default) {
            providers.locals.sk
        }
        if (sk == null) {
            _states.value = State.Unregistered
        } else {
            logger.debug("id: ${sk.id}")
            val pk = withContext(providers.contexts.default) {
                providers.locals.pk
            }
            if (pk == null) {
                _states.value = State.Unauthorized
            } else {
                logger.debug("pk: ${pk.encoded.hex()}")
                _states.value = State.Authorized
            }
        }
    }
}
