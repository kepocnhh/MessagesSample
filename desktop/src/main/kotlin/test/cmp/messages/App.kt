package test.cmp.messages

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import kotlinx.coroutines.Dispatchers
import sp.kx.logics.Logics
import sp.kx.logics.LogicsFactory
import sp.kx.logics.LogicsProvider
import test.cmp.messages.module.router.RouterScreen
import test.cmp.messages.provider.Contexts
import test.cmp.messages.provider.FinalLocals
import test.cmp.messages.provider.FinalLoggers
import test.cmp.messages.provider.FinalSentry
import test.cmp.messages.provider.Locals
import test.cmp.messages.provider.Loggers
import test.cmp.messages.provider.Providers
import test.cmp.messages.provider.Sentry

internal object App {
    val providers: Providers

    private val _logicsProvider = LogicsProvider(
        factory = object : LogicsFactory {
            override fun <T : Logics> create(type: Class<T>): T {
                return type
                    .getConstructor(Providers::class.java)
                    .newInstance(providers)
            }
        },
    )


    init {
        val contexts = Contexts(
            main = Dispatchers.Main,
            default = Dispatchers.Default,
        )
        val loggers: Loggers = FinalLoggers()
        val locals: Locals = FinalLocals()
        val sentry: Sentry = FinalSentry()
        providers = Providers(
            contexts = contexts,
            loggers = loggers,
            locals = locals,
            sentry = sentry,
        )
    }

    @Composable
    inline fun <reified T : Logics> logics(label: String = T::class.java.name): T {
        val contains = remember { _logicsProvider.contains(label = label, T::class.java) }
        val logics = _logicsProvider.get(label = label, T::class.java)
        DisposableEffect(Unit) {
            onDispose {
                if (!contains) _logicsProvider.remove(label = label, T::class.java)
            }
        }
        return logics
    }
}

fun main() {
    application {
        Window(onCloseRequest = ::exitApplication, title = "MessagesSample") {
            RouterScreen()
        }
    }
}
