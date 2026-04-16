package test.cmp.messages.module.authorized

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.withContext
import test.cmp.messages.App

@Composable
internal fun AuthorizedScreen(
    onLock: () -> Unit,
) {
    val providers = remember { App.providers }
    val logger = remember { providers.loggers.create("[Authorized]") }
    val logics = App.logics<AuthorizedLogics>()
    val isLoading = logics.loading.collectAsState().value
    LaunchedEffect(Unit) {
        withContext(providers.contexts.default) {
            logics.events.collect { event ->
                when (event) {
                    AuthorizedLogics.Event.OnLock -> onLock()
                    is AuthorizedLogics.Event.OnEncrypt -> {
                        logger.debug("on encrypt: ${event.message.size}")
                        logics.decrypt(message = event.message)
                    }
                    is AuthorizedLogics.Event.OnDecrypt -> {
                        event.result.fold(
                            onSuccess = { body ->
                                logger.debug("on decrypt: ${String(body)}")
                            },
                            onFailure = { error ->
                                logger.warning("on decrypt error: $error")
                            },
                        )
                    }
                }
            }
        }
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.White),
        verticalArrangement = Arrangement.Center,
    ) {
        BasicText(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(!isLoading) {
                    logics.lock()
                }
                .padding(16.dp)
                .wrapContentSize(),
            text = "lock",
        )
    }
}
