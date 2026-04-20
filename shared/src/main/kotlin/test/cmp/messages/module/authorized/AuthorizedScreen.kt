package test.cmp.messages.module.authorized

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
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
                            onSuccess = { time ->
                                logger.debug("on decrypt: $time")
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
        BasicText(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(!isLoading) {
                    logics.receive()
                }
                .padding(16.dp)
                .wrapContentSize(),
            text = "receive",
        )
        val addresses = remember { mutableStateOf("http://10.60.70.221:56934") } // todo
        BasicTextField(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp)
                .background(color = Color.LightGray, shape = RoundedCornerShape(16.dp))
                .padding(horizontal = 16.dp, vertical = 8.dp)
                .wrapContentHeight(),
            value = addresses.value,
            readOnly = isLoading,
            onValueChange = { value ->
                if (value.length < 32) {
                    addresses.value = value
                }
            },
            singleLine = true,
            textStyle = TextStyle(fontFamily = FontFamily.Monospace),
        )
        BasicText(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(!isLoading) {
                    logics.transmit(address = addresses.value)
                }
                .padding(16.dp)
                .wrapContentSize(),
            text = "transmit",
        )
    }
}
