package test.cmp.messages.module.authorized

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
internal fun UnauthorizedScreen(
    onUnlock: () -> Unit,
    onExit: () -> Unit,
) {
    val providers = remember { App.providers }
    val logger = remember { providers.loggers.create("[Unauthorized]") }
    val logics = App.logics<UnauthorizedLogics>()
    val isLoading = logics.loading.collectAsState().value
    val passwords = remember { mutableStateOf("") }
    LaunchedEffect(Unit) {
        withContext(providers.contexts.default) {
            logics.events.collect { event ->
                when (event) {
                    is UnauthorizedLogics.Event.OnUnlock -> {
                        event.result.fold(
                            onSuccess = {
                                onUnlock()
                            },
                            onFailure = { error ->
                                logger.warning("on unlock error: $error")
                                passwords.value = ""
                            },
                        )
                    }
                    UnauthorizedLogics.Event.OnExit -> onExit()
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
                .padding(horizontal = 16.dp, vertical = 8.dp),
            text = "password",
        )
        BasicTextField(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp)
                .background(color = Color.LightGray, shape = RoundedCornerShape(16.dp))
                .padding(horizontal = 16.dp, vertical = 8.dp)
                .wrapContentHeight(),
            value = passwords.value,
            readOnly = isLoading,
            onValueChange = { value ->
                if (value.length < 32) {
                    passwords.value = value
                }
            },
            singleLine = true,
            textStyle = TextStyle(fontFamily = FontFamily.Monospace),
        )
        val password = passwords.value
        BasicText(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(enabled = password.isNotEmpty() && !isLoading) {
                    logics.unlock(password = password)
                }
                .padding(16.dp)
                .wrapContentSize(),
            text = "unlock",
        )
        BasicText(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(!isLoading) {
                    logics.exit()
                }
                .padding(16.dp)
                .wrapContentSize(),
            text = "exit",
        )
    }
}
