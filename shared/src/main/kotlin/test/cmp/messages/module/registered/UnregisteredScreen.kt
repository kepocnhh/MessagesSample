package test.cmp.messages.module.registered

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
internal fun UnregisteredScreen(
    onRegister: () -> Unit,
) {
    val providers = remember { App.providers }
    val logger = remember { providers.loggers.create("[Unregistered]") }
    val logics = App.logics<UnregisteredLogics>()
    val isLoading = logics.loading.collectAsState().value
    val passphrases = remember { mutableStateOf("foo") } // todo
    val passwords = remember { mutableStateOf("bar") } // todo
    LaunchedEffect(Unit) {
        withContext(providers.contexts.default) {
            logics.events.collect { event ->
                when (event) {
                    UnregisteredLogics.Event.OnRegister -> onRegister()
                    UnregisteredLogics.Event.OnEnter -> onRegister() // todo
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
            text = "passphrase",
        )
        BasicTextField(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp)
                .background(color = Color.LightGray, shape = RoundedCornerShape(16.dp))
                .padding(horizontal = 16.dp, vertical = 8.dp)
                .wrapContentHeight(),
            value = passphrases.value,
            readOnly = isLoading,
            onValueChange = { value ->
                if (value.length < 32) {
                    passphrases.value = value
                }
            },
            singleLine = true,
            textStyle = TextStyle(fontFamily = FontFamily.Monospace),
        )
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
        val passphrase = passphrases.value
        val password = passwords.value
        BasicText(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(enabled = passphrase.isNotEmpty() && password.isNotEmpty() && !isLoading) {
                    logics.register(passphrase = passphrase, password = password)
                }
                .padding(16.dp)
                .wrapContentSize(),
            text = "register",
        )
    }
}
