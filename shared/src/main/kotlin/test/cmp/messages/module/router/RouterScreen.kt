package test.cmp.messages.module.router

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import test.cmp.messages.App
import test.cmp.messages.module.authorized.AuthorizedScreen
import test.cmp.messages.module.authorized.UnauthorizedScreen
import test.cmp.messages.module.registered.UnregisteredScreen

@Composable
internal fun RouterScreen() {
    val logics = App.logics<RouterLogics>()
    val state = logics.states.collectAsState().value
    LaunchedEffect(Unit) {
        logics.requestState()
    }
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.White),
    ) {
        when (state) {
            RouterLogics.State.Authorized -> {
                AuthorizedScreen(
                    onLock = {
                        logics.requestState()
                    },
                )
            }
            RouterLogics.State.Unauthorized -> {
                UnauthorizedScreen(
                    onUnlock = {
                        logics.requestState()
                    },
                    onExit = {
                        logics.requestState()
                    },
                )
            }
            RouterLogics.State.Unregistered -> {
                UnregisteredScreen(
                    onRegister = {
                        logics.requestState()
                    },
                )
            }
            null -> {
                BasicText(
                    modifier = Modifier
                        .fillMaxWidth()
                        .align(Alignment.Center),
                    text = "loading...",
                )
            }
        }
    }
}
