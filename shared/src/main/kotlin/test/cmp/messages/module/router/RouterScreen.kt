package test.cmp.messages.module.router

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import test.cmp.messages.App

@Composable
internal fun RouterScreen() {
    val logics = App.logics<RouterLogics>()
    val state = logics.states.collectAsState().value
    LaunchedEffect(Unit) {
//        logics.requestState() // todo
    }
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.White),
    ) {
        // todo
    }
}
