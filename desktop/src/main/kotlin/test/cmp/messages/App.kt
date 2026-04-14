package test.cmp.messages

import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application

internal object App {
    init {
        // todo
    }
}

fun main() {
    application {
        Window(onCloseRequest = ::exitApplication, title = "MessagesSample") {
            // todo
        }
    }
}
