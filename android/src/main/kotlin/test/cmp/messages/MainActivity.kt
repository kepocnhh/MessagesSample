package test.cmp.messages

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.compose.ui.platform.ComposeView
import test.cmp.messages.module.router.RouterScreen

internal class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val context: Context = this
        val view = ComposeView(context)
        setContentView(view)
        view.setContent {
            RouterScreen()
        }
    }
}
