package test.cmp.messages.provider

internal class FinalLoggers : Loggers {
    override fun create(tag: String): Logger {
        return FinalLogger(tag = tag)
    }
}

private class FinalLogger(private val tag: String) : Logger {
    override fun debug(message: String) {
        System.out.println("$tag: $message")
    }

    override fun warning(message: String) {
        System.err.println("$tag: $message")
    }
}
