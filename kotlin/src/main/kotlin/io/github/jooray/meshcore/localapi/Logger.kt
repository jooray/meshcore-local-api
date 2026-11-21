package io.github.jooray.meshcore.localapi

/**
 * Where the library writes its diagnostics. On Android, forward to `android.util.Log`; the
 * library itself has no Android imports. Messages never contain keys, signatures or payloads.
 */
interface MeshLogger {
    fun debug(tag: String, message: String) {}
    fun info(tag: String, message: String) {}
    fun warn(tag: String, message: String, error: Throwable? = null) {}

    companion object {
        /** Drops everything (the default). */
        val NONE: MeshLogger = object : MeshLogger {}

        /** Prints to stdout/stderr; handy in tests and command-line tools. */
        val STDOUT: MeshLogger = object : MeshLogger {
            override fun debug(tag: String, message: String) = println("D/$tag: $message")
            override fun info(tag: String, message: String) = println("I/$tag: $message")
            override fun warn(tag: String, message: String, error: Throwable?) =
                System.err.println("W/$tag: $message" + (error?.let { " ($it)" } ?: ""))
        }
    }
}
