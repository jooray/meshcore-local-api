package io.github.jooray.meshcore.localapi

import io.github.jooray.meshcore.localapi.SessionLogic.Action
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The session decisions, message by message, without a socket (ported from Roadbeacon). */
class SessionLogicTest {

    private var now = 1_000_000L
    private val session = SessionLogic("#test") { now }

    private fun json(text: String): JsonObject = Json.parseToJsonElement(text).jsonObject

    private fun hello(connected: Boolean?) = Hello.parse(json(
        """{"type":"hello","protocol":1,"device":{"name":"Test node"""" +
            (connected?.let { ""","connected":$it""" } ?: "") + "}}"
    )).device

    private fun device(connected: Boolean, vararg channels: String) = DeviceUpdate.parse(json(
        """{"type":"device","device":{"connected":$connected,"name":"Test node"},"channels":[""" +
            channels.joinToString(",") { """{"index":19,"name":"$it"}""" } + "]}"
    ))

    private val ok: ApiResult<String> = ApiResult.Ok("s1")
    private fun error(code: String) = ApiResult.Failed(ApiError(code, "x"))
    private fun info(text: String): ApiResult<DeviceUpdate> {
        val r = json(text)
        return ApiResult.Ok(DeviceUpdate(DeviceInfo.parse(r), ChannelInfo.parseList(r["channels"])))
    }

    private fun connectedAndSubscribed() {
        session.connectionStarted()
        assertEquals(Action.Subscribe, session.onHello(hello(true)))
        assertEquals(Action.None, session.onSubscribeAnswer(ok))
    }

    @Test
    fun `hello with the radio subscribes and the answer connects`() {
        connectedAndSubscribed()
        assertEquals(SessionState.Connected("Test node"), session.state)
        assertTrue(session.isSubscribed)
    }

    @Test
    fun `hello without the connected flag still subscribes`() {
        session.connectionStarted()
        assertEquals(Action.Subscribe, session.onHello(hello(null)))
    }

    @Test
    fun `no radio waits for a device message, then subscribes`() {
        session.connectionStarted()
        assertEquals(Action.None, session.onHello(hello(false)))
        assertEquals(SessionState.NoRadio, session.state)
        assertEquals(Action.None, session.onDevice(device(false)))
        assertEquals(SessionState.NoRadio, session.state)
        assertEquals(Action.Subscribe, session.onDevice(device(true, "#test")))
        session.onSubscribeAnswer(ok)
        assertEquals(SessionState.Connected("Test node"), session.state)
    }

    @Test
    fun `radio coming back without the channel still subscribes once to find out`() {
        session.connectionStarted()
        session.onHello(hello(false))
        assertEquals(Action.Subscribe, session.onDevice(device(true, "Public")))
    }

    @Test
    fun `radio gone and back keeps the one subscription`() {
        connectedAndSubscribed()
        assertEquals(Action.None, session.onDevice(device(false)))
        assertEquals(SessionState.NoRadio, session.state)
        assertTrue(session.isSubscribed)
        assertEquals(Action.None, session.onDevice(device(true, "#test")))
        assertEquals(SessionState.Connected("Test node"), session.state)
    }

    @Test
    fun `device message while subscribed changes nothing`() {
        connectedAndSubscribed()
        assertEquals(Action.None, session.onDevice(device(true, "#test")))
        assertEquals(SessionState.Connected("Test node"), session.state)
    }

    @Test
    fun `device push before hello is ignored`() {
        session.connectionStarted()
        assertEquals(Action.None, session.onDevice(device(true, "#test")))
    }

    @Test
    fun `unknown channel without a radio is no radio`() {
        session.connectionStarted()
        session.onHello(hello(null))
        session.onDevice(device(false))
        assertEquals(Action.None, session.onSubscribeAnswer(error("unknown_channel")))
        assertEquals(SessionState.NoRadio, session.state)
    }

    @Test
    fun `other errors are refused with their code`() {
        session.connectionStarted()
        session.onHello(hello(true))
        assertEquals(Action.None, session.onSubscribeAnswer(error("rate_limited")))
        assertEquals(SessionState.Refused("rate_limited"), session.state)
        session.connectionStarted()
        session.onHello(hello(true))
        session.onSubscribeAnswer(ApiResult.Failed(ApiError(ErrorCodes.TIMEOUT)))
        assertEquals(SessionState.Refused(ErrorCodes.TIMEOUT), session.state)
    }

    @Test
    fun `not_connected on subscribe is no radio`() {
        session.connectionStarted()
        session.onHello(hello(true))
        session.onSubscribeAnswer(error("not_connected"))
        assertEquals(SessionState.NoRadio, session.state)
    }

    @Test
    fun `missing channel asks once, then subscribes`() {
        session.connectionStarted()
        session.onHello(hello(true))
        assertEquals(Action.Join, session.onSubscribeAnswer(error("unknown_channel")))
        assertEquals(SessionState.WaitingForChannel, session.state)
        // The server announces the new channel too; the join answer already subscribes.
        assertEquals(Action.None, session.onDevice(device(true, "#test")))
        assertEquals(Action.Subscribe, session.onJoinAnswer(ApiResult.Ok(JoinResult(19, "#test", true))))
        session.onSubscribeAnswer(ok)
        assertEquals(SessionState.Connected("Test node"), session.state)
    }

    @Test
    fun `join is asked once per connection`() {
        session.connectionStarted()
        session.onHello(hello(true))
        assertEquals(Action.Join, session.onSubscribeAnswer(error("unknown_channel")))
        assertEquals(Action.None, session.onJoinAnswer(error("no_free_slot")))
        assertEquals(SessionState.ChannelMissing("no_free_slot"), session.state)
        assertEquals(Action.Subscribe, session.onRetry(null))
        assertEquals(Action.None, session.onSubscribeAnswer(error("unknown_channel")))
        assertEquals(SessionState.ChannelMissing("no_free_slot"), session.state)
        // A new connection may ask again.
        session.connectionStarted()
        session.onHello(hello(true))
        assertEquals(Action.Join, session.onSubscribeAnswer(error("unknown_channel")))
    }

    @Test
    fun `join can be switched off`() {
        val quiet = SessionLogic("#test", askToJoin = false) { now }
        quiet.connectionStarted()
        quiet.onHello(hello(true))
        assertEquals(Action.None, quiet.onSubscribeAnswer(error("unknown_channel")))
        assertEquals(SessionState.ChannelMissing(null), quiet.state)
    }

    @Test
    fun `a denial pauses asking for ten minutes, across connections`() {
        session.connectionStarted()
        session.onHello(hello(true))
        session.onSubscribeAnswer(error("unknown_channel"))
        assertEquals(Action.None, session.onJoinAnswer(error("denied")))
        assertEquals(SessionState.ChannelDenied, session.state)

        now += SessionLogic.DENIED_PAUSE_MS - 1
        session.connectionStarted()
        session.onHello(hello(true))
        assertEquals(Action.None, session.onSubscribeAnswer(error("unknown_channel")))
        assertEquals(SessionState.ChannelDenied, session.state)

        now += 1
        session.connectionStarted()
        session.onHello(hello(true))
        assertEquals(Action.Join, session.onSubscribeAnswer(error("unknown_channel")))
    }

    @Test
    fun `a new session asks again at once`() {
        session.connectionStarted()
        session.onHello(hello(true))
        session.onSubscribeAnswer(error("unknown_channel"))
        session.onJoinAnswer(error("denied"))
        val fresh = SessionLogic("#test") { now }
        fresh.connectionStarted()
        fresh.onHello(hello(true))
        assertEquals(Action.Join, fresh.onSubscribeAnswer(error("unknown_channel")))
    }

    @Test
    fun `channel added on the server after a denial subscribes`() {
        session.connectionStarted()
        session.onHello(hello(true))
        session.onSubscribeAnswer(error("unknown_channel"))
        session.onJoinAnswer(error("denied"))
        assertEquals(Action.None, session.onDevice(device(true, "Public")))
        assertEquals(Action.Subscribe, session.onDevice(device(true, "Public", "#test")))
    }

    @Test
    fun `retry only for servers that never send device`() {
        session.connectionStarted()
        assertFalse(session.retryDue())
        session.onHello(hello(true))
        assertFalse(session.retryDue()) // subscription in flight
        session.onSubscribeAnswer(error("rate_limited"))
        assertTrue(session.retryDue())
        session.onDevice(device(true, "Public"))
        assertFalse(session.retryDue())
    }

    @Test
    fun `retry reads device info before subscribing`() {
        session.connectionStarted()
        session.onHello(hello(false))
        assertTrue(session.retryDue())
        assertEquals(Action.None, session.onRetry(info("""{"connected":false,"channels":[]}""")))
        assertEquals(SessionState.NoRadio, session.state)
        assertEquals(Action.Subscribe, session.onRetry(info("""{"connected":true,"name":"Test node","channels":[]}""")))
    }

    @Test
    fun `unknown region is shown until a send goes through`() {
        connectedAndSubscribed()
        assertFalse(session.onSendAnswer(error("unknown_region"), "xx-test"))
        assertEquals(SessionState.Connected("Test node", "xx-test"), session.state)
        assertTrue(session.onSendAnswer(ApiResult.Ok(Unit), null))
        assertEquals(SessionState.Connected("Test node"), session.state)
        // Without a region set, bad_request is not about the region.
        assertFalse(session.onSendAnswer(error("bad_request"), null))
        assertEquals(SessionState.Connected("Test node"), session.state)
    }
}
