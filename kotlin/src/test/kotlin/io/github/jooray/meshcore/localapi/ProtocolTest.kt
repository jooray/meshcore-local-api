package io.github.jooray.meshcore.localapi

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Parsing and request building, without a socket. */
class ProtocolTest {
    private fun json(text: String): JsonObject = Json.parseToJsonElement(text).jsonObject

    @Test
    fun `capabilities come from the top level of hello only`() {
        assertEquals(setOf("tx_path_data", "rx_path"),
            Hello.parse(json("""{"type":"hello","capabilities":["tx_path_data","rx_path",3]}""")).capabilities)
        assertTrue(Hello.parse(json("""{"type":"hello","server":{"name":"meshcored","capabilities":["tx_path_data"]}}""")).capabilities.isEmpty())
        assertTrue(Hello.parse(json("""{"type":"hello","capabilities":"tx_path_data"}""")).capabilities.isEmpty())
    }

    @Test
    fun `hello limits, device and radio`() {
        val hello = Hello.parse(json(
            """{"type":"hello","protocol":1,"client":{"fingerprint":"AB12"},"device":{"name":"Node\u0007 A","connected":false,
               "radio":{"sf":11,"bwHz":250000.0,"cr":1,"freqHz":869525000}},"limits":{"maxPayloadBytes":163,"sendsPerMinute":30},
               "eventTypes":["channel.data"],"future":{"x":1}}"""
        ))
        assertEquals(1, hello.protocol)
        assertEquals("Node A", hello.device!!.name)
        assertEquals(false, hello.device!!.connected)
        assertEquals(RadioParams(11, 250000, 5, 869525000L, null), hello.device!!.radio)
        assertEquals(163, hello.limits.maxPayloadBytes)
        assertNull(hello.limits.maxQueuedBytes)
        assertEquals(listOf("channel.data"), hello.eventTypes)
    }

    @Test
    fun `responses map to results and errors`() {
        assertEquals(ApiResponse.Ok(json("""{"queued":true}""")), ApiResponse.parse(json("""{"id":3,"ok":true,"result":{"queued":true}}""")))
        val err = ApiResponse.parse(json("""{"id":3,"ok":false,"error":{"code":"payload_too_large","message":"too big"}}"""))
        assertEquals(ApiResponse.Error(ApiError("payload_too_large", "too big")), err)
        assertEquals("payload_too_large", err.errorCode)
        assertEquals(ErrorCodes.INTERNAL, ApiResponse.parse(json("""{"id":3,"ok":false}""")).errorCode)
        assertEquals(ErrorCodes.TIMEOUT, ApiResponse.Timeout.toResult { }.errorCode)
        assertEquals(ErrorCodes.DISCONNECTED, ApiResponse.NotConnected.toResult { }.errorCode)
    }

    private fun event(extra: String = "") = json(
        """{"type":"channel.data","channel":"#test","channelIndex":19,"dataType":336,"payload":"AQID","snrDb":-7.25,
           "receivedAt":"2026-01-01T10:00:00.000Z","outgoing":false,"hops":2$extra}"""
    )

    @Test
    fun `channel data events are parsed, with hops and path`() {
        val d = MeshEvent.parse(event()) as MeshEvent.ChannelData
        assertArrayEquals(byteArrayOf(1, 2, 3), d.payload)
        assertEquals(-7.25, d.snrDb!!, 0.0)
        assertEquals(2, d.hops)
        assertEquals(336, d.dataType)
        assertEquals(1767261600000L, d.receivedAtMs)
        assertNull(d.path)
        val routed = MeshEvent.parse(event(""","path":"a1b2c3d4","pathHashSize":2,"routeType":"flood","rssiDbm":-101.5""")) as MeshEvent.ChannelData
        assertArrayEquals(byteArrayOf(0xa1.toByte(), 0xb2.toByte(), 0xc3.toByte(), 0xd4.toByte()), routed.path)
        assertEquals(2, routed.pathHashSize)
        assertEquals(-101.5, routed.rssiDbm!!, 0.0)
        val zero = MeshEvent.parse(event(""","path":"","pathHashSize":1""")) as MeshEvent.ChannelData
        assertEquals(0, zero.path!!.size)
        assertNull("odd path for its hash size", (MeshEvent.parse(event(""","path":"a1b2c3","pathHashSize":2""")) as MeshEvent.ChannelData).path)
    }

    @Test
    fun `unknown and malformed events are ignored`() {
        assertNull(MeshEvent.parse(json("""{"type":"send.result","sendId":"x"}""")))
        assertNull(MeshEvent.parse(json("""{"type":"channel.data","channel":"#test","dataType":336,"payload":"!!"}""")))
        assertNull(MeshEvent.parse(json("""{"type":"channel.data","channel":"#test","payload":"AQID"}""")))
        val text = MeshEvent.parse(json("""{"type":"channel.text","channel":"Public","text":"hi","senderName":null,"messageId":42,"outgoing":false}"""))
        assertEquals("42", (text as MeshEvent.ChannelText).messageId)
        assertTrue(MeshEvent.parse(json("""{"type":"advert","pubkey":"ab","name":null,"nodeType":2}""")) is MeshEvent.Advert)
    }

    @Test
    fun `subscribe params carry since only when set`() {
        val p = EventFilter.channelData("#test", listOf(0x0150), "2026-01-01T10:00:00.000Z").toParams()
        assertEquals("""["channel.data"]""", p["events"].toString())
        assertEquals("[336]", p["dataTypes"].toString())
        assertEquals("2026-01-01T10:00:00.000Z", p["since"]!!.jsonPrimitive.content)
        assertFalse(EventFilter.channelData("#test", listOf(1)).toParams().containsKey("since"))
        assertFalse(EventFilter().toParams().containsKey("events"))
    }

    @Test
    fun `send params by route`() {
        val bytes = byteArrayOf(1, 2, 3)
        val flood = MeshCoreApiClient.sendDataParams("#test", 336, bytes, null, Route.Flood)
        assertEquals("AQID", flood["payload"]!!.jsonPrimitive.content)
        assertFalse(flood.containsKey("region"))
        assertFalse(flood.containsKey("path"))
        assertFalse(MeshCoreApiClient.sendDataParams("#test", 336, bytes, " ", Route.Flood).containsKey("region"))
        assertEquals("sk-ba", MeshCoreApiClient.sendDataParams("#test", 336, bytes, "sk-ba", Route.Flood)["region"]!!.jsonPrimitive.content)

        val zero = MeshCoreApiClient.sendDataParams("#test", 336, bytes, "sk-ba", Route.ZeroHop)
        assertEquals("", zero["path"]!!.jsonPrimitive.content)
        assertEquals(1, zero["pathHashSize"]!!.jsonPrimitive.content.toInt())
        assertFalse("zero-hop never carries a region", zero.containsKey("region"))

        val direct = MeshCoreApiClient.sendDataParams("#test", 336, bytes, "sk-ba", Route.Direct(byteArrayOf(0x0a, 0x1b, 0x2c, 0x3d), 2))
        assertEquals("0a1b2c3d", direct["path"]!!.jsonPrimitive.content)
        assertEquals(2, direct["pathHashSize"]!!.jsonPrimitive.content.toInt())
        assertEquals("sk-ba", direct["region"]!!.jsonPrimitive.content)
    }

    @Test
    fun `direct paths are checked`() {
        assertTrue(Route.Direct(ByteArray(63), 1).valid)
        assertFalse(Route.Direct(ByteArray(64), 1).valid)
        assertTrue(Route.Direct(ByteArray(64), 2).valid)
        assertFalse(Route.Direct(ByteArray(3), 2).valid)
        assertFalse(Route.Direct(ByteArray(0), 1).valid)
        assertFalse(Route.Direct(ByteArray(4), 4).valid)
    }

    @Test
    fun `replay guard drops the frame at the cursor and remembers recent ones`() {
        val store = InMemoryCursorStore()
        val a = MeshEvent.parse(event()) as MeshEvent.ChannelData
        val guard = ReplayGuard(store)
        assertTrue(guard.accept(a))
        guard.advance(a)
        assertFalse("same process", guard.accept(a))
        assertTrue(store.load()!!.startsWith("2026-01-01T10:00:00.000Z "))

        val restarted = ReplayGuard(store)
        assertEquals("2026-01-01T10:00:00.000Z", restarted.since())
        assertFalse("after a restart", restarted.accept(a))
        val other = MeshEvent.parse(json(event().toString().replace("AQID", "BAUG"))) as MeshEvent.ChannelData
        assertTrue("another frame at the same instant", restarted.accept(other))

        // A plain timestamp (the apps' old cursor) still works as `since`.
        assertEquals("2026-01-01T09:00:00.000Z", ReplayGuard(InMemoryCursorStore("2026-01-01T09:00:00.000Z")).since())
    }

    @Test
    fun `the cursor never moves back`() {
        val store = InMemoryCursorStore()
        val guard = ReplayGuard(store)
        val newer = MeshEvent.parse(json(event().toString().replace("10:00:00", "11:00:00"))) as MeshEvent.ChannelData
        val older = MeshEvent.parse(event()) as MeshEvent.ChannelData
        guard.advance(newer)
        guard.advance(older)
        assertEquals("2026-01-01T11:00:00.000Z", guard.since())
    }
}
