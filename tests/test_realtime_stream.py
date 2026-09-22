import asyncio

from app.routers.realtime import realtime_stream
from app.collectors.websocket_collector import bus


def test_realtime_stream_flushes_connection_preamble_immediately():
    response = asyncio.run(realtime_stream())

    async def first_chunk():
        return await response.body_iterator.__anext__()

    assert asyncio.run(first_chunk()) == ": connected\n\n"


def test_realtime_stream_heartbeat_does_not_close_subscription(monkeypatch):
    async def scenario():
        response = await realtime_stream()
        iterator = response.body_iterator.__aiter__()
        assert await iterator.__anext__() == ": connected\n\n"
        original = asyncio.wait_for

        async def short_wait(awaitable, timeout):
            return await original(awaitable, 0.001)

        monkeypatch.setattr("app.routers.realtime.asyncio.wait_for", short_wait)
        assert await iterator.__anext__() == ": heartbeat\n\n"
        await bus.publish("ip_changes", {"cursor": 9})
        chunk = await iterator.__anext__()
        assert 'event: ip_changes' in chunk and '"cursor": 9' in chunk
        await iterator.aclose()

    asyncio.run(scenario())
