import asyncio

from app.routers.realtime import realtime_stream


def test_realtime_stream_flushes_connection_preamble_immediately():
    response = asyncio.run(realtime_stream())

    async def first_chunk():
        return await response.body_iterator.__anext__()

    assert asyncio.run(first_chunk()) == ": connected\n\n"
