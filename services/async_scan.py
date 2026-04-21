import asyncio
import aiohttp

TIMEOUT = 5


async def fetch(session, url):
    try:
        async with session.get(url, timeout=TIMEOUT) as r:
            return await r.text()
    except:
        return None


async def scan_multiple(urls):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, u) for u in urls]
        return await asyncio.gather(*tasks)