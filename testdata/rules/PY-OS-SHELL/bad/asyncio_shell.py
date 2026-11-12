import asyncio


async def convert(path):
    # ruleid: PY-OS-SHELL
    proc = await asyncio.create_subprocess_shell(f"convert {path} out.png")
    await proc.wait()
