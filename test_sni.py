import asyncio
import httpx
import socket
import ssl

async def test():
    hostname = "www.google.com"
    ip = socket.gethostbyname(hostname)
    print(f"IP: {ip}")

    # Standard request
    print("--- Standard Request ---")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"https://{hostname}")
            print(f"Standard: {resp.status_code}")
        except Exception as e:
            print(f"Standard Error: {e}")

    # IP Request with Host header (Expect SSL Error)
    print("\n--- IP Request (No SNI fix) ---")
    async with httpx.AsyncClient(verify=True) as client:
        try:
            resp = await client.get(f"https://{ip}", headers={"Host": hostname})
            print(f"IP Request: {resp.status_code}")
        except Exception as e:
            print(f"IP Request Error: {e}")

    # IP Request with sni_hostname extension
    print("\n--- IP Request (extensions={'sni_hostname': hostname}) ---")
    transport = httpx.AsyncHTTPTransport()
    async with httpx.AsyncClient(transport=transport, verify=True) as client:
        try:
            # Manually construct request to pass extensions
            req = client.build_request("GET", f"https://{ip}", headers={"Host": hostname})
            req.extensions["sni_hostname"] = hostname
            resp = await client.send(req)
            print(f"SNI Extension: {resp.status_code}")
        except Exception as e:
            print(f"SNI Extension Error: {e}")

if __name__ == "__main__":
    asyncio.run(test())
