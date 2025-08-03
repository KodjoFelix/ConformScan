import asyncio
import ipaddress
import socket

# Configurables
DEFAULT_PORT_START = 1
DEFAULT_PORT_END = 1024
DEFAULT_TIMEOUT = 1.0  # secondes par tentative
DEFAULT_CONCURRENCY = 200  # connexions simultanées max


def normalize_ipv4_allow_leading_zeros(target: str) -> str | None:
    """
    Normalise une IPv4 en supprimant les zéros en tête par octet.
    Ex: '172.20.10.05' -> '172.20.10.5'
    Retourne None si impossible.
    """
    try:
        parts = target.strip().split(".")
        if len(parts) != 4:
            return None
        nums = []
        for p in parts:
            if p == "":
                return None
            # int('05') -> 5 ; vérifie aussi l'intervalle 0..255
            n = int(p, 10)
            if n < 0 or n > 255:
                return None
            nums.append(str(n))
        ip = ".".join(nums)
        # Validation finale
        ipaddress.IPv4Address(ip)
        return ip
    except Exception:
        return None


def coerce_target_to_ip(target: str) -> str | None:
    """
    Essaie dans l'ordre :
    1) target est déjà une IPv4 valide ;
    2) normalisation 'zéros en tête' ;
    3) résolution DNS si target est un hostname.
    Retourne l'IP normalisée ou None si échec.
    """
    t = target.strip()
    # 1) IPv4 directe
    try:
        ipaddress.IPv4Address(t)
        return t
    except Exception:
        pass
    # 2) Normalisation zéros en tête
    ip_norm = normalize_ipv4_allow_leading_zeros(t)
    if ip_norm:
        return ip_norm
    # 3) Hostname -> IP
    try:
        resolved = socket.gethostbyname(t)
        ipaddress.IPv4Address(resolved)
        return resolved
    except Exception:
        return None


async def scan_port(ip: str, port: int, timeout: float) -> bool:
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except AttributeError:
            pass
        return True
    except Exception:
        return False


async def _bounded_scan(semaphore: asyncio.Semaphore, ip: str, port: int, timeout: float, results: list):
    async with semaphore:
        open_ = await scan_port(ip, port, timeout)
        if open_:
            results.append(port)


async def scan_ports_concurrent(ip: str, ports: list[int], timeout: float, concurrency: int) -> list[int]:
    semaphore = asyncio.Semaphore(concurrency)
    results: list[int] = []
    tasks = [
        _bounded_scan(semaphore, ip, port, timeout, results)
        for port in ports
    ]
    await asyncio.gather(*tasks)
    return sorted(results)


async def scan_range_async(ip: str, port_start: int = DEFAULT_PORT_START, port_end: int = DEFAULT_PORT_END,
                           timeout: float = DEFAULT_TIMEOUT, concurrency: int = DEFAULT_CONCURRENCY) -> dict:
    # ip doit être déjà normalisée/validée en amont
    ports = list(range(port_start, port_end + 1))
    open_ports = await scan_ports_concurrent(ip, ports, timeout, concurrency)
    return {"scanned_ip": ip, "open_ports": open_ports}


def scan_range(ip: str, port_start: int = DEFAULT_PORT_START, port_end: int = DEFAULT_PORT_END,
               timeout: float = DEFAULT_TIMEOUT, concurrency: int = DEFAULT_CONCURRENCY) -> dict:
    return asyncio.run(scan_range_async(ip, port_start, port_end, timeout, concurrency))
