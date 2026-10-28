"""Small Nintendo LZ11 encoder used by the CRO patch builders."""

from collections import defaultdict, deque


def compress(data: bytes) -> bytes:
    if len(data) > 0xFFFFFF:
        raise ValueError("input too large for short LZ11 header")
    out = bytearray((0x11, len(data) & 0xFF, (len(data) >> 8) & 0xFF,
                     (len(data) >> 16) & 0xFF))
    chains: dict[bytes, deque[int]] = defaultdict(deque)
    pos = 0

    def remember(start: int, end: int) -> None:
        for current in range(start, min(end, len(data) - 2)):
            key = bytes(data[current:current + 3])
            queue = chains[key]
            queue.append(current)
            while queue and current - queue[0] > 0x1000:
                queue.popleft()

    while pos < len(data):
        flag_pos = len(out)
        out.append(0)
        flags = 0
        for token in range(8):
            if pos >= len(data):
                break
            best_len = 0
            best_disp = 0
            if pos + 2 < len(data):
                key = bytes(data[pos:pos + 3])
                for candidate in reversed(tuple(chains.get(key, ()))[-64:]):
                    displacement = pos - candidate
                    if not 1 <= displacement <= 0x1000:
                        continue
                    limit = min(0x10110, len(data) - pos)
                    length = 3
                    while (length < limit and
                           data[candidate + (length % displacement)] == data[pos + length]):
                        length += 1
                    if length > best_len:
                        best_len, best_disp = length, displacement
                        if length == limit:
                            break
            if best_len < 3:
                out.append(data[pos])
                remember(pos, pos + 1)
                pos += 1
                continue

            flags |= 1 << (7 - token)
            d = best_disp - 1
            if best_len <= 0x10:
                out.extend(((best_len - 1) << 4 | (d >> 8), d & 0xFF))
            elif best_len <= 0x110:
                n = best_len - 0x11
                out.extend((n >> 4, (n & 0xF) << 4 | (d >> 8), d & 0xFF))
            else:
                n = best_len - 0x111
                out.extend((0x10 | (n >> 12), (n >> 4) & 0xFF,
                            (n & 0xF) << 4 | (d >> 8), d & 0xFF))
            remember(pos, pos + best_len)
            pos += best_len
        out[flag_pos] = flags
    return bytes(out)
