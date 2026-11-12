"""Throwaway: keep large type blocks from `-Zprint-type-sizes` output."""
import re
import sys

HEADER = re.compile(r"^print-type-size type: `(.*)`: (\d+) bytes, alignment: (\d+) bytes")
FIELD_SIZE = re.compile(r": (\d+) bytes")
INTERESTING = re.compile(
    r"H2Stream|H2ClientFuture|ProxyBody|RequestContext|DirectH2RequestBody|ResponseBody|"
    r"BackendDispatchResult|BackendResponse|PipeToSendStream|ClientAbortScope|"
    r"TransactionSummary|PluginCacheRequestView|GrpcBody|UploadSource|SendWhen|ConnTask"
)
MIN_BLOCK = 1024
MIN_FIELD = 96
MAX_LINES = 600

block = None
keep = False
lines = 0


def flush():
    global block
    if block and keep:
        sys.stdout.write("".join(block))
    block = None


for line in sys.stdin:
    match = HEADER.match(line)
    if match:
        flush()
        size = int(match.group(2))
        name = match.group(1)
        keep = size >= MIN_BLOCK or (size >= 256 and INTERESTING.search(name) is not None)
        block = [line[:2000] + ("\n" if len(line) > 2000 else "")]
        lines = 0
        continue
    if block is None or not keep:
        continue
    if "variant" in line or "discriminant" in line:
        block.append(line[:600] + ("\n" if len(line) > 600 else ""))
        continue
    field = FIELD_SIZE.search(line)
    if field and int(field.group(1)) >= MIN_FIELD and lines < MAX_LINES:
        block.append(line[:600] + ("\n" if len(line) > 600 else ""))
        lines += 1
flush()
