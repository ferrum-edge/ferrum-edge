-- Unified wrk script for gateway comparison benchmarks (POST variant)
-- Sends a ~10 KB JSON payload to /api/echo and expects it echoed back.
-- This measures realistic request+response body proxying overhead.

-- Build a ~10 KB JSON payload once at init time
local function build_payload()
    local items = {}
    for i = 1, 50 do
        items[#items + 1] = string.format(
            '{"id":%d,"name":"user_%d","email":"user_%d@example.com","role":"member","active":true,"score":%d,"bio":"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore."}',
            i, i, i, i * 17
        )
    end
    return '{"items":[' .. table.concat(items, ",") .. ']}'
end

local payload = build_payload()

wrk.method = "POST"
wrk.body = payload
wrk.headers["Content-Type"] = "application/json"
wrk.headers["Accept"] = "application/json"
wrk.headers["User-Agent"] = "wrk-gateway-comparison"

done = function(summary, latency, requests)
    -- Machine-parseable output block
    -- The report generator keys on "--- Comparison Results ---" as a delimiter
    io.write("\n--- Comparison Results ---\n")
    io.write(string.format("total_requests: %d\n", summary.requests))
    io.write(string.format("duration_us: %d\n", summary.duration))
    io.write(string.format("errors_status: %d\n", summary.errors.status))
    io.write(string.format("errors_connect: %d\n", summary.errors.connect))
    io.write(string.format("errors_read: %d\n", summary.errors.read))
    io.write(string.format("errors_write: %d\n", summary.errors.write))
    io.write(string.format("errors_timeout: %d\n", summary.errors.timeout))
    io.write(string.format("latency_min_us: %.2f\n", latency.min))
    io.write(string.format("latency_max_us: %.2f\n", latency.max))
    io.write(string.format("latency_mean_us: %.2f\n", latency.mean))
    io.write(string.format("latency_stdev_us: %.2f\n", latency.stdev))
    io.write(string.format("latency_p50_us: %.2f\n", latency:percentile(50)))
    io.write(string.format("latency_p90_us: %.2f\n", latency:percentile(90)))
    io.write(string.format("latency_p99_us: %.2f\n", latency:percentile(99)))
    io.write(string.format("latency_p999_us: %.2f\n", latency:percentile(99.9)))
    io.write(string.format("rps: %.2f\n", summary.requests / (summary.duration / 1000000)))
    io.write(string.format("bytes_total: %d\n", summary.bytes))
    io.write("--- End Results ---\n")
end
