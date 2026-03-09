-- wrk script for health check endpoint testing
-- Measures basic gateway latency and throughput

wrk.method = "GET"
wrk.body = nil
wrk.headers["Accept"] = "application/json"
wrk.headers["User-Agent"] = "wrk-performance-test"

done = function(summary, latency, requests)
    -- Print additional statistics
    io.write("\n--- Additional Statistics ---\n")
    io.write(string.format("Total requests: %d\n", summary.requests or 0))
    io.write(string.format("Successful requests: %d\n", summary.status_200 or 0))
    
    local errors = 0
    if summary.errors and type(summary.errors) == "table" then
        for _, count in pairs(summary.errors) do
            errors = errors + count
        end
    elseif summary.errors and type(summary.errors) == "number" then
        errors = summary.errors
    end
    
    io.write(string.format("Failed requests: %d\n", errors))
end
