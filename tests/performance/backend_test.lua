-- wrk script for direct backend testing (baseline)
-- Measures backend performance without gateway overhead

wrk.method = "GET"
wrk.body = nil
wrk.headers["Accept"] = "application/json"
wrk.headers["User-Agent"] = "wrk-backend-baseline"

request = function()
    -- Test the same endpoint as gateway test for comparison
    return wrk.format("GET", "/api/users", wrk.headers, nil)
end

done = function(summary, latency, requests)
    io.write("\n--- Backend Baseline Statistics ---\n")
    io.write(string.format("Direct backend requests: %d\n", summary.status_200 or 0))
end
