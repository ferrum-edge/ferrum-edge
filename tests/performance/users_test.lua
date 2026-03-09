-- wrk script for users API endpoint testing
-- Tests more complex JSON responses and gateway routing

wrk.method = "GET"
wrk.body = nil
wrk.headers["Accept"] = "application/json"
wrk.headers["User-Agent"] = "wrk-performance-test"

-- Test different user IDs to simulate realistic usage
local user_ids = {1, 2, 3, 4, 5}
local current_user_id = 1

init = function(args)
    -- Initialize any test-specific state
    wrk.headers["X-Test-ID"] = "users-api-test"
end

request = function()
    -- Alternate between list endpoint and specific user endpoints
    local path
    
    if math.random() > 0.7 then
        -- 30% chance to hit specific user endpoint
        path = "/api/users/" .. user_ids[current_user_id]
        current_user_id = (current_user_id % #user_ids) + 1
    else
        -- 70% chance to hit list endpoint
        path = "/api/users"
    end
    
    return wrk.format("GET", path, wrk.headers, nil)
end

done = function(summary, latency, requests)
    io.write("\n--- Users API Statistics ---\n")
    io.write(string.format("JSON responses: %d\n", summary.status_200 or 0))
end
