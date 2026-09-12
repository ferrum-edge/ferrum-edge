use dashmap::{DashMap, Map};
use ferrum_edge::util::sharding::{MAX_SHARD_AMOUNT, pool_shard_amount};

#[test]
fn explicit_one_constructs_a_working_two_shard_map() {
    assert_eq!(pool_shard_amount(1), 2);
    let map = DashMap::with_shard_amount(pool_shard_amount(1));
    map.insert("key", 42);
    assert_eq!(map._shard_count(), 2);
    assert_eq!(*map.get("key").unwrap(), 42);
    assert_eq!(map.remove("key"), Some(("key", 42)));
}

#[test]
fn shard_normalization_preserves_rounding_and_bounds() {
    let auto = pool_shard_amount(0);
    assert!(auto.is_power_of_two());
    assert!((64..=MAX_SHARD_AMOUNT).contains(&auto));
    for input in 1usize..=4096 {
        let expected = input.next_power_of_two().max(2);
        assert_eq!(pool_shard_amount(input), expected, "{input}");
    }
    // Cover every rounding interval's boundaries without allocating maps with
    // millions of locks. The helper also saturates values beyond its ceiling.
    for exponent in 1..=30 {
        let power = 1usize << exponent;
        for input in [power - 1, power, power + 1] {
            let expected = input
                .checked_next_power_of_two()
                .unwrap_or(MAX_SHARD_AMOUNT)
                .clamp(2, MAX_SHARD_AMOUNT);
            assert_eq!(pool_shard_amount(input), expected, "{input}");
        }
    }
    assert_eq!(pool_shard_amount(usize::MAX), MAX_SHARD_AMOUNT);
}
