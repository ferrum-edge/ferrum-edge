//! Exercise the private, reusable interner implementation without exposing a
//! production testing API or mutating the process-global metrics interner.

#[path = "../../../src/plugins/mesh/label_interner.rs"]
mod implementation;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Barrier, Weak};

use implementation::{
    FRONT_CACHE_MAX_LABEL_BYTES, FRONT_CACHE_SLOTS, LabelFrontCache, LabelInterner, LabelLookup,
};

fn slot(value: &str) -> usize {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish() as usize % FRONT_CACHE_SLOTS
}

#[test]
fn warm_front_hit_reuses_the_admitted_arc_without_global_lookup() {
    let interner = LabelInterner::<4096>::new(4);
    let mut front = LabelFrontCache::new();
    let mut lookups = 0;
    let first = front.intern_with("payments", |value| {
        lookups += 1;
        interner.intern(value)
    });
    for _ in 0..100 {
        let repeated = front.intern_with("payments", |value| {
            lookups += 1;
            interner.intern(value)
        });
        assert!(Arc::ptr_eq(&first, &repeated));
    }
    assert_eq!(lookups, 1);
    assert!(Arc::ptr_eq(&first, &interner.intern("payments").into_arc()));
}

#[test]
fn colliding_texts_replace_one_slot_without_aliasing_labels() {
    let first_text = "payments";
    let other = (0..10_000)
        .map(|index| format!("collision-{index}"))
        .find(|value| value != first_text && slot(value) == slot(first_text))
        .expect("a 64-slot cache must have a collision in this finite set");
    let interner = LabelInterner::<4096>::new(4);
    let mut front = LabelFrontCache::new();
    let first = front.intern_with(first_text, |value| interner.intern(value));
    let second = front.intern_with(&other, |value| interner.intern(value));
    assert_eq!(second.as_ref(), other);
    assert!(!Arc::ptr_eq(&first, &second));
    let restored = front.intern_with(first_text, |value| interner.intern(value));
    assert_eq!(restored.as_ref(), first_text);
    assert!(Arc::ptr_eq(&first, &restored));
}

#[test]
fn fallback_allocations_never_populate_or_evict_front_slots() {
    let mut front = LabelFrontCache::new();
    let mut calls = 0;
    let first = front.intern_with("not-admitted", |value| {
        calls += 1;
        LabelLookup::Uncached(Arc::from(value))
    });
    let second = front.intern_with("not-admitted", |value| {
        calls += 1;
        LabelLookup::Uncached(Arc::from(value))
    });
    assert_eq!(calls, 2);
    assert!(!Arc::ptr_eq(&first, &second));

    let admitted = front.intern_with("retained", |value| LabelLookup::Interned(Arc::from(value)));
    let overflow = (0..10_000)
        .map(|index| format!("overflow-{index}"))
        .find(|value| slot(value) == slot("retained"))
        .unwrap();
    let uncached = front.intern_with(&overflow, |value| LabelLookup::Uncached(Arc::from(value)));
    assert_eq!(uncached.as_ref(), overflow);
    let retained = front.intern_with("retained", |_| panic!("overflow evicted an admitted slot"));
    assert!(Arc::ptr_eq(&admitted, &retained));
}

#[test]
fn front_retention_has_fixed_slots_and_a_byte_length_bound() {
    let mut front = LabelFrontCache::new();
    let mut allocations: Vec<Weak<str>> = Vec::new();
    for index in 0..FRONT_CACHE_SLOTS * 8 {
        let text = format!("label-{index}");
        let value = front.intern_with(&text, |value| LabelLookup::Interned(Arc::from(value)));
        allocations.push(Arc::downgrade(&value));
    }
    let retained = allocations
        .iter()
        .filter(|value| value.strong_count() != 0)
        .count();
    assert!(retained > 0 && retained <= FRONT_CACHE_SLOTS);
    drop(front);
    assert!(allocations.iter().all(|value| value.strong_count() == 0));

    // The limit counts bytes, not characters; no normalization or truncation.
    let at_limit = "é".repeat(FRONT_CACHE_MAX_LABEL_BYTES / 2);
    let over_limit = format!("{at_limit}é");
    for (text, expected_calls) in [(at_limit, 1), (over_limit, 2)] {
        let mut front = LabelFrontCache::new();
        let mut calls = 0;
        let first = front.intern_with(&text, |value| {
            calls += 1;
            LabelLookup::Interned(Arc::from(value))
        });
        let second = front.intern_with(&text, |value| {
            calls += 1;
            LabelLookup::Interned(Arc::from(value))
        });
        assert_eq!(first.as_ref(), text);
        assert_eq!(second.as_ref(), text);
        assert_eq!(calls, expected_calls);
    }
}

#[test]
fn a_full_global_interner_keeps_existing_values_and_never_caches_overflow() {
    let interner = LabelInterner::<4096>::new(4);
    let mut admitted = Vec::new();
    for index in 0..4096 {
        let text = format!("admitted-{index}");
        let LabelLookup::Interned(value) = interner.intern(&text) else {
            panic!("global cap refused slot {index}");
        };
        admitted.push(value);
    }
    for (index, original) in admitted.iter().enumerate() {
        let LabelLookup::Interned(repeated) = interner.intern(&format!("admitted-{index}")) else {
            panic!("a full pool must still serve existing values");
        };
        assert!(Arc::ptr_eq(original, &repeated));
    }
    let mut front = LabelFrontCache::new();
    let mut lookups = 0;
    let first = front.intern_with("overflow", |value| {
        lookups += 1;
        interner.intern(value)
    });
    let second = front.intern_with("overflow", |value| {
        lookups += 1;
        interner.intern(value)
    });
    assert_eq!(lookups, 2);
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(first.as_ref(), "overflow");
}

#[test]
fn concurrent_unique_admissions_stay_at_the_4096_process_cap() {
    let interner = LabelInterner::<4096>::new(4);
    let start = Barrier::new(8);
    let admitted = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|worker| {
                let interner = &interner;
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    (0..1024)
                        .map(|index| {
                            let text = format!("worker-{worker}-label-{index}");
                            let lookup = interner.intern(&text);
                            let shared = matches!(&lookup, LabelLookup::Interned(_));
                            (text, lookup.into_arc(), shared)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        admitted.iter().filter(|(_, _, shared)| *shared).count(),
        4096
    );
    for (text, first, shared) in admitted {
        let repeated = interner.intern(&text);
        assert_eq!(matches!(&repeated, LabelLookup::Interned(_)), shared);
        assert_eq!(Arc::ptr_eq(&first, &repeated.into_arc()), shared);
    }
}

#[test]
fn racing_duplicate_admissions_release_reservations_and_share_across_workers() {
    let interner = LabelInterner::<128>::new(4);
    let start = Barrier::new(8);
    std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 0..8 {
            let interner = &interner;
            let start = &start;
            workers.push(scope.spawn(move || {
                let mut front = LabelFrontCache::new();
                start.wait();
                for _ in 0..4 {
                    for index in 0..96 {
                        let text = format!("shared-{index}");
                        let value = front.intern_with(&text, |value| interner.intern(value));
                        assert_eq!(value.as_ref(), text);
                    }
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
    });
    // A leaked occupied-entry reservation would refuse these final slots.
    for index in 0..128 {
        assert!(matches!(
            interner.intern(&format!("shared-{index}")),
            LabelLookup::Interned(_)
        ));
    }
    assert!(matches!(
        interner.intern("overflow"),
        LabelLookup::Uncached(_)
    ));
    let first = interner.intern("shared-0").into_arc();
    let other = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let mut front = LabelFrontCache::new();
                front.intern_with("shared-0", |value| interner.intern(value))
            })
            .join()
            .unwrap()
    });
    assert!(Arc::ptr_eq(&first, &other));
}
