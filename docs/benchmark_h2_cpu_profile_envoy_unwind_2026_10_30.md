# H2 CPU profile: Envoy symbols vs. unwinding (2026-10-30)

Point-in-time observation from the manual **H2 and gRPC CPU Profile** workflow
([h2_cpu_profile.md](h2_cpu_profile.md)), hosted run 40999505084 (HTTP/2,
10 KiB, head `f6b91a1a3d19644d12f9964b5f55c8b324d232e5`). It is not updated as
behaviour changes.

The run had two Envoy captures. The debug-symbol twin named every Envoy
executable leaf in the measurement window: 62 of 62 and 46 of 46, up from 2
and 0. Even so, in pair 1, 2,073 of all 2,319 Envoy samples carried no unwound
frame, against 12 of all 2,393 Ferrum samples, and symbolization left those
counts unchanged. Total Envoy known-leaf coverage in the window therefore rose
only from 1.4–1.9% to about 4%.
