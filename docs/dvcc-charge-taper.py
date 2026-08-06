# Offline prototype of the phase-2 cell-aware charge taper for dbus-shadowgrid.
# Drop-in for the block at ~line 246-248. Pure function -> unit-testable, hard-clamped.
# 8S LiFePO4: cell OVP 3.65V, OVP-release 3.50V, JBD full-chg 3.55V, bal_start 3.30V.

def charge_limits(maxcell, maxcur, cvl, temp_block, fet_chg,
                  taper_start=3.45, taper_full=3.60, hard_cut=3.62, ccl_floor=2.0):
    """Return (CCL_A, CVL_V). Preserves today's hard-stop on temp/FET; adds a
    linear CCL taper on the HIGHEST cell so it's held just under OVP while the
    JBD balancer bleeds it and the low cells catch up over cycles."""
    # existing safety behavior — unchanged, always wins
    if temp_block or not fet_chg:
        return 0.0, cvl
    # no cell data -> fall back to today's behavior (JBD BMS still the backstop)
    if maxcell is None:
        return maxcur, cvl
    if maxcell >= hard_cut:
        return 0.0, cvl
    if maxcell <= taper_start:
        return maxcur, cvl
    frac = (maxcell - taper_start) / (taper_full - taper_start)   # 0..1
    frac = min(max(frac, 0.0), 1.0)
    ccl = maxcur - frac * (maxcur - ccl_floor)
    return round(ccl, 1), cvl

# ---- validation sweep: highest cell 3.30 -> 3.66 V, healthy pack ----
print(f"{'maxcell':>8} | {'CCL today':>10} | {'CCL taper':>10} | {'CVL':>6} | note")
print("-"*62)
OVP=3.65
for mv in range(330, 367, 1):
    c = mv/100.0
    today_ccl = 100.0              # binary: full until the FET trips at OVP
    tccl, tcvl = charge_limits(c, 100.0, 28.4, temp_block=False, fet_chg=1)
    note=""
    if c < 3.45: note="full charge"
    elif c < 3.60: note="tapering"
    elif c < 3.62: note="trickle (balancer bleeds high cell)"
    else: note="charge held off (safely under 3.65 OVP)"
    star = "  <-- OVP trip today" if abs(c-OVP)<0.001 else ""
    print(f"{c:8.2f} | {today_ccl:9.0f}A | {tccl:9.1f}A | {tcvl:5.1f}V | {note}{star}")

# ---- safety cases ----
print("\nsafety cases (must match today's hard stops):")
print("  temp_block   ->", charge_limits(3.40, 100, 28.4, True,  1))
print("  FET open     ->", charge_limits(3.40, 100, 28.4, False, 0))
print("  no cell data ->", charge_limits(None, 100, 28.4, False, 1))
