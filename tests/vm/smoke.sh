# Guest-side smoke test for timed. Run with
#   dist/release/drive.py --no-disk --share <dir> --timeout 420 \
#     --cmdline-extra 'loglevel=7 ignore_loglevel' \
#     --qemu-extra '-rtc base=2020-01-01T00:00:00' <dir>/smoke.sh
# and read <dir>/timed-report.txt plus the timed: lines on the console.
#
# The --qemu-extra is the point of the test, not a detail. QEMU's default
# is -rtc base=utc, so a guest normally boots with the host's correct
# clock and the three things most worth proving — the build floor, the
# startup step, and NTS-KE succeeding on a machine whose clock is years
# wrong — never execute at all.
#
# No grep, sed or awk: the image ships peiosutils, a coreutils fork, and
# has none of them.
{
  # PEI-577: peinit drops into recovery when atriumd reaches Backoff,
  # which happens 20-30 seconds into a script this long, ending the
  # session before an NTS handshake and a poll can complete. Nothing to do
  # with timed — a script that only sleeps reproduces the same state — and
  # `svctl stop atriumd` does not avoid it, because RestartPolicy brings
  # it back. Everything up to the wait loop completes; everything after it
  # currently does not.

  echo "== the clock as the kernel found it"
  date
  echo "(the RTC was set to 2020-01-01; if this reads 2026 then timed has"
  echo " already raised it to the build floor, which is the first thing"
  echo " it does and the reason TLS can work at all)"

  echo "== service"
  svctl status timed | head -3
  echo "-- the identity it actually got, and what it may do"
  svctl status timed | head -8

  echo "== the state directory the pre-start hook made"
  if [ -d /var/state/timed ]; then
    echo "ok   /var/state/timed"
    sd show /var/state/timed --sddl 2>&1 | head -2
  else
    echo "MISSING /var/state/timed"
  fi
  echo "-- the hook's own log"
  cat /var/state/timed-prepare.log 2>&1 | tail -5

  echo "== status at start"
  clock status

  echo "== sources"
  clock sources

  echo "== the registry holds the policy, and the defaults are the safe ones"
  reg get 'Machine/System/Time'
  echo "-- and the privilege grant that lets timed act"
  reg ls 'Machine/Generic/Authn/Policy'

  echo "== waiting for the first measurement (up to four minutes)"
  # An NTS-KE handshake to a public server plus a poll. Slow, and worth
  # waiting for: everything before this proves the machine can start, and
  # only this proves it can tell the time.
  i=0
  while [ "$i" -lt 24 ]; do
    sleep 10
    i=$((i + 1))
    STATE=$(clock status | head -2 | tail -1)
    echo "  [$i] $STATE"
    # "unsynchronised" contains "synchronised", so a *synchronised* glob
    # matches the state we are waiting to leave and the loop exits at once.
    # Match the two states that mean the clock is actually being steered.
    case "$STATE" in
      *"state        synchronised"*|*settling*|*spike*) break ;;
    esac
  done

  echo "== status after synchronising"
  clock status
  echo "== sources after synchronising"
  clock sources
  echo "== the clock now"
  date

  echo "== the drift file"
  cat /var/state/timed/drift 2>&1
  echo "== the cookie store (one file per NTS source)"
  ls /var/state/timed/cookies 2>&1

  echo "== reload is gated, query is not"
  clock reload; echo "exit=$?"

  echo "== a bad configuration is refused rather than silently ignored"
  reg set Machine/System/Time Servers multi:'time.example.org prefered'
  sleep 3
  clock sources
  reg del Machine/System/Time Servers
  sleep 3

  echo "== final status"
  clock status
} > /share/timed-report.txt 2>&1
