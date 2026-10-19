-- timed.evman — timed.clock.stepped: a clock set by hand is recorded with
-- operation.name `manual`, the clock's reading before and after, and the
-- requester's SID.
--
-- timed has no TRM yet; the event's definition in timed.evman, and the
-- user guide's "Setting the clock" (Time topic), are what this checks.
-- It is also the proof that timed's service SID holds SeAuditPrivilege
-- (timed-policy.reg, kept by RequiredPrivileges in timed-service.reg),
-- which no unit test can show: without it the clock still moves and the
-- record is lost.
--
-- The machine is the whole Peios of the peinit profile, which runs timed.
-- It has no network, so timed never steps the clock on its own; the one
-- step in the window is the one asked for. The record is read off the
-- KMES ring (helpers.kmes): one vCPU, so CPU 0's ring sees everything.

local peinit = require("helpers.peinit")
local kmes = require("helpers.kmes")
local sys = require("helpers.sys")

peinit.claim(1)

local vm = peinit.boot({})
-- peinit reports phase 2 complete before the boot's own service starts
-- have run, and on a loaded host timed can still be starting well after
-- that. Until it is serving, `clock set` has no socket to reach.
peinit.settle(vm)

local TYPE = "timed.clock.stepped"
-- S-1-5-18, the agent's user, in its binary form.
local SYSTEM_SID = "\1\1\0\0\0\0\0\5\18\0\0\0"
local NS = 1000000000

local function epoch()
    local r = vm:run("date +%s")
    r:assert_ok()
    return tonumber(r.stdout:match("%d+"))
end

test("a clock set by hand is recorded as timed.clock.stepped: manual, the times before and after, and who asked",
    { spec = "timed.evman timed.clock.stepped" }, function(t)
        vm:run([[REG_ASSUME_YES=1 reg set 'Machine\System\Time' Automatic dword:0]]):assert_ok()

        local ring, errno = kmes.attach(vm, 0)
        t:assert(ring, "a KMES ring attaches: " .. sys.errname(errno or 0))
        local before = epoch()
        -- An hour ahead: far past anything a slew could do, and nowhere
        -- near the build floor.
        local target = before + 3600
        -- timed refuses until it has read Automatic = 0 from its registry
        -- watch, so ask until it accepts.
        local last
        local ok = pcall(wait_until, function()
            last = vm:run("clock set @" .. target)
            return last.exit_code == 0
        end, { timeout = 15, interval = 0.5, desc = "clock set to be accepted" })
        t:assert(ok, "clock set @" .. target .. " is accepted once Automatic is 0: "
            .. tostring(last and (last.stdout .. last.stderr)))

        local seen = {}
        local found = pcall(wait_until, function()
            for _, e in ipairs(kmes.drain(ring)) do
                if e.type == TYPE then seen[#seen + 1] = e end
            end
            return #seen >= 1
        end, { timeout = 10, interval = 0.2, desc = "a timed.clock.stepped record" })
        kmes.detach(ring)
        t:assert(found, "timed wrote " .. TYPE .. " (it needs SeAuditPrivilege)")
        t:assert_eq(#seen, 1, "one record for one step")

        local e = seen[1]
        local p = e.payload
        t:assert(p, "the payload decodes: " .. tostring(e.payload_error))
        t:assert_eq(e.origin, kmes.ORIGIN.USERSPACE, "written by a userspace emitter")
        t:assert_eq(p.operation and p.operation.name, "manual", "operation.name is manual")
        local clock = p.clock or {}
        t:assert(math.type(clock.time) == "integer", "clock.time is an integer count of nanoseconds")
        t:assert(math.type(clock["time-previous"]) == "integer", "and so is clock.time-previous")
        local after = clock.time // NS
        local previous = clock["time-previous"] // NS
        t:assert(math.abs(after - target) <= 2,
            string.format("clock.time is the time asked for (%d s, asked %d)", after, target))
        t:assert(previous >= before - 2 and previous <= before + 20,
            string.format("clock.time-previous is the clock just before (%d s, read %d)", previous, before))
        t:assert(p.subject and p.subject.token, "a manual set carries subject.token")
        t:assert_eq(p.subject.token.sid, SYSTEM_SID, "subject.token.sid is the requester, SYSTEM, in binary")
    end)
