//
// VanetAodv.ned  (v4: adaptive + cooperative R_max)
// Single AODV variant for the Veins sweep; role set by parameters.
//
package vanet_blackhole;

import inet.routing.aodv.Aodv;
import inet.applications.contract.IApp;

simple VanetAodv extends Aodv like IApp
{
    parameters:
        @class(VanetAodv);
        bool isBlackhole = default(false);
        int fakeSeqJump = default(0);   // 0 = classic attacker of all earlier experiments (own counter += 1000); > 0 = smart: RREQ's dest seq + fakeSeqJump
        string detectionMode = default("none");          // "none" | "ackTimeout" | "plausibility"
        double blacklistExpiry @unit(s) = default(0s);   // ackTimeout only; 0s = permanent
        double maxRange @unit(m) = default(400m);        // R_max for the plausibility check
        string rangeMode = default("fixed");             // "fixed": maxRange | "adaptive": own receptions | "cooperative": max of own and neighbours' learned bounds
        double rangeMargin = default(0.1);               // adaptive: R_used = (largest observed one-hop distance) * (1 + margin)
        double rangeWindow @unit(s) = default(0s);       // adaptive: only observations from the last rangeWindow count; 0s = all
        double posErrorStd @unit(m) = default(0m);       // beacon realism: Gaussian error (per axis) on every beaconed position; 0 = exact
        double beaconInterval @unit(s) = default(0s);    // beacon realism: positions are refreshed only this often (stale in between); 0 = always current
        double poisonRange @unit(m) = default(0m);       // > 0: this vehicle advertises poisonRange as its learned bound (cooperative poisoning)
        double rangeCap @unit(m) = default(0m);          // adaptive/cooperative: learned and advertised bounds are capped here; 0 = no cap
        double rangeFallback @unit(m) = default(0m);     // adaptive, no observation yet: use this bound; 0m = accept (cannot judge)
        bool dpbhaAlarm = default(false);                 // DPBHA: idealised alarm (step 27): a bait-confirmed attacker is known to every vehicle at once
        bool dpbha = default(false);                      // DPBHA baseline at the RREQ originator (combinable with detectionMode)
        double dpbhaCollectTime @unit(s) = default(0.1s); // DPBHA: how long RREPs are collected (rrep_time_out); keep below the 0.32 s ring timeout
        string dpbhaBaitAddress = default("10.0.255.254");// DPBHA: bait destination, must be an UNASSIGNED address
        double rangeAlertLevel @unit(m) = default(1000m); // instrumentation: time at which the learned bound first exceeds this is recorded
        @display("i=block/network2;is=s");
}
