//
// VanetAodvDpbha.cc -- DPBHA baseline for VanetAodv (parameter dpbha = true)
//
// Reference: A. Malik, M. Z. Khan, M. Faisal, F. Khan, J.-T. Seo,
// "An Efficient Dynamic Solution for the Detection and Prevention of Black Hole
// Attack in VANETs", Sensors 22(5):1897, 2022.  (Algorithm steps cited below.)
//
// Detection logic as written by the author (VanetAodvDpbha.user.cc), adapted to
// VanetAodv being a SUBCLASS of INET's Aodv, not a copy of it:
//   - handleRREP/createRREP are non-virtual in INET, so RREPs are intercepted in
//     VanetAodv::socketDataArrived and the chosen one is handed to handleRREP
//     directly (no re-entry flag needed);
//   - global namespace, like VanetAodv;
//   - TP/FP ground truth from the RREP's type: only the attacker builds DpbhaRrep,
//     INET's honest createRREP builds a plain Rrep (whose replier is unknown, so
//     the previous hop is grey-listed, as in the original fallback).
//
// Runs only at the RREQ originator, on honest vehicles:
//   1. collect every RREP for the destination for dpbhaCollectTime    (steps 11-12)
//   2. sort by D_SN, compute the dynamic threshold lambda              (steps 13-15, Eq. 11-13)
//   3. D_SN > lambda  ->  grey list (suspect)                          (steps 16-19, Eq. 14)
//   4. use the RREP with the highest D_SN <= lambda, fewest hops       (step 20)
//   5. broadcast a bait RREQ for a non-existent address; a grey-listed
//      node that answers it is blacklisted                             (steps 21-27)
// Steps 26-27 (alarm): optional and idealised (dpbhaAlarm = true): a bait-confirmed
// attacker enters a set shared by all vehicles at once, without packets or loss.
//

#include <algorithm>
#include <cmath>

#include "VanetAodv.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/contract/IRoute.h"
#include "inet/routing/aodv/AodvRouteData.h"

std::set<L3Address> VanetAodv::dpbhaAlarmSet;

void VanetAodv::dpbhaInit()
{
    dpbhaEnabled = par("dpbha").boolValue() && !blackhole;
    dpbhaCollectTime = par("dpbhaCollectTime");
    dpbhaBaitAddr = L3AddressResolver().resolve(par("dpbhaBaitAddress").stringValue());
    dpbhaAlarm = par("dpbhaAlarm").boolValue();

    // Reset the shared alarm set once per run. A simTime() == 0 test would never fire:
    // Veins creates the first vehicle at connectAt + updateInterval, after t = 0.
    static std::string alarmRunId;
    std::string runId = getEnvir()->getConfigEx()->getVariable(CFGVAR_RUNID);
    if (runId != alarmRunId) {
        dpbhaAlarmSet.clear();
        alarmRunId = runId;
    }
}

// Eq. (13) as in the paper's worked example: lambda = | (sum D_SN_i - delta) / n  +  n * delta |
double VanetAodv::dpbhaThreshold(const std::vector<DpbhaEntry>& rat, double delta)
{
    double sum = 0;
    for (const auto& e : rat)
        sum += e.rrep->getDestSeqNum();
    double n = rat.size();
    return std::fabs((sum - delta) / n + n * delta);
}

// Returns true if DPBHA consumed the RREP (buffered or dropped); the caller then deletes the packet.
bool VanetAodv::dpbhaInterceptRrep(const Ptr<const Rrep>& rrepIn, const L3Address& sourceAddr)
{
    // Idealised alarm: every honest DPBHA vehicle, relays included, drops route replies
    // from an alarmed node. Hellos (no originator) are not route replies and pass.
    if (dpbhaAlarm && !rrepIn->getOriginatorAddr().isUnspecified()
        && dpbhaAlarmSet.count(dpbhaReplier(rrepIn, sourceAddr))) {
        numDpbhaAlarmDrops++;
        return true;
    }

    if (rrepIn->getOriginatorAddr() != getSelfIPAddress())
        return false;                                  // not our discovery (also excludes hellos)

    const L3Address dest = rrepIn->getDestAddr();
    const L3Address replier = dpbhaReplier(rrepIn, sourceAddr);
    const bool fake = dynamicPtrCast<const DpbhaRrep>(rrepIn) != nullptr;   // ground truth only

    // Steps 23-25: nobody can legitimately answer for the bait address.
    if (dest == dpbhaBaitAddr) {
        if (dpbhaGreyList.count(replier) && dpbhaBlackList.insert(replier).second) {
            if (addressBelongsToBlackhole(replier)) numDpbhaBlackTP++; else numDpbhaBlackFP++;
            if (dpbhaAlarm)
                dpbhaAlarmSet.insert(replier);
            EV_WARN << "DPBHA: " << replier << " answered the bait RREQ -> blacklisted"
                    << (dpbhaAlarm ? " (alarm: all vehicles)" : "") << endl;
        }
        return true;   // never install a route to the bait address
    }

    if (dpbhaBlackList.count(replier)) {
        numDpbhaDropped++;
        return true;
    }

    // Mutable copy: handleRREP increments the hop count when the RREP is released.
    Ptr<Rrep> rrep = dynamicPtrCast<Rrep>(rrepIn->dupShared());

    // Steps 11-12: store in the response analysis table until the window closes.
    auto it = dpbhaCollect.find(dest);
    if (it == dpbhaCollect.end() && hasOngoingRouteDiscovery(dest)) {
        it = dpbhaCollect.emplace(dest, DpbhaWindow()).first;
        it->second.timer = new cMessage("dpbha-collect");
        scheduleAfter(dpbhaCollectTime, it->second.timer);
        numDpbhaWindows++;
    }
    if (it != dpbhaCollect.end()) {
        it->second.rat.push_back({rrep, sourceAddr, replier, fake});
        numDpbhaRrepsCollected++;
        return true;
    }

    // Late RREP after the window closed: judge it against that window's threshold,
    // otherwise a fake D_SN would overwrite the chosen route (AODV rule 6.7 ii).
    auto last = dpbhaLastLambda.find(dest);
    if (last != dpbhaLastLambda.end() && rrep->getDestSeqNum() > last->second) {
        dpbhaGreyListNode(replier, fake);
        numDpbhaDropped++;
        return true;
    }
    return false;
}

// Called from VanetAodv::handleMessageWhenUp(); returns true if msg was a DPBHA timer.
bool VanetAodv::dpbhaHandleSelfMessage(cMessage *msg)
{
    auto it = std::find_if(dpbhaCollect.begin(), dpbhaCollect.end(),
            [msg](const std::pair<const L3Address, DpbhaWindow>& e) { return e.second.timer == msg; });
    if (it == dpbhaCollect.end())
        return false;

    L3Address dest = it->first;
    std::vector<DpbhaEntry> rat = std::move(it->second.rat);
    delete msg;
    dpbhaCollect.erase(it);
    if (rat.size() == 1)
        numDpbhaSingleWindows++;   // with one reply lambda equals its D_SN, so it can never be flagged

    // Steps 13-14: sort by destination sequence number, descending.
    std::sort(rat.begin(), rat.end(), [](const DpbhaEntry& a, const DpbhaEntry& b) {
        return a.rrep->getDestSeqNum() > b.rrep->getDestSeqNum();
    });

    // Eq. (12): delta = D_SN(RREP_n) - D_SN in own routing table (0 if no valid entry).
    double delta = 0;
    IRoute *route = routingTable->findBestMatchingRoute(dest);
    if (route && route->getSource() == this) {
        auto *routeData = check_and_cast<AodvRouteData *>(route->getProtocolData());
        if (routeData->hasValidDestNum())
            delta = (double)rat.back().rrep->getDestSeqNum() - (double)routeData->getDestSeqNum();
    }
    double lambda = dpbhaThreshold(rat, delta);
    dpbhaLastLambda[dest] = lambda;

    // Steps 16-20: grey-list D_SN > lambda; pick highest D_SN <= lambda, then fewest hops.
    const DpbhaEntry *chosen = nullptr;
    unsigned int baitTtl = 0;
    for (const auto& e : rat) {
        unsigned int seq = e.rrep->getDestSeqNum();
        if (seq > lambda) {
            dpbhaGreyListNode(e.replier, e.fake);
            baitTtl = std::max(baitTtl, e.rrep->getHopCount() + 1);   // reach the farthest suspect
        }
        else if (!chosen || seq > chosen->rrep->getDestSeqNum()
                 || (seq == chosen->rrep->getDestSeqNum() && e.rrep->getHopCount() < chosen->rrep->getHopCount()))
            chosen = &e;
    }
    EV_INFO << "DPBHA: " << rat.size() << " RREPs for " << dest << ", delta = " << delta
            << ", lambda = " << lambda << endl;

    // Steps 21-22: bait RREQ (in parallel; the data route below is not held back).
    if (baitTtl > 0)
        dpbhaSendBait(baitTtl);

    // Steps 30-31: install the chosen route through INET's normal RREP handling
    // (completes the route discovery and releases the buffered datagrams).
    if (chosen)
        handleRREP(chosen->rrep, chosen->sender);
    else
        numDpbhaNoChoice++;    // every reply was above lambda; AODV's timeout/retry takes over
    return true;
}

void VanetAodv::dpbhaSendBait(unsigned int ttl)
{
    static bool checked = false;
    if (!checked) {   // addresses are assigned after INITSTAGE_LOCAL, so check here, once
        if (L3AddressResolver().findHostWithAddress(dpbhaBaitAddr) != nullptr)
            throw cRuntimeError("DPBHA: bait address %s belongs to a node; choose an unassigned one",
                                dpbhaBaitAddr.str().c_str());
        checked = true;
    }
    // createRREQ gives a fresh rreqId and buffers it, so our own bait is not re-processed.
    // Sent directly (not via sendRREQ): no WaitForRrep timer or expanding ring for the bait.
    auto bait = createRREQ(dpbhaBaitAddr);
    sendAODVPacket(bait, addressType->getBroadcastAddress(), ttl, 0);
    numDpbhaBaits++;
}

L3Address VanetAodv::dpbhaReplier(const Ptr<const Rrep>& rrep, const L3Address& sourceAddr) const
{
    if (auto d = dynamicPtrCast<const DpbhaRrep>(rrep))
        return d->getReplierAddr();
    return sourceAddr;   // RREP built by INET's createRREP: replier unknown, fall back to the previous hop
}

// Ground truth (TP/FP) only; never used in a decision.
void VanetAodv::dpbhaGreyListNode(const L3Address& addr, bool fake)
{
    if (dpbhaGreyList.insert(addr).second) {
        if (fake) numDpbhaGreyTP++; else numDpbhaGreyFP++;
    }
}

void VanetAodv::dpbhaFinish()
{
    if (!dpbhaEnabled)
        return;
    recordScalar("dpbhaWindows", numDpbhaWindows);
    recordScalar("dpbhaSingleReplyWindows", numDpbhaSingleWindows);
    recordScalar("dpbhaRrepsCollected", numDpbhaRrepsCollected);
    recordScalar("dpbhaNoChoice", numDpbhaNoChoice);
    recordScalar("dpbhaBaitsSent", numDpbhaBaits);
    recordScalar("dpbhaRrepsDropped", numDpbhaDropped);
    recordScalar("dpbhaGreyTP", numDpbhaGreyTP);
    recordScalar("dpbhaGreyFP", numDpbhaGreyFP);
    recordScalar("dpbhaBlackTP", numDpbhaBlackTP);
    recordScalar("dpbhaBlackFP", numDpbhaBlackFP);
    if (dpbhaAlarm)
        recordScalar("dpbhaAlarmDrops", numDpbhaAlarmDrops);
}
