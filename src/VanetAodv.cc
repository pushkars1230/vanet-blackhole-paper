//
// VanetAodv.cc  (v8: + DPBHA alarm, poisonRange; v7: + instrumentation of bound propagation; DPBHA logic in VanetAodvDpbha.cc)
//
#include "VanetAodv.h"
#include "inet/common/ModuleAccess.h"
#include "inet/mobility/contract/IMobility.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/contract/IRoute.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/routing/aodv/AodvRouteData.h"

Define_Module(VanetAodv);


void VanetAodv::initialize(int stage)
{
    Aodv::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        blackhole = par("isBlackhole").boolValue();
        fakeSeqJump = par("fakeSeqJump").intValue();
        detectionMode = par("detectionMode").stdstringValue();
        blacklistExpiry = par("blacklistExpiry");
        maxRange = par("maxRange").doubleValue();
        rangeMode = par("rangeMode").stdstringValue();
        rangeMargin = par("rangeMargin").doubleValue();
        rangeWindow = par("rangeWindow");
        rangeFallback = par("rangeFallback").doubleValue();
        posErrorStd = par("posErrorStd").doubleValue();
        beaconInterval = par("beaconInterval");
        rangeCap = par("rangeCap").doubleValue();
        poisonRange = par("poisonRange").doubleValue();
        rangeAlertLevel = par("rangeAlertLevel").doubleValue();
        dpbhaInit();
        if (simTime() == 0)
            beaconTable.clear();
        if (rangeMode != "fixed" && rangeMode != "adaptive" && rangeMode != "cooperative")
            throw cRuntimeError("VanetAodv: unknown rangeMode '%s'", rangeMode.c_str());
        if (rangeMode == "cooperative" && rangeWindow > 0)
            throw cRuntimeError("VanetAodv: rangeMode 'cooperative' requires rangeWindow = 0s");

        if (detectionMode != "none" && detectionMode != "ackTimeout" && detectionMode != "plausibility")
            throw cRuntimeError("VanetAodv: unknown detectionMode '%s'", detectionMode.c_str());

        // Display only (Qtenv), no effect on results: blackholes black with a
        // stop marker and a "blackhole" label; node[0], the accident vehicle in
        // every configuration, red with an "accident" label.
        if (hasGUI()) {
            cModule *host = getContainingNode(this);
            cDisplayString& ds = host->getDisplayString();
            if (blackhole) {
                ds.setTagArg("i", 1, "black");
                ds.setTagArg("i", 2, "100");
                ds.setTagArg("i2", 0, "status/stop");
                ds.setTagArg("t", 0, "blackhole");
                ds.setTagArg("t", 2, "black");
            }
            else if (host->isVector() && host->getIndex() == 0) {
                ds.setTagArg("i", 1, "red");
                ds.setTagArg("i", 2, "100");
                ds.setTagArg("t", 0, "accident");
                ds.setTagArg("t", 2, "red");
            }
        }
    }
}


// DPBHA collection timers are VanetAodv's own; everything else goes to INET's Aodv.
void VanetAodv::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage() && dpbhaHandleSelfMessage(msg))
        return;
    Aodv::handleMessageWhenUp(msg);
}

VanetAodv::~VanetAodv()
{
    for (auto& e : dpbhaCollect)
        cancelAndDelete(e.second.timer);
}

// ------------------------------------------------------------------
// positions (stand-in for beacon-based neighbor/destination positions)
// ------------------------------------------------------------------

static bool positionOfHost(cModule *host, Coord& pos)
{
    if (host == nullptr)
        return false;
    auto mob = dynamic_cast<IMobility *>(host->getSubmodule("mobility"));
    if (mob == nullptr)
        return false;
    pos = mob->getCurrentPosition();
    return true;
}

bool VanetAodv::selfPosition(Coord& pos)
{
    return positionOfHost(getContainingNode(this), pos);
}

std::map<L3Address, VanetAodv::BeaconEntry> VanetAodv::beaconTable;

// Position of addr as the other vehicles know it from beacons: the true
// position at the time of the vehicle's last beacon, plus GPS error. With
// beaconInterval = 0 and posErrorStd = 0 this is the true current position.
// The error uses RNG 1 so that RNG 0 (AODV jitter etc.) is unchanged.
bool VanetAodv::beaconPositionOf(const L3Address& addr, Coord& pos)
{
    Coord truth;
    if (!positionOf(addr, truth))
        return false;
    if (beaconInterval <= 0 && posErrorStd <= 0) {
        pos = truth;
        return true;
    }
    BeaconEntry& e = beaconTable[addr];
    if (!e.valid || beaconInterval <= 0 || simTime() - e.t >= beaconInterval) {
        e.p = truth;
        if (posErrorStd > 0)
            e.p += Coord(normal(0, posErrorStd, 1), normal(0, posErrorStd, 1), 0);
        e.t = simTime();
        e.valid = true;
    }
    pos = e.p;
    return true;
}

bool VanetAodv::positionOf(const L3Address& addr, Coord& pos)
{
    return positionOfHost(L3AddressResolver().findHostWithAddress(addr), pos);
}

// Instrumentation only: is this address configured as a blackhole?
bool VanetAodv::addressBelongsToBlackhole(const L3Address& addr)
{
    cModule *host = L3AddressResolver().findHostWithAddress(addr);
    if (host == nullptr)
        return false;
    auto aodv = dynamic_cast<VanetAodv *>(host->getSubmodule("aodv"));
    return aodv != nullptr && aodv->isBlackhole();
}


bool VanetAodv::isBlacklisted(const L3Address& addr) const
{
    auto it = blacklistedUntil.find(addr);
    return it != blacklistedUntil.end() && simTime() < it->second;
}


// ------------------------------------------------------------------
// receive path
// ------------------------------------------------------------------

void VanetAodv::socketDataArrived(UdpSocket *sock, Packet *packet)
{
    auto addressInd = packet->findTag<L3AddressInd>();
    L3Address directSender = (addressInd != nullptr) ? addressInd->getSrcAddress() : L3Address();

    // Largest one-hop distance actually achieved (instrumentation), and the
    // observation that the adaptive bound learns from: this packet was received
    // from directSender, so a link of this length exists right now.
    if (!directSender.isUnspecified()) {
        Coord me, them;
        if (selfPosition(me) && positionOf(directSender, them)) {
            // instrumentation uses the true distance
            maxNeighborDistance = std::max(maxNeighborDistance, me.distance(them));
            // the bound learns from what the vehicle can actually know: beaconed positions
            Coord bme, bthem;
            if (rangeMode != "fixed" && beaconPositionOf(getSelfIPAddress(), bme) && beaconPositionOf(directSender, bthem)) {
                double d = bme.distance(bthem);
                observeRange(d);
                if (rangeMode == "cooperative") {
                    // the sender's learned bound, as if carried in its packet
                    cModule *host = L3AddressResolver().findHostWithAddress(directSender);
                    auto peer = host ? dynamic_cast<VanetAodv *>(host->getSubmodule("aodv")) : nullptr;
                    if (peer != nullptr)
                        runningMaxRange = std::max(runningMaxRange, peer->getLearnedRange());
                }
                runningMaxRange = capRange(runningMaxRange);
                // instrumentation (no effect on decisions): how fast an inflated bound spreads
                if (firstRangeObsAt < 0)
                    firstRangeObsAt = simTime().dbl();
                if (rangeAlertAt < 0 && rangeAlertLevel > 0 && runningMaxRange > rangeAlertLevel)
                    rangeAlertAt = simTime().dbl();
            }
        }
    }

    // ackTimeout MITIGATION: ignore anything from a blacklisted neighbor.
    if (detectionMode == "ackTimeout" && !directSender.isUnspecified() && isBlacklisted(directSender)) {
        numIgnoredFromBlacklisted++;
        EV_WARN << "[VanetAodv] MITIGATION: ignoring '" << packet->getName()
                << "' from blacklisted neighbor " << directSender << endl;
        delete packet;
        return;
    }

    auto chunk = packet->peekAtFront<Chunk>();

    // plausibility DETECTION: honest nodes drop implausible RREPs before AODV sees them.
    if (!blackhole && detectionMode == "plausibility" && !directSender.isUnspecified()) {
        auto rrep = dynamicPtrCast<const Rrep>(chunk);
        if (rrep != nullptr && !isPlausible(rrep, directSender)) {
            delete packet;
            return;
        }
    }

    // DPBHA (source only): RREPs for our own route discovery go to the response
    // analysis table instead of AODV; the chosen one is handed to handleRREP later.
    // Runs after the plausibility check, so with both enabled DPBHA only sees
    // replies that passed it.
    if (dpbhaEnabled && !directSender.isUnspecified()) {
        auto rrep = dynamicPtrCast<const Rrep>(chunk);
        if (rrep != nullptr && dpbhaInterceptRrep(rrep, directSender)) {
            delete packet;
            return;
        }
    }

    // ATTACK (route discovery): answer foreign RREQs with a fake RREP.
    if (blackhole) {
        auto rreq = dynamicPtrCast<const Rreq>(chunk);
        if (rreq != nullptr && rreq->getDestAddr() != getSelfIPAddress())
            sendFakeRrep(rreq, packet);
    }

    Aodv::socketDataArrived(sock, packet);
}


// RREP hopCount as received = sender's claimed number of hops to the destination
// (the destination itself sends 0; each forwarder sends its own metric).
// Plausible iff the sender can geometrically be that close:
//     dist(sender, dest) <= hopCount * maxRange
bool VanetAodv::isPlausible(const Ptr<const Rrep>& rrep, const L3Address& sender)
{
    numPlausibilityChecks++;

    L3Address dest = rrep->getDestAddr();
    if (sender == dest)
        return true;                                   // the destination answering for itself

    Coord s, d;
    if (!beaconPositionOf(sender, s) || !beaconPositionOf(dest, d))
        return true;                                   // no position known -> cannot judge, accept

    double range;
    if (!currentRange(range))
        return true;                                   // adaptive, nothing learned yet -> cannot judge, accept

    double dist = s.distance(d);
    unsigned int h = rrep->getHopCount();
    if (dist <= h * range) {
        // instrumentation: a blackhole's fake RREP got through the check
        if (rrep->getDestSeqNum() >= FAKE_SEQ_FLOOR && addressBelongsToBlackhole(sender)) {
            numPassedFakes++;
            EV_WARN << "[VanetAodv] PLAUSIBILITY: fake RREP from " << sender << " PASSED (" << dist
                    << " m <= " << h << " x " << range << " m)" << endl;
        }
        return true;
    }

    bool truth = addressBelongsToBlackhole(sender);
    if (truth) numRejectTruePositives++; else numRejectFalsePositives++;

    EV_WARN << "[VanetAodv] PLAUSIBILITY: rejecting RREP for " << dest << " from " << sender
            << ": claims " << h << " hop(s) but is " << dist << " m away (limit "
            << h * range << " m, R_max " << range << " m)" << (truth ? " [true positive]" : " [FALSE positive]") << endl;
    return false;
}


// ------------------------------------------------------------------
// adaptive R_max
// ------------------------------------------------------------------

void VanetAodv::observeRange(double oneHopDistance)
{
    if (rangeWindow <= 0) {
        runningMaxRange = std::max(runningMaxRange, oneHopDistance);
        return;
    }
    rangeSamples.emplace_back(simTime(), oneHopDistance);
}

// The bound used by the plausibility check.
//   fixed    : maxRange
//   adaptive : largest one-hop distance this vehicle has received over (within
//              rangeWindow if set), times (1 + rangeMargin); rangeFallback if
//              nothing has been received yet, or no bound (accept) if that is 0.
bool VanetAodv::currentRange(double& range)
{
    if (rangeMode == "fixed") {
        range = maxRange;
        return true;
    }

    double observed = -1;
    if (rangeMode == "cooperative" || rangeWindow <= 0)
        observed = runningMaxRange;
    else {
        simtime_t oldest = simTime() - rangeWindow;
        while (!rangeSamples.empty() && rangeSamples.front().first < oldest)
            rangeSamples.pop_front();
        for (const auto& s : rangeSamples)
            observed = std::max(observed, s.second);
    }

    if (observed < 0) {
        numRangeNoEstimate++;
        if (rangeFallback <= 0)
            return false;
        range = rangeFallback;
        return true;
    }

    range = capRange(observed) * (1.0 + rangeMargin);
    numRangeEstimates++;
    sumRangeUsed += range;
    minRangeUsed = (minRangeUsed < 0) ? range : std::min(minRangeUsed, range);
    maxRangeUsed = std::max(maxRangeUsed, range);
    return true;
}


void VanetAodv::sendFakeRrep(const Ptr<const Rreq>& rreq, Packet *packet)
{
    L3Address originatorAddr = rreq->getOriginatorAddr();
    L3Address targetAddr = rreq->getDestAddr();

    auto addressInd = packet->findTag<L3AddressInd>();
    L3Address directSender = (addressInd != nullptr) ? addressInd->getSrcAddress() : originatorAddr;

    numFakeRreps++;

    auto fakeRrep = makeShared<DpbhaRrep>();   // an Rrep that also names its creator (see DpbhaPackets.msg)
    fakeRrep->setReplierAddr(getSelfIPAddress());
    fakeRrep->setPacketType(RREP);
    fakeRrep->setChunkLength(B(20));          // same as INET's genuine IPv4 RREP
    fakeRrep->setDestAddr(targetAddr);
    unsigned int fakeSeq;
    if (fakeSeqJump <= 0) {           // classic attacker, unchanged from v5
        sequenceNum += 1000;
        fakeSeq = sequenceNum;
    }
    else                              // smart attacker
        fakeSeq = (rreq->getUnknownSeqNumFlag() ? 0 : rreq->getDestSeqNum()) + fakeSeqJump;
    fakeRrep->setDestSeqNum(fakeSeq);
    fakeRrep->setOriginatorAddr(originatorAddr);
    fakeRrep->setHopCount(1);                  // claim to be next to the destination
    fakeRrep->setLifeTime(simtime_t(6, SIMTIME_S));
    fakeRrep->setAckRequiredFlag(false);
    fakeRrep->setRepairFlag(false);
    fakeRrep->setPrefixSize(0);
    fakeRrep->setReserved(0);

    EV_WARN << "[VanetAodv] BLACK HOLE: fake RREP for " << targetAddr
            << " (seq " << fakeSeq << ", hop 1) to " << directSender
            << " (originator " << originatorAddr << ")" << endl;

    sendAODVPacket(fakeRrep, directSender, 255, 0);
}


INetfilter::IHook::Result VanetAodv::datagramForwardHook(Packet *datagram)
{
    if (blackhole) {
        numForwardedDropped++;
        classifyDrop(datagram);
        EV_WARN << "[VanetAodv] BLACK HOLE: dropping forwarded datagram '"
                << datagram->getName() << "' (total " << numForwardedDropped << ")" << endl;
        return IHook::DROP;   // do not delete the datagram here
    }
    return Aodv::datagramForwardHook(datagram);
}


// Instrumentation only: was this dropped warning travelling on a route that a
// fake RREP created? Looks at the SOURCE's current route to the destination:
// a destSeqNum >= FAKE_SEQ_FLOOR can only come from a fake RREP (seq + 1000);
// genuine destination sequence numbers stay far below that in a 60 s run.
void VanetAodv::classifyDrop(Packet *datagram)
{
    if (strcmp(datagram->getName(), "AccidentWarning") != 0)
        return;
    auto ip = datagram->peekAtFront<Ipv4Header>();
    L3Address src = ip->getSrcAddress(), dst = ip->getDestAddress();

    cModule *srcHost = L3AddressResolver().findHostWithAddress(src);
    auto srcAodv = srcHost ? dynamic_cast<VanetAodv *>(srcHost->getSubmodule("aodv")) : nullptr;
    unsigned int seq = 0;
    if (srcAodv != nullptr) {
        IRoute *route = srcAodv->routingTable->findBestMatchingRoute(dst);
        auto data = route ? dynamic_cast<AodvRouteData *>(route->getProtocolData()) : nullptr;
        if (data != nullptr)
            seq = data->getDestSeqNum();
    }
    if (seq >= FAKE_SEQ_FLOOR) numDropsViaFakeRoute++; else numDropsViaGenuineRoute++;
    EV_WARN << "[VanetAodv] BLACK HOLE drop of warning " << src << " -> " << dst << ": source route seq "
            << seq << (seq >= FAKE_SEQ_FLOOR ? " (via FAKE route)" : " (on GENUINE route)") << endl;
}


// ------------------------------------------------------------------
// ackTimeout baseline
// ------------------------------------------------------------------

void VanetAodv::reportDeliveryFailure(const L3Address& destAddr)
{
    if (detectionMode != "ackTimeout")
        return;

    IRoute *route = routingTable->findBestMatchingRoute(destAddr);
    if (route == nullptr) {
        EV_WARN << "[VanetAodv] Delivery failure for " << destAddr
                << " but no current route -- nothing to blacklist." << endl;
        return;
    }

    L3Address suspect = route->getNextHopAsGeneric();
    if (isBlacklisted(suspect)) {
        EV_WARN << "[VanetAodv] " << suspect << " already blacklisted." << endl;
        return;
    }

    simtime_t until = (blacklistExpiry > 0) ? simTime() + blacklistExpiry : SimTime::getMaxTime();
    blacklistedUntil[suspect] = until;
    numNeighborsBlacklisted++;

    bool truth = addressBelongsToBlackhole(suspect);
    if (truth) numTruePositives++; else numFalsePositives++;

    EV_WARN << "[VanetAodv] DETECTION: no ack for " << destAddr << " -- blacklisting next hop "
            << suspect << (truth ? " [true positive]" : " [FALSE positive]") << endl;

    for (int i = routingTable->getNumRoutes() - 1; i >= 0; i--) {
        IRoute *r = routingTable->getRoute(i);
        if (r->getNextHopAsGeneric() == suspect) {
            EV_WARN << "[VanetAodv] Purging route to " << r->getDestinationAsGeneric()
                    << " (via " << suspect << ")" << endl;
            routingTable->deleteRoute(r);
        }
    }
}


void VanetAodv::finish()
{
    beaconTable.clear();
    recordScalar("isBlackhole", blackhole ? 1 : 0);
    if (maxNeighborDistance >= 0)
        recordScalar("maxNeighborDistance", maxNeighborDistance);
    if (blackhole) {
        recordScalar("blackholePacketsDropped", numForwardedDropped);
        recordScalar("blackholeFakeRrepCount", numFakeRreps);
        recordScalar("dropsViaFakeRoute", numDropsViaFakeRoute);
        recordScalar("dropsViaGenuineRoute", numDropsViaGenuineRoute);
    }
    if (detectionMode == "ackTimeout") {
        recordScalar("blackholeNeighborsBlacklisted", numNeighborsBlacklisted);
        recordScalar("detectionTruePositives", numTruePositives);
        recordScalar("detectionFalsePositives", numFalsePositives);
        recordScalar("ignoredFromBlacklisted", numIgnoredFromBlacklisted);
    }
    if (detectionMode == "plausibility" && !blackhole) {
        recordScalar("plausibilityChecks", numPlausibilityChecks);
        recordScalar("plausibilityRejectsTP", numRejectTruePositives);
        recordScalar("plausibilityRejectsFP", numRejectFalsePositives);
        recordScalar("plausibilityPassedFakes", numPassedFakes);
        if (rangeMode != "fixed") {
            recordScalar("rangeNoEstimate", numRangeNoEstimate);
            recordScalar("rangeEstimates", numRangeEstimates);
            if (numRangeEstimates > 0) {
                recordScalar("rangeUsedMean", sumRangeUsed / numRangeEstimates);
                recordScalar("rangeUsedMin", minRangeUsed);
                recordScalar("rangeUsedMax", maxRangeUsed);
            }
            recordScalar("rangeFirstObservationTime", firstRangeObsAt);
            recordScalar("rangeAlertTime", rangeAlertAt);
        }
    }
    dpbhaFinish();
    // Aodv::finish() is ambiguous (cComponent vs cListener).
    cComponent::finish();
}
