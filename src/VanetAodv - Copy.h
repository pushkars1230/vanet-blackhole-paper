//
// VanetAodv.h  (v5: adaptive + cooperative R_max; position error, beacon staleness, range cap)
//
// One AODV subclass for the Veins sweep. Role set by parameters:
//
//   isBlackhole   -- inject fake RREPs (seq+1000, hopCount 1) on foreign RREQs
//                    and drop all forwarded data.
//
//   detectionMode -- "none"         : plain AODV
//                    "ackTimeout"   : source blacklists its current next hop when
//                                     AccidentApp reports a missing ack (baseline)
//                    "plausibility" : every honest node checks each received RREP:
//                                     reject if  dist(sender, dest) > hopCount * maxRange
//                                     (sender = neighbor that transmitted the RREP,
//                                      hopCount = sender's claimed hops to dest)
//
//   maxRange        -- R_max for the plausibility check (rangeMode "fixed")
//   rangeMode       -- "fixed"    : R_max = maxRange
//                      "adaptive" : each vehicle learns R_max from its own receptions:
//                                   R_used = (largest distance at which it has received an
//                                   AODV packet, incl. hellos) * (1 + rangeMargin)
//                      "cooperative" : as adaptive, but every packet also carries the
//                                   sender's learned bound and the receiver keeps the
//                                   larger one, so the bound spreads to vehicles whose
//                                   own neighbours happen to be close. A liar can only
//                                   loosen the bound this way, never tighten it.
//                                   (Read from the sender's module here, standing in for
//                                   a field in the beacon, like the positions.)
//   rangeWindow     -- adaptive: only receptions in the last rangeWindow count (0 s = all)
//   rangeFallback   -- adaptive, nothing received yet: bound to use (0 m = accept)
//   blacklistExpiry -- ackTimeout mode only; 0 s = permanent
//
// Positions come from a global lookup of the vehicles' mobility modules. This
// stands in for positions learned from periodic beacons (CAM/BSM) and assumes
// honest position reports.
//
// Instrumentation (never used for decisions): ground-truth classification of
// every blacklist/rejection, and the largest observed one-hop distance.
//
#ifndef __VANET_BLACKHOLE_VANETAODV_H
#define __VANET_BLACKHOLE_VANETAODV_H

#include "inet/common/geometry/common/Coord.h"
#include "inet/routing/aodv/Aodv.h"
#include "inet/routing/aodv/AodvControlPackets_m.h"
#include <deque>
#include <map>
#include <string>

using namespace inet;
using namespace inet::aodv;

class VanetAodv : public Aodv
{
  protected:
    // parameters
    bool blackhole = false;
    std::string detectionMode;
    simtime_t blacklistExpiry;
    double maxRange = 0;
    std::string rangeMode;
    double rangeMargin = 0;
    simtime_t rangeWindow;
    double rangeFallback = 0;
    double posErrorStd = 0;
    simtime_t beaconInterval;
    double rangeCap = 0;

    // beacon realism: the position each vehicle last "broadcast", shared by all
    // receivers (one beacon is heard by everyone), with its time stamp
    struct BeaconEntry { simtime_t t; Coord p; bool valid = false; };
    static std::map<L3Address, BeaconEntry> beaconTable;

    // adaptive R_max state: (time, one-hop distance) of successful receptions
    std::deque<std::pair<simtime_t, double>> rangeSamples;
    double runningMaxRange = -1;       // used when rangeWindow == 0

    // adaptive R_max statistics
    long numRangeEstimates = 0;        // checks that used a learned bound
    long numRangeNoEstimate = 0;       // checks with nothing learned yet
    double sumRangeUsed = 0, minRangeUsed = -1, maxRangeUsed = -1;

    // blackhole statistics
    long numForwardedDropped = 0;
    long numFakeRreps = 0;

    // ackTimeout detection state + statistics
    std::map<L3Address, simtime_t> blacklistedUntil;
    long numNeighborsBlacklisted = 0;
    long numTruePositives = 0;
    long numFalsePositives = 0;
    long numIgnoredFromBlacklisted = 0;

    // plausibility detection statistics
    long numPlausibilityChecks = 0;
    long numRejectTruePositives = 0;
    long numRejectFalsePositives = 0;

    // instrumentation
    double maxNeighborDistance = -1;
    long numPassedFakes = 0;          // honest node: fake RREP (seq >= FAKE_SEQ_FLOOR from a blackhole) passed the check
    long numDropsViaFakeRoute = 0;    // blackhole: dropped warning whose source route came from a fake RREP
    long numDropsViaGenuineRoute = 0; // blackhole: dropped warning on a genuine route
    static const unsigned int FAKE_SEQ_FLOOR = 1000;

    virtual void initialize(int stage) override;
    virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;
    virtual Result datagramForwardHook(Packet *datagram) override;
    virtual void finish() override;

    bool isBlacklisted(const L3Address& addr) const;
    void sendFakeRrep(const Ptr<const Rreq>& rreq, Packet *packet);
    bool isPlausible(const Ptr<const Rrep>& rrep, const L3Address& sender);
    void observeRange(double oneHopDistance);
    bool currentRange(double& range);   // false -> no bound available (accept)

    bool selfPosition(Coord& pos);
    static bool positionOf(const L3Address& addr, Coord& pos);
    bool beaconPositionOf(const L3Address& addr, Coord& pos);   // what other vehicles believe (error, staleness)
    double capRange(double r) const { return (rangeCap > 0 && r > rangeCap) ? rangeCap : r; }
    static bool addressBelongsToBlackhole(const L3Address& addr);
    void classifyDrop(Packet *datagram);

  public:
    VanetAodv() {}

    bool isBlackhole() const { return blackhole; }
    double getLearnedRange() const { return runningMaxRange; }

    // ackTimeout DETECTION entry point, called by AccidentApp on ack timeout.
    void reportDeliveryFailure(const L3Address& destAddr);
};

#endif
