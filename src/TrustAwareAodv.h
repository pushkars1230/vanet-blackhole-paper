//
// TrustAwareAodv.h
//
// Used only by the SOURCE vehicle (vehicle0). Adds detection +
// mitigation on top of completely normal AODV behavior:
//
//  DETECTION: the co-located AccidentApp calls reportDeliveryFailure()
//  when it notices a sent packet was never acknowledged by the real
//  destination within a timeout. This module then looks up whichever
//  neighbor is CURRENTLY the next hop toward that destination -- i.e.
//  whoever AODV itself believes is the right relay -- and treats that
//  neighbor as the suspect. Nothing is assumed or hard-coded about
//  which node is malicious.
//
//  MITIGATION: the suspect neighbor is added to a local blacklist, and
//  every existing route through it is purged from the IP routing table
//  (via INET's standard, protocol-agnostic IRoutingTable interface --
//  no INET source is touched). Because socketDataArrived() is
//  overridden to silently ignore any further packet arriving directly
//  from a blacklisted neighbor, that neighbor cannot re-poison a fresh
//  route discovery either -- its RREQs/RREPs are simply never handed
//  to the real Aodv processing logic again.
//
// AODV route discovery itself is never disabled, forced, or faked --
// this class only decides, after the fact, whose replies to keep
// listening to.
//
#ifndef __VANET_BLACKHOLE_TRUSTAWAREAODV_H
#define __VANET_BLACKHOLE_TRUSTAWAREAODV_H

#include "inet/routing/aodv/Aodv.h"
#include <set>

using namespace inet;
using namespace inet::aodv;

class TrustAwareAodv : public Aodv
{
  protected:
    std::set<L3Address> blacklistedNeighbors;
    long numNeighborsBlacklisted = 0;

    // MITIGATION half: drop anything arriving directly from a
    // blacklisted neighbor before it ever reaches real Aodv processing.
    virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;

    virtual void finish() override;

  public:
    TrustAwareAodv() {}

    // DETECTION entry point, called externally by AccidentApp.
    void reportDeliveryFailure(const L3Address& destAddr);
};

#endif
