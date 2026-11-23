//
// BlackholeAodv.h
//
// Classic AODV Black Hole node.
//
// Two distinct malicious behaviors, matching the two phases of a real
// AODV Black Hole attack:
//
//  (A) ROUTE DISCOVERY PHASE (this file's new addition):
//      When V1 receives a genuine RREQ broadcast for a destination it is
//      not itself, it fabricates a fake/attractive RREP -- claiming a
//      route to that destination with an inflated (deliberately "fresh")
//      destination sequence number and a minimal hop count -- and sends
//      it directly back toward the RREQ originator using AODV's own
//      sendAODVPacket() path. This is injected ALONGSIDE normal
//      processing: the original RREQ is handed unmodified to the real
//      Aodv implementation afterward, so genuine route discovery,
//      forwarding, and any real RREP from the actual destination still
//      happen exactly as they would without the attack. AODV's own
//      "prefer higher destination sequence number" rule is what makes
//      the source accept the malicious route -- nothing is forced.
//
//  (B) DATA FORWARDING PHASE (existing, unchanged):
//      Once selected as next hop, V1 silently drops any data packet it
//      is asked to forward, via the virtual datagramForwardHook().
//
// Neither handleRREQ(), handleRREP(), nor createRREP() are touched or
// overridden -- those are NOT virtual in INET's Aodv and cannot be
// polymorphically overridden by a subclass. socketDataArrived() IS
// virtual (it satisfies the UdpSocket::ICallback interface), which is
// why it is the correct and only reliable interception point.
//
#ifndef __VANET_BLACKHOLE_BLACKHOLEAODV_H
#define __VANET_BLACKHOLE_BLACKHOLEAODV_H

#include "inet/routing/aodv/Aodv.h"
#include "inet/routing/aodv/AodvControlPackets_m.h"

using namespace inet;
using namespace inet::aodv;

class BlackholeAodv : public Aodv
{
  protected:
    long numForwardedDropped = 0;
    long numFakeRreps = 0;

    // (A) Route-discovery-phase attack: intercept incoming RREQs and
    // inject a fake RREP, then let normal processing continue.
    virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;

    // (B) Data-forwarding-phase attack: drop instead of relay (unchanged).
    virtual Result datagramForwardHook(Packet *datagram) override;

    virtual void finish() override;

  public:
    BlackholeAodv() {}
};

#endif
