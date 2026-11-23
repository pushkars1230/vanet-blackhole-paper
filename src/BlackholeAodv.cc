//
// BlackholeAodv.cc
//

#include "BlackholeAodv.h"
#include "inet/networklayer/common/L3AddressTag_m.h"

Define_Module(BlackholeAodv);


// ============================================================
// (A) ROUTE DISCOVERY PHASE -- fake/attractive RREP injection
// ============================================================

void BlackholeAodv::socketDataArrived(UdpSocket *sock, Packet *packet)
{
    /*
     * Peek at the incoming packet without consuming it.
     *
     * The original packet will still be handed to the real AODV
     * implementation below.
     */
    auto chunk = packet->peekAtFront<Chunk>();
    auto rreq = dynamicPtrCast<const Rreq>(chunk);

    /*
     * Only attack RREQs requesting a route to another node.
     */
    if (rreq != nullptr && rreq->getDestAddr() != getSelfIPAddress()) {

        L3Address originatorAddr = rreq->getOriginatorAddr();
        L3Address targetAddr = rreq->getDestAddr();

        /*
         * Identify the node that directly transmitted the RREQ to us.
         *
         * In the current topology:
         *
         * V0 -> V1
         *
         * therefore directSender should be V0.
         */
        auto addressInd = packet->findTag<L3AddressInd>();

        L3Address directSender =
            (addressInd != nullptr)
            ? addressInd->getSrcAddress()
            : originatorAddr;

        numFakeRreps++;

        EV_WARN << endl;
        EV_WARN << "==================================================" << endl;
        EV_WARN << "[BlackholeAodv] Received RREQ for destination "
                << targetAddr << endl;
        EV_WARN << "[BlackholeAodv] RREQ originator = "
                << originatorAddr << endl;
        EV_WARN << "[BlackholeAodv] Direct RREQ sender = "
                << directSender << endl;
        EV_WARN << "[BlackholeAodv] BLACK HOLE ATTACK: generating fake RREP"
                << endl;
        EV_WARN << "==================================================" << endl;


        /*
         * Create the malicious RREP.
         */
        auto fakeRrep = makeShared<Rrep>();

        /*
         * IMPORTANT:
         *
         * INET's genuine AODV RREP creator explicitly sets the
         * chunk length to 20 bytes for IPv4.
         *
         * Without this, the fake RREP has an invalid/zero chunk
         * length and can cause a runtime failure when UDP/IP tries
         * to transmit it.
         */
        fakeRrep->setPacketType(RREP);
        fakeRrep->setChunkLength(B(20));

        /*
         * Claim that we have a route to the requested destination.
         */
        fakeRrep->setDestAddr(targetAddr);

        /*
         * Deliberately advertise an artificially fresh sequence number.
         *
         * This is the classic Black Hole mechanism:
         * the malicious node advertises a route with a more attractive
         * destination sequence number.
         */
        sequenceNum += 1000;

        fakeRrep->setDestSeqNum(sequenceNum);

        /*
         * Original source of the RREQ.
         */
        fakeRrep->setOriginatorAddr(originatorAddr);

        /*
         * Claim that the destination is extremely close.
         *
         * RREP hop count represents the number of hops from the
         * originator to the destination through the advertised route.
         */
        fakeRrep->setHopCount(1);

        /*
         * Keep the route valid for six seconds.
         */
        fakeRrep->setLifeTime(simtime_t(6, SIMTIME_S));

        /*
         * Standard RREP flags/fields.
         */
        fakeRrep->setAckRequiredFlag(false);
        fakeRrep->setRepairFlag(false);
        fakeRrep->setPrefixSize(0);
        fakeRrep->setReserved(0);


        /*
         * Logging for research evidence.
         */
        EV_WARN << "[BlackholeAodv] Fake RREP destination = "
                << targetAddr << endl;

        EV_WARN << "[BlackholeAodv] Fake RREP destination sequence number = "
                << sequenceNum << endl;

        EV_WARN << "[BlackholeAodv] Fake RREP hop count = 1" << endl;

        EV_WARN << "[BlackholeAodv] Fake RREP lifetime = 6s" << endl;

        EV_WARN << "[BlackholeAodv] Sending malicious RREP to originator "
                << originatorAddr << endl;

        EV_WARN << "[BlackholeAodv] Sending fake RREP to direct sender "
                << directSender << endl;


        /*
         * Send the fake RREP using INET AODV's own transmission helper.
         *
         * This means the fake RREP still travels through:
         *
         * AODV
         * UDP
         * IP
         * wireless interface
         * radio medium
         *
         * We are NOT directly modifying V0's routing table.
         */
        sendAODVPacket(
            fakeRrep,
            directSender,
            255,
            0
        );

        EV_WARN << "[BlackholeAodv] Fake RREP transmitted successfully"
                << endl;

        EV_WARN << "==================================================" << endl;
    }


    /*
     * VERY IMPORTANT:
     *
     * Give the ORIGINAL packet to the real AODV implementation.
     *
     * This preserves genuine AODV route discovery.
     *
     * V1 can therefore:
     * - create its reverse route
     * - forward the RREQ
     * - receive a genuine RREP
     * - forward a genuine RREP
     *
     * The fake RREP simply competes with the genuine RREP.
     */
    Aodv::socketDataArrived(sock, packet);
}


// ============================================================
// (B) DATA FORWARDING PHASE -- drop instead of relay
// ============================================================

INetfilter::IHook::Result
BlackholeAodv::datagramForwardHook(Packet *datagram)
{
    numForwardedDropped++;

    EV_WARN << "[BlackholeAodv] Intercepted forwarded datagram '"
            << datagram->getName()
            << "' -- DROPPING instead of relaying. Total dropped so far: "
            << numForwardedDropped
            << endl;

    /*
     * DROP tells INET to discard the datagram.
     *
     * Do not delete datagram here.
     */
    return IHook::DROP;
}


// ============================================================
// Statistics
// ============================================================

void BlackholeAodv::finish()
{
    recordScalar(
        "blackholePacketsDropped",
        numForwardedDropped
    );

    recordScalar(
        "blackholeFakeRrepCount",
        numFakeRreps
    );

    /*
     * Explicitly qualify cComponent::finish().
     */
    cComponent::finish();
}
