//
// TrustAwareAodv.cc
//
#include "TrustAwareAodv.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/contract/IRoute.h"

Define_Module(TrustAwareAodv);

void TrustAwareAodv::socketDataArrived(UdpSocket *sock, Packet *packet)
{
    auto addressInd = packet->findTag<L3AddressInd>();
    L3Address directSender = (addressInd != nullptr) ? addressInd->getSrcAddress() : L3Address();

    if (!directSender.isUnspecified() && blacklistedNeighbors.count(directSender) > 0) {
        EV_WARN << "[TrustAwareAodv] MITIGATION: ignoring packet '"
                << packet->getName() << "' arriving directly from blacklisted "
                << "neighbor " << directSender << " -- not handed to AODV." << endl;
        delete packet;
        return; // never reaches Aodv::socketDataArrived -- as if it never arrived
    }

    // Everyone else's traffic (including the legitimate relay) is
    // processed completely normally.
    Aodv::socketDataArrived(sock, packet);
}

void TrustAwareAodv::reportDeliveryFailure(const L3Address& destAddr)
{
    IRoute *route = routingTable->findBestMatchingRoute(destAddr);
    if (route == nullptr) {
        EV_WARN << "[TrustAwareAodv] Delivery failure reported for " << destAddr
                << " but no current route exists -- nothing to blacklist yet." << endl;
        return;
    }

    L3Address suspectNeighbor = route->getNextHopAsGeneric();

    if (blacklistedNeighbors.count(suspectNeighbor) > 0) {
        EV_WARN << "[TrustAwareAodv] " << suspectNeighbor
                << " is already blacklisted; nothing new to do." << endl;
        return;
    }

    numNeighborsBlacklisted++;
    blacklistedNeighbors.insert(suspectNeighbor);

    EV_WARN << "[TrustAwareAodv] DETECTION: no delivery confirmation for destination "
            << destAddr << " -- current relay " << suspectNeighbor
            << " is suspected of dropping traffic." << endl;
    EV_WARN << "[TrustAwareAodv] MITIGATION: blacklisting neighbor " << suspectNeighbor
            << " and purging all routes through it." << endl;

    // Purge every route (not just the one to destAddr) that currently
    // goes through the misbehaving neighbor, forcing AODV to perform
    // fresh route discovery on the next send attempt.
    for (int i = routingTable->getNumRoutes() - 1; i >= 0; i--) {
        IRoute *r = routingTable->getRoute(i);
        if (r->getNextHopAsGeneric() == suspectNeighbor) {
            EV_WARN << "[TrustAwareAodv] Purging route to "
                    << r->getDestinationAsGeneric()
                    << " (was via " << suspectNeighbor << ")" << endl;
            routingTable->deleteRoute(r);
        }
    }
}

void TrustAwareAodv::finish()
{
    recordScalar("blackholeNeighborsBlacklisted", numNeighborsBlacklisted);
    // See earlier note: Aodv::finish() alone is ambiguous due to Aodv's
    // multiple inheritance (cComponent::finish() vs cListener::finish()).
    cComponent::finish();
}
