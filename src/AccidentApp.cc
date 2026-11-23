#include <omnetpp.h>

#include "inet/applications/base/ApplicationBase.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/packet/chunk/BytesChunk.h"
#include "inet/mobility/contract/IMobility.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include "TrustAwareAodv.h"
#include "VanetAodv.h"

using namespace omnetpp;
using namespace inet;

class AccidentApp : public ApplicationBase
{
  protected:
    UdpSocket socket;
    cMessage *accidentTimer = nullptr;
    cMessage *ackTimeoutTimer = nullptr;

    simtime_t accidentTime;
    simtime_t ackTimeout;
    int localPort;
    int destPort;
    std::string destAddress;     // "" = pure receiver, "auto" = distance-band selection, else fixed address

    double minDestDistance;
    double maxDestDistance;
    L3Address destL3;
    bool destChosen = false;

    // stream mode: sendInterval > 0 sends numWarnings packets, one per interval, no retries
    simtime_t sendInterval;
    int numWarnings = 1;
    int packetBytes = 100;
    int streamSent = 0;

    int retryCount = 0;
    static const int MAX_RETRIES = 1;

    // statistics
    int numWarningsSent = 0;
    int numWarningsReceived = 0;
    int numAcksReceived = 0;
    int numAcksSent = 0;
    int numAckTimeouts = 0;
    long bytesReceived = 0;
    double delaySum = 0;
    simtime_t firstSendTime = -1;
    simtime_t firstReceiveTime = -1;
    simtime_t lastReceiveTime = -1;
    simtime_t ackLatency = -1;
    double destDistance = -1;
    int destCandidates = -1;

    virtual void initialize(int stage) override;
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void finish() override;
    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;

    void sendWarning();
    void sendAck(const L3Address& toAddr);
    void reportDeliveryFailureToAodv();
    bool chooseDestination();

  public:
    AccidentApp();
    virtual ~AccidentApp();
};

Define_Module(AccidentApp);

AccidentApp::AccidentApp()
{
    accidentTimer = nullptr;
    ackTimeoutTimer = nullptr;
}

AccidentApp::~AccidentApp()
{
    cancelAndDelete(accidentTimer);
    cancelAndDelete(ackTimeoutTimer);
}

void AccidentApp::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        accidentTime = par("accidentTime");
        ackTimeout = par("ackTimeout");
        localPort = par("localPort");
        destPort = par("destPort");
        destAddress = par("destAddress").stdstringValue();
        minDestDistance = par("minDestDistance").doubleValue();
        maxDestDistance = par("maxDestDistance").doubleValue();
        sendInterval = par("sendInterval");
        numWarnings = par("numWarnings");
        packetBytes = par("packetBytes");

        accidentTimer = new cMessage("accidentTimer");
        ackTimeoutTimer = new cMessage("ackTimeoutTimer");
    }
    // The socket is bound in handleStartOperation(), not here.
}

void AccidentApp::handleMessageWhenUp(cMessage *msg)
{
    if (msg == accidentTimer) {
        if (streamSent == 0)
            EV_INFO << "ACCIDENT DETECTED at " << simTime() << " by " << getFullPath() << endl;
        sendWarning();
        streamSent++;
        if (sendInterval > 0 && streamSent < numWarnings)
            scheduleAt(simTime() + sendInterval, accidentTimer);
    }

    else if (msg == ackTimeoutTimer) {
        numAckTimeouts++;
        EV_WARN << "AccidentApp: no AccidentAck within timeout -- treating current route as failed." << endl;
        reportDeliveryFailureToAodv();

        if (sendInterval == 0) {           // single-warning mode: one retry
            if (retryCount < MAX_RETRIES) {
                retryCount++;
                EV_INFO << "AccidentApp: retrying send (attempt " << retryCount << ")" << endl;
                sendWarning();
            }
            else {
                EV_WARN << "AccidentApp: retry limit reached, giving up." << endl;
            }
        }
    }

    else if (msg->isPacket()) {
        auto packet = check_and_cast<Packet *>(msg);
        std::string name = packet->getName();

        auto addressInd = packet->findTag<L3AddressInd>();
        L3Address sourceAddr = (addressInd != nullptr) ? addressInd->getSrcAddress() : L3Address();

        if (name == "AccidentWarning") {
            EV_INFO << "Received packet: " << name << endl;
            numWarningsReceived++;
            bytesReceived += packet->getByteLength();
            delaySum += (simTime() - packet->getCreationTime()).dbl();
            if (firstReceiveTime < 0)
                firstReceiveTime = simTime();
            lastReceiveTime = simTime();

            // Only a pure receiver acknowledges.
            if (destAddress.empty() && !sourceAddr.isUnspecified())
                sendAck(sourceAddr);
        }
        else if (name == "AccidentAck") {
            EV_INFO << "AccidentApp: delivery CONFIRMED via AccidentAck from " << sourceAddr << endl;
            numAcksReceived++;
            if (ackLatency < 0 && firstSendTime >= 0)
                ackLatency = simTime() - firstSendTime;
            if (ackTimeoutTimer->isScheduled())
                cancelEvent(ackTimeoutTimer);
        }
        else {
            EV_INFO << "Received packet: " << name << endl;
        }

        delete packet;
    }

    else {
        delete msg;
    }
}

// Experiment control (not part of the protocol): pick a random honest vehicle whose
// distance from this vehicle lies in [minDestDistance, maxDestDistance], so the route
// is multi-hop. Uses global positions from the simulation.
bool AccidentApp::chooseDestination()
{
    cModule *host = getContainingNode(this);
    auto myMob = check_and_cast<IMobility *>(host->getSubmodule("mobility"));
    Coord myPos = myMob->getCurrentPosition();

    std::vector<cModule *> candidates;
    std::vector<double> distances;
    cModule *network = host->getParentModule();
    for (cModule::SubmoduleIterator it(network); !it.end(); ++it) {
        cModule *other = *it;
        if (other == host || strcmp(other->getName(), "node") != 0)
            continue;
        auto mob = dynamic_cast<IMobility *>(other->getSubmodule("mobility"));
        if (mob == nullptr)
            continue;
        auto otherAodv = dynamic_cast<VanetAodv *>(other->getSubmodule("aodv"));
        if (otherAodv != nullptr && otherAodv->isBlackhole())
            continue;
        double d = myPos.distance(mob->getCurrentPosition());
        if (d >= minDestDistance && d <= maxDestDistance) {
            candidates.push_back(other);
            distances.push_back(d);
        }
    }

    destCandidates = candidates.size();
    if (candidates.empty()) {
        EV_WARN << "AccidentApp: no vehicle within [" << minDestDistance << ", "
                << maxDestDistance << "] m -- not sending." << endl;
        return false;
    }

    int k = intuniform(0, candidates.size() - 1);
    destL3 = L3AddressResolver().resolve(candidates[k]->getFullPath().c_str());
    destDistance = distances[k];
    EV_INFO << "AccidentApp: distance-band destination " << candidates[k]->getFullPath()
            << " (" << destL3 << ") at " << destDistance << " m, out of "
            << destCandidates << " candidates" << endl;
    return true;
}

void AccidentApp::sendWarning()
{
    if (!destChosen) {
        if (destAddress == "auto") {
            if (!chooseDestination())
                return;
        }
        else {
            destL3 = L3AddressResolver().resolve(destAddress.c_str());
        }
        destChosen = true;
    }

    auto packet = new Packet("AccidentWarning");
    auto payload = makeShared<BytesChunk>();
    std::vector<uint8_t> data(packetBytes, 0xAB);
    payload->setBytes(data);
    packet->insertAtBack(payload);

    numWarningsSent++;
    if (firstSendTime < 0)
        firstSendTime = simTime();

    socket.sendTo(packet, destL3, destPort);
    EV_INFO << "Emergency accident warning sent to " << destL3 << endl;

    if (sendInterval > 0) {
        // stream mode: the timer measures time since the oldest unacknowledged send
        if (!ackTimeoutTimer->isScheduled())
            scheduleAt(simTime() + ackTimeout, ackTimeoutTimer);
    }
    else {
        if (ackTimeoutTimer->isScheduled())
            cancelEvent(ackTimeoutTimer);
        scheduleAt(simTime() + ackTimeout, ackTimeoutTimer);
    }
}

void AccidentApp::sendAck(const L3Address& toAddr)
{
    auto ackPacket = new Packet("AccidentAck");
    auto payload = makeShared<BytesChunk>();
    std::vector<uint8_t> data(8, 0xCD);
    payload->setBytes(data);
    ackPacket->insertAtBack(payload);

    numAcksSent++;
    socket.sendTo(ackPacket, toAddr, destPort);
    EV_INFO << "AccidentApp: sent AccidentAck back to " << toAddr << endl;
}

void AccidentApp::reportDeliveryFailureToAodv()
{
    cModule *hostModule = getParentModule();
    cModule *aodvModule = hostModule != nullptr ? hostModule->getSubmodule("aodv") : nullptr;

    if (auto vanetAodv = dynamic_cast<VanetAodv *>(aodvModule)) {
        vanetAodv->reportDeliveryFailure(destL3);
        return;
    }
    if (auto trustAodv = dynamic_cast<TrustAwareAodv *>(aodvModule)) {
        trustAodv->reportDeliveryFailure(destL3);
        return;
    }
    EV_WARN << "AccidentApp: co-located aodv module has no detection." << endl;
}

void AccidentApp::handleStartOperation(LifecycleOperation *operation)
{
    socket.setOutputGate(gate("socketOut"));
    socket.bind(localPort);

    // Only nodes configured with a destAddress originate warnings.
    if (!destAddress.empty() && !accidentTimer->isScheduled())
        scheduleAt(simTime() + accidentTime, accidentTimer);
}

void AccidentApp::handleStopOperation(LifecycleOperation *operation)
{
    socket.close();
}

void AccidentApp::handleCrashOperation(LifecycleOperation *operation)
{
    socket.destroy();
}

void AccidentApp::finish()
{
    recordScalar("warningsSent", numWarningsSent);
    recordScalar("warningsReceived", numWarningsReceived);
    recordScalar("acksReceived", numAcksReceived);
    recordScalar("acksSent", numAcksSent);
    recordScalar("ackTimeouts", numAckTimeouts);
    recordScalar("bytesReceived", bytesReceived);
    recordScalar("e2eDelaySum", delaySum);
    if (firstReceiveTime >= 0)
        recordScalar("firstReceiveTime", firstReceiveTime);
    if (lastReceiveTime >= 0)
        recordScalar("lastReceiveTime", lastReceiveTime);
    if (ackLatency >= 0)
        recordScalar("ackLatency", ackLatency);
    if (destCandidates >= 0)
        recordScalar("destCandidates", destCandidates);
    if (destDistance >= 0)
        recordScalar("destDistance", destDistance);
    ApplicationBase::finish();
}
