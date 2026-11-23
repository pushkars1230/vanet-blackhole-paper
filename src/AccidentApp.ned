package vanet_blackhole;

import inet.applications.contract.IApp;

simple AccidentApp like IApp
{
    parameters:
        double accidentTime @unit(s) = default(5s);
        double ackTimeout @unit(s) = default(2s);
        int localPort = default(5000);
        int destPort = default(5000);
        string destAddress = default("");
        double minDestDistance @unit(m) = default(400m);  // used when destAddress == "auto"
        double maxDestDistance @unit(m) = default(700m);
        double sendInterval @unit(s) = default(0s);   // 0s = single warning with one retry
        int numWarnings = default(1);                  // packets sent in stream mode
        int packetBytes = default(100);                // payload size
        @class(AccidentApp);
        @display("i=block/app");
    gates:
        input socketIn;
        output socketOut;
}
