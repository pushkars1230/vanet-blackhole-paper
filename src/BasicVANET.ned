package vanet_blackhole;

import inet.node.aodv.AodvRouter;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.physicallayer.wireless.common.medium.RadioMedium;
import inet.node.contract.INetworkNode;

network BasicVANET
{
    parameters:
        @display("bgb=1000,600");

    submodules:
        radioMedium: RadioMedium {
            @display("p=100,100");
        }

        configurator: Ipv4NetworkConfigurator {
            @display("p=100,200");
        }

        // Source
        vehicle0: <default("inet.node.aodv.AodvRouter")> like INetworkNode {
          parameters:
              numApps = 1;
              app[0].typename = "vanet_blackhole.AccidentApp";
              app[0].accidentTime = 5s;
              app[0].localPort = 5000;
              app[0].destPort = 5000;
              app[0].destAddress = "vehicle2";
          @display("p=200,250");

        }

        // Malicious node
        vehicle1: <default("inet.node.aodv.AodvRouter")> like INetworkNode {
            @display("p=500,250");
        }

        // Destination
        vehicle2: AodvRouter {
            parameters:
                numApps = 1;
                app[0].typename = "vanet_blackhole.AccidentApp";
                app[0].localPort = 5000;
                app[0].destPort = 5000;
            @display("p=500,500");
        }

        // Legitimate alternate-path relay
        vehicle3: AodvRouter {
            @display("p=200,500");
        }
}