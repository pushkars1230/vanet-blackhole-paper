//
// TrustAwareAodvRouter.ned
// Identical to INET's AodvRouter, except the aodv submodule is
// TrustAwareAodv instead of Aodv. Used only for the source vehicle in
// the mitigation-enabled config.
//
package vanet_blackhole;

import inet.node.inet.AdhocHost;

module TrustAwareAodvRouter extends AdhocHost
{
    submodules:
        aodv: TrustAwareAodv {
            @display("p=825,226");
        }
    connections:
        aodv.socketOut --> at.in++;
        aodv.socketIn <-- at.out++;
}
