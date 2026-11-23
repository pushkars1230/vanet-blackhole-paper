//
// BlackholeAodvRouter.ned
// Identical to INET's AodvRouter, except the aodv submodule is
// BlackholeAodv instead of Aodv. Used only for the node(s) designated
// malicious in the BlackholeAttack config.
//
package vanet_blackhole;

import inet.node.inet.AdhocHost;

module BlackholeAodvRouter extends AdhocHost
{
    submodules:
        aodv: BlackholeAodv {
            @display("p=825,226");
        }
    connections:
        aodv.socketOut --> at.in++;
        aodv.socketIn <-- at.out++;
}
