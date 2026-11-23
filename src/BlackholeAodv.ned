//
// BlackholeAodv.ned
// Same parameters as INET's Aodv -- only the C++ behavior (dropping
// forwarded data) differs.
//
package vanet_blackhole;

import inet.routing.aodv.Aodv;

simple BlackholeAodv extends Aodv
{
    parameters:
        @class(BlackholeAodv);
        @display("i=block/network2;is=s;i2=status/stop");
}
