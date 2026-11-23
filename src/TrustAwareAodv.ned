//
// TrustAwareAodv.ned
// Same parameters and gates as INET's Aodv -- only the C++ behavior
// (detection + blacklist-based mitigation) differs.
//
package vanet_blackhole;

import inet.routing.aodv.Aodv;

simple TrustAwareAodv extends Aodv
{
    parameters:
        @class(TrustAwareAodv);
        @display("i=block/network2;is=s;i2=status/check");
}
