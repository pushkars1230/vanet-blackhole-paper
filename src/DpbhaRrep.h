//
// DpbhaRrep.h -- an RREP that also carries the address of the node that created it.
// DPBHA grey-lists and blacklists the replier; at the source the L3 sender is only
// the last hop. Simulation shortcut: no extra bytes are charged (chunk stays 20 B).
// Plain C++ subclass instead of a .msg file, so no message-compiler imports are needed.
//
#ifndef __VANET_BLACKHOLE_DPBHARREP_H
#define __VANET_BLACKHOLE_DPBHARREP_H

#include "inet/routing/aodv/AodvControlPackets_m.h"

class DpbhaRrep : public inet::aodv::Rrep
{
  protected:
    inet::L3Address replierAddr;

  public:
    DpbhaRrep() : inet::aodv::Rrep() {}
    DpbhaRrep(const DpbhaRrep& other) = default;
    virtual DpbhaRrep *dup() const override { return new DpbhaRrep(*this); }

    const inet::L3Address& getReplierAddr() const { return replierAddr; }
    void setReplierAddr(const inet::L3Address& a) { handleChange(); replierAddr = a; }
};

#endif
