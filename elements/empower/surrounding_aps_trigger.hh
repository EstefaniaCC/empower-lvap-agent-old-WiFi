#ifndef CLICK_EMPOWER_SUMMARY_HH
#define CLICK_EMPOWER_SUMMARY_HH
#include <click/straccum.hh>
#include <click/hashcode.hh>
#include <click/timer.hh>
#include <click/vector.hh>
#include "trigger.hh"
#include "frame.hh"
CLICK_DECLS

typedef Vector<Frame> FramesList;
typedef FramesList::iterator FIter;

class SurroundingApsTrigger: public Trigger {

public:

	EtherAddress _ap;
	int _iface;
	uint32_t _sent;
	int16_t _limit;
	FramesList _frames;

	SurroundingApsTrigger(int, EtherAddress, uint32_t, int16_t, uint16_t, EmpowerLVAPManager *, EmpowerCollisionSniffer *);
	~SurroundingApsTrigger();

	String unparse();

	inline bool operator==(const SummaryTrigger &b) {
		return (_iface == b._iface) && (_eth == b._eth);
	}

};

CLICK_ENDDECLS
#endif /* CLICK_EMPOWER_SUMMARY_HH */
