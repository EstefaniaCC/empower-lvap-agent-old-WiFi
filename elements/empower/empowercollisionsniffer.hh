/*
 * empowercollisionsniffer.hh
 *
 *  Created on: Jun 8, 2017
 *      Author: estefania
 */

#ifndef ELEMENTS_EMPOWER_EMPOWERCOLLISIONSNIFFER_HH_
#define ELEMENTS_EMPOWER_EMPOWERCOLLISIONSNIFFER_HH_

#include <click/element.hh>
#include <click/config.h>
#include <elements/wifi/availablerates.hh>
#include <click/etheraddress.hh>
#include <click/hashtable.hh>
#include <click/glue.hh>
#include <click/timer.hh>
#include <click/straccum.hh>
#include <clicknet/wifi.h>
#include <click/sync.hh>
#include "empowerpacket.hh"
#include "domaininfo.hh"
CLICK_DECLS

/*
=c

EmpowerCollisionSniffer(EL, [, I<KEYWORDS>])

=s EmPOWER

Detect issues related to collision domains between APs

=d

Keyword arguments are:

=over 8

=item EL
An EmpowerLVAPManager element

=item DEBUG
Turn debug on/off

=back 8

=a EmpowerLVAPManager
*/

typedef HashTable<EtherAddress, DomainInfo> SurroundingAPsTable;
typedef SurroundingAPsTable::iterator SAIter;

class EmpowerCollisionSniffer: public Element {
public:

	EmpowerCollisionSniffer();
	~EmpowerCollisionSniffer();

	const char *class_name() const { return "EmpowerCollisionSniffer"; }
	const char *port_count() const { return "1/1"; }
	const char *processing() const { return AGNOSTIC; }

	int initialize(ErrorHandler *);
	int configure(Vector<String> &, ErrorHandler *);
	void run_timer(Timer *);

	void add_handlers();
	Packet *simple_action(Packet *);

	void add_surrounding_aps_trigger(int, EtherAddress, uint32_t, int16_t, uint16_t);
	void del_surrounding_aps_trigger(uint32_t);

	ReadWriteLock lock;
	SurroundingAPsTable aps;

private:

	class EmpowerLVAPManager *_el;
	Timer _timer;

	bool _debug;

	// Read/Write handlers
	static String read_handler(Element *e, void *user_data);
	static int write_handler(const String &, Element *, void *, ErrorHandler *);

	void update_surrounding_aps(EtherAddress, int16_t, uint8_t, String);

};

CLICK_ENDDECLS

#endif /* ELEMENTS_EMPOWER_EMPOWERCOLLISIONSNIFFER_HH_ */
