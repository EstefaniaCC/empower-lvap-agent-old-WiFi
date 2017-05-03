// -*- mode: c++; c-basic-offset: 2 -*-
#ifndef CLICK_EMPOWERBEACONSOURCE_HH
#define CLICK_EMPOWERBEACONSOURCE_HH
#include <click/element.hh>
#include <click/config.h>
#include <click/timer.hh>
#include <elements/wifi/availablerates.hh>
CLICK_DECLS

/*
=c

EmpowerBeaconSource(RT, EL[, I<KEYWORDS>])

=s EmPOWER

Send 802.11 beacons. Notice that in the EmPOWER architecture beacons
are unicast. The EL element keeps track of the known stations. Probe
requests from unknown stations are sent to the Access Controller. If
the station is authorized then a new Ligh Virtual Access Point (LVAP)
is spawned and the probe request is generated by the Wireless Termination
Point (WTP). Subsequent probe request are directly handled by the WTP.

=d

Keyword arguments are:

=over 8

=item RT
An AvailableRates element

=item EL
An EmpowerLVAPManager element

=item CHANNEL
The wireless channel it is operating on.

=item PERIOD
How often beacon packets are sent, in milliseconds.

=item DEBUG
Turn debug on/off

=back 8

=a EmpowerLVAPManager
*/

class EmpowerBeaconSource: public Element {
public:

	EmpowerBeaconSource();
	~EmpowerBeaconSource();

	const char *class_name() const { return "EmpowerBeaconSource"; }
	const char *port_count() const { return "1/1"; }
	const char *processing() const { return PUSH; }

	int initialize(ErrorHandler *);
	int configure(Vector<String> &, ErrorHandler *);
	void add_handlers();
	void run_timer(Timer *);

	void send_beacon(EtherAddress, EtherAddress, String, int, int, bool, bool, int, int);

	void push(int, Packet *);

private:

	class EmpowerLVAPManager *_el;

	unsigned int _period; // msecs
	Timer _timer;

	bool _debug;

	// Read/Write handlers
	static String read_handler(Element *e, void *user_data);
	static int write_handler(const String &, Element *, void *, ErrorHandler *);

};

CLICK_ENDDECLS
#endif
