/*
 * empowerscheduler.hh
 *
 *  Created on: May 15, 2017
 *      Author: estefania
 */

#ifndef ELEMENTS_EMPOWER_EMPOWERSCHEDULER_HH_
#define ELEMENTS_EMPOWER_EMPOWERSCHEDULER_HH_

#include <click/config.h>
#include <click/element.hh>
#include <clicknet/ether.h>
#include <click/etheraddress.hh>
#include <click/straccum.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <click/notifier.hh>
#include <click/packet_anno.hh>
#include <clicknet/wifi.h>
#include <clicknet/llc.h>
#include <clicknet/ether.h>
#include <clicknet/wifi.h>
#include <elements/wifi/minstrel.hh>
CLICK_DECLS


/*
=c

EmpowerScheduler(EL)

=s EmPOWER

Converts Ethernet packets to 802.11 packets with a LLC header. Setting
the appropriate BSSID given the destination address. An EmPOWER Access
Point generates one virtual BSSID called LVAP for each active station.

=d

Strips the Ethernet header off the front of the packet and pushes
an 802.11 frame header and LLC header onto the packet.

Arguments are:

=item EL
An EmpowerLVAPManager element

=item DEBUG
Turn debug on/off

=back 8

=a EmpowerWifiDecap
*/



class EmpowerClientQueue {
public:
	EtherAddress _sta;
	//Vector <Packet*> _packets;
	int _head = 0;
	int _tail = 0;
	int _max_size = 1000;
	int _nb_pkts = 0;
	Packet* _packets[_max_size] = {};
	int _quantum;
};

typedef HashTable<EtherAddress, EmpowerClientQueue> LVAPQueues;
typedef LVAPQueues::iterator LVAPQueuesIter;

class EmpowerScheduler: public Element {
public:

	EmpowerScheduler();
	~EmpowerScheduler();

	const char *class_name() const { return "EmpowerScheduler"; }
	const char *port_count() const { return PORTS_1_1; }
	const char *processing() const { return PUSH_TO_PULL; }

	int configure(Vector<String> &, ErrorHandler *);
	void push(int, Packet *);
	Packet *pull(int port);
	void add_handlers();
	LVAPQueues* lvap_queues() { return &_lvap_queues; }
	Vector * rr_order(){return &_rr_order;}
	Packet* schedule_packet();
	float quantum_division() {return _quantum_div;}

	void update_quantum(float new_quantum)
	{
		_quantum_div = new_quantum;
	}

	void add_queue_order(EtherAddress sta)
	{
		_rr_order.push_back(sta);
	}

	void remove_queue_order(EtherAddress sta)
	{
		_rr_order.erase(sta);
	}

	MinstrelDstInfo * get_dst_info(EtherAddress sta){
		//EmpowerStationState *ess = _lvaps.get_pointer(sta);
		//MinstrelDstInfo * nfo = _rcs.at(ess->_iface_id)->neighbors()->findp(sta);
		//return nfo;
		MinstrelDstInfo * nfo =_rc->neighbors()->findp(sta);
		return nfo;
	}


private:

	//class EmpowerLVAPManager *_el;
	class Minstrel * _rc;
	Vector<Minstrel *> _rcs;
	LVAPQueues _lvap_queues;
	Vector <EtherAddress> _rr_order;
	float _quantum_div = 1000; // 1000 microseconds
	int _empty_scheduler_queues = 0;

	bool _debug;
	ActiveNotifier _notifier;

	//Packet *wifi_encap(Packet *, EtherAddress, EtherAddress, EtherAddress);

	static int write_handler(const String &, Element *, void *, ErrorHandler *);
	static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif /* ELEMENTS_EMPOWER_EMPOWERSCHEDULER_HH_ */
