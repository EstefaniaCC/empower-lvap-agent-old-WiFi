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
	int _head = 0;
	int _tail = 0;
	static const  int _max_size = 1000;
	int _nb_pkts;
	Packet* _packets[_max_size];
	int _quantum;
	bool _first_pkt;
	enum empower_phy_types _phy;
};

enum empower_phy_types {
    EMPOWER_PHY_80211a = 0x00,
    EMPOWER_PHY_80211b = 0x01,
	EMPOWER_PHY_80211g = 0x02
};

class TransmissionTime {
public:
	int _plcp_preamb;
	int _plcp_header;
	int _mac_header_body;
	int _ack_mac_header;
	int _sifs;
	int _difs;
	int _slot_time;
	int _cw_min;
	int _cw_max;

	TransmissionTime (int plcp_reamb, int plcp_header, int mac_header_body, int ack_mac_header,
		int sifs, int difs, int slot_time, int cw_min, int cw_max) {
		_plcp_preamb = plcp_reamb; // microsec
		_plcp_header = plcp_header;
		_mac_header_body = mac_header_body;
		_ack_mac_header = ack_mac_header;
		_sifs = sifs;
		_difs = difs;
		_slot_time = slot_time;
		_cw_min = cw_min;
		_cw_max = cw_max;
	}
};


/*
class TransmissionTime {
public:
	int _sifs;
	int _difs;
	int _slot_time;
	int _cw_min;
	int _cw_max;

TransmissionTime::TransmissionTime(int sifs, int difs, int slot_time, int cw_min, int cw_max) {
		_sifs = sifs;
		_difs = difs;
		_slot_time = slot_time;
		_cw_min = cw_min;
		_cw_max = cw_max;
	}
};
*/

typedef HashTable<EtherAddress, EmpowerClientQueue> LVAPQueues;
typedef LVAPQueues::iterator LVAPQueuesIter;

typedef HashTable<enum empower_phy_types, TransmissionTime> TransmissionTimes;
typedef TransmissionTimes::iterator TransmissionTimesIter;

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
	Packet* schedule_packet();
	float quantum_division() {return _quantum_div;}
	float pkt_transmission_time(EtherAddress, Packet *);


	void update_quantum(float new_quantum)
	{
		_quantum_div = new_quantum;
	}

	void add_queue_order(EtherAddress sta)
	{
		_rr_order.push_back(sta);
	}

	MinstrelDstInfo * get_dst_info(EtherAddress sta){
		MinstrelDstInfo * nfo =_rc->neighbors()->findp(sta);
		return nfo;
	}

	void release_queue(EtherAddress sta)
	{
		EmpowerClientQueue *ec = _lvap_queues.get_pointer(sta);
		// Delete all the remaining packets in the queue
		while(ec->_nb_pkts > 0)
		{
			ec->_packets[ec->_head]->kill();
			ec->_head = (ec->_head + 1) % ec->_max_size;
			ec->_nb_pkts--;
		}
		// Delete the queue
		_lvap_queues.erase(sta);
		// Delete it from the ordered queue
		int index = -1;
		for (int i = 0; i < _rr_order.size(); i++)
		{
			if (_rr_order.at(0) == sta)
			{
				index = i;
				break;
			}
		}
		_rr_order.erase(_rr_order.begin() + index);
	}


private:
	class Minstrel * _rc;
	Vector<Minstrel *> _rcs;
	LVAPQueues _lvap_queues;
	Vector <EtherAddress> _rr_order;
	float _quantum_div = 1000; // 1000 microseconds
	int _empty_scheduler_queues = 0;
	TransmissionTimes _waiting_times;

	bool _debug;
	ActiveNotifier _notifier;

	static int write_handler(const String &, Element *, void *, ErrorHandler *);
	static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif /* ELEMENTS_EMPOWER_EMPOWERSCHEDULER_HH_ */
