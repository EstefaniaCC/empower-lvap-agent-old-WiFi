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
#include <elements/wifi/bitrate.hh>
#include <elements/standard/counter.hh>
#include <elements/wifi/transmissionpolicy.hh>
#include <elements/wifi/availablerates.hh>
#include <include/clicknet/radiotap.h>
#include <click/confparse.hh>
#include <click/vector.hh>
#include <click/hashtable.hh>
#include "empowerpacket.hh"
#include "empowerrxstats.hh"
#include "empowercqm.hh"
#include "empowerscheduler.hh"
#include "empowerlvapmanager.hh"
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

/*enum empower_phy_types {
    EMPOWER_PHY_80211a = 0x00,
    EMPOWER_PHY_80211b = 0x01,
	EMPOWER_PHY_80211g = 0x02
};
*/

class EmpowerClientQueue {
public:
	EtherAddress _lvap;
	EtherAddress _sta;
	int _head;
	int _tail;
	int _max_size;
	int _nb_pkts;
	Packet** _packets;
	int _quantum;
	bool _first_pkt;
	int _total_consumed_time;
	int _dropped_packets;
	//enum empower_phy_types _phy;

	EmpowerClientQueue() {
		_lvap = EtherAddress();
		_sta = EtherAddress();;
		_head = 0;
		_tail = 0;
		_max_size = 1000;
		_nb_pkts = 0;
		_packets = new Packet*[_max_size];
		_quantum = 0;
		_first_pkt = true;
		_total_consumed_time = 0;
		_dropped_packets = 0;
	}

	~EmpowerClientQueue() {
		while(_nb_pkts > 0)
		{
			_packets[_head]->kill();
			_head = (_head + 1) % _max_size;
			_nb_pkts--;
		}
	}
};

/*
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
*/


typedef HashTable<EtherAddress, EmpowerClientQueue> LVAPQueues;
typedef LVAPQueues::iterator LVAPQueuesIter;

//typedef HashTable<int, TransmissionTime*> TransmissionTimes;
//typedef TransmissionTimes::iterator TransmissionTimesIter;

class EmpowerScheduler: public Element {
public:

	EmpowerScheduler();
	~EmpowerScheduler();

	const char *class_name() const { return "EmpowerScheduler"; }
	const char *port_count() const { return PORTS_1_1; }
	const char *processing() const { return PUSH_TO_PULL; }

	int configure(Vector<String> &, ErrorHandler *);
	//void *cast(const char *);
	int initialize(ErrorHandler *);

	void push(int, Packet *);
	Packet *pull(int port);

	void add_handlers();

	LVAPQueues* lvap_queues() { return &_lvap_queues; }
	int quantum_division() {return _quantum_div;}
	int emtpy_scheduler_queues() {return _empty_scheduler_queues;}
	void compute_system_quantum(EtherAddress, int);
	int pkt_transmission_time(EtherAddress, int);

	void update_quantum(float new_quantum)
	{
		_quantum_div = new_quantum;
	}

	void add_queue_order(EtherAddress lvap_bssid)
	{
		_rr_order.push_back(lvap_bssid);
		_empty_scheduler_queues++;
	}

	/*MinstrelDstInfo * get_dst_info(EtherAddress sta){
		MinstrelDstInfo * nfo =_rc->neighbors()->findp(sta);
		return nfo;
	}*/

	void release_queue(EtherAddress sta)
	{
		EmpowerStationState *ess = _el->lvaps()->get_pointer(sta);
		if (!ess) {
			click_chatter("%{element} :: %s :: unknown LVAP %s ignoring",
						  this,
						  __func__,
						  sta.unparse_colon().c_str());
			return;
		}

		EmpowerClientQueue *ec = _lvap_queues.get_pointer(ess->_lvap_bssid);

		if (!ec) {
			click_chatter("%{element} :: %s :: UNAVAILABLE QUEUE FOR LVAP corresponding to sta %s",
						  this,
						  __func__,
						  sta.unparse_colon().c_str());
			return;
		}

		// Delete all the remaining packets in the queue

		click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. All the packets in queue %s are going to be destroyed ----- ",
																					 this,
																					 __func__,
																					 ess->_lvap_bssid.unparse().c_str());
		while(ec->_nb_pkts > 0)
		{
			ec->_packets[ec->_head]->kill();
			ec->_head = (ec->_head + 1) % ec->_max_size;
			ec->_nb_pkts--;
		}
		// Delete the queue
		_lvap_queues.erase(ess->_lvap_bssid);
		// Delete it from the ordered queue
		int index = -1;
		for (int i = 0; i < _rr_order.size(); i++)
		{
			if (_rr_order.at(0) == ess->_lvap_bssid)
			{
				index = i;
				break;
			}
		}
		_rr_order.erase(_rr_order.begin() + index);

		click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. Packets in queue %s destroyed and queue erased ----- ",
																							 this,
																							 __func__,
																							 ess->_lvap_bssid.unparse().c_str());
	}


private:
	class EmpowerLVAPManager *_el;
	LVAPQueues _lvap_queues;
	Vector <EtherAddress> _rr_order;
	int _quantum_div; // 1000 microseconds
	int _empty_scheduler_queues;
	//TransmissionTimes _waiting_times;
	//int _next;
	bool _debug;
	ActiveNotifier _notifier;

	static int write_handler(const String &, Element *, void *, ErrorHandler *);
	static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif /* ELEMENTS_EMPOWER_EMPOWERSCHEDULER_HH_ */
