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
#include <click/router.hh>
#include <click/task.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <click/userutils.hh>
#include <click/sync.hh>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
CLICK_DECLS


/*
=c

EmpowerScheduler(EL)

=s EmPOWER


=d

Schedules 802.11 frames following a DRR approach among the clients.
For that it allocates the packets in a different queue for each client.

Arguments are:

=item EL
An EmpowerLVAPManager element

=item DEBUG
Turn debug on/off

=back 8

=a EmpowerScheduler
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
	int _transmitted_packets;
	ReadWriteLock _mutex;
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
		_transmitted_packets = 0;
	}

	~EmpowerClientQueue() {
		_mutex.acquire_write();
		while(_nb_pkts > 0)
		{
			_packets[_head]->kill();
			_head = (_head + 1) % _max_size;
			_nb_pkts--;
		}
		_mutex.release_write();
	}
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
	void *cast(const char *);
	int initialize(ErrorHandler *);

	void push(int, Packet *);
	Packet *pull(int port);

	void add_handlers();

	LVAPQueues* lvap_queues() { return &_lvap_queues; }
	Vector <EtherAddress> rr_order() { return _rr_order; }
	int quantum_division() {return _quantum_div;}
	void compute_system_quantum(EtherAddress, int);
	int pkt_transmission_time(EtherAddress, int);

	void update_quantum(float new_quantum)
	{
		_quantum_div = new_quantum;
	}

	void request_queue(EtherAddress sta, EtherAddress lvap_bssid)
	{
		EmpowerClientQueue queue;

		queue._lvap = lvap_bssid;
		queue._sta = sta;

		_lvap_queues_mutex.acquire_write();
		_lvap_queues.set(lvap_bssid, queue);
		_rr_order.push_back(lvap_bssid);
		_empty_scheduler_queues++;
		_lvap_queues_mutex.release_write();

		click_chatter("%{element} :: %s :: ----- LVAP bssid %s sta %s added to SCHEDULER QUEUE. Size %d ----- ",
																			 this,
																			 __func__,
																			 lvap_bssid.unparse().c_str(),
																			 sta.unparse().c_str(),
																			 _lvap_queues.size());
	}

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
		ec->_mutex.acquire_write();
		while(ec->_nb_pkts > 0)
		{
			ec->_packets[ec->_head]->kill();
			ec->_head = (ec->_head + 1) % ec->_max_size;
			ec->_nb_pkts--;
		}
		ec->_mutex.release_write();

		// Delete the queue
		_lvap_queues_mutex.acquire_write();
		_lvap_queues.erase(ess->_lvap_bssid);
		// Delete it from the ordered queue
		_lvap_queues_mutex.release_write();
		int index = -1;
		_lvap_queues_mutex.acquire_write();
		for (int i = 0; i < _rr_order.size(); i++)
		{
			if (_rr_order.at(i) == ess->_lvap_bssid)
			{
				index = i;
				break;
			}
		}
		if (index != -1)
			_rr_order.erase(_rr_order.begin() + index);
		_lvap_queues_mutex.release_write();

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
	bool _debug;
	ActiveNotifier _notifier;
	ReadWriteLock _lvap_queues_mutex;

	static int write_handler(const String &, Element *, void *, ErrorHandler *);
	static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif /* ELEMENTS_EMPOWER_EMPOWERSCHEDULER_HH_ */
