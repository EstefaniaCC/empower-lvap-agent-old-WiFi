/*
 * empowerscheduler.cc
 *
 *  Created on: May 15, 2017
 *      Author: estefania
 */

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
#include <elements/standard/counter.hh>
#include <elements/wifi/transmissionpolicy.hh>
#include <elements/wifi/availablerates.hh>
#include <include/clicknet/radiotap.h>
#include <click/vector.hh>
#include <click/hashtable.hh>
#include "empowerpacket.hh"
#include "empowerrxstats.hh"
#include "empowercqm.hh"
#include "empowerscheduler.hh"
#include "empowerlvapmanager.hh"
#include <elements/wifi/bitrate.hh>
#include <click/straccum.hh>
#include <click/confparse.hh>
#include <click/router.hh>
#include <click/task.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <click/userutils.hh>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
CLICK_DECLS


EmpowerScheduler::EmpowerScheduler() :
	_el(0), _debug(false) {
}

EmpowerScheduler::~EmpowerScheduler() {
}

int EmpowerScheduler::configure(Vector<String> &conf,
		ErrorHandler *errh) {

	_notifier.initialize(Notifier::EMPTY_NOTIFIER, router());

	return Args(conf, this, errh)
			.read_m("EL", ElementCastArg("EmpowerLVAPManager"), _el)
			.read("DEBUG", _debug)
			.complete();

}

void *
EmpowerScheduler::cast(const char *n)
{
    if (strcmp(n, Notifier::EMPTY_NOTIFIER) == 0)
    	return static_cast<Notifier *>(&_notifier);
    else
    	return Element::cast(n);
}

int EmpowerScheduler::initialize(ErrorHandler *) {
	_quantum_div = 0;
	_empty_scheduler_queues = 0;
	_notifier.initialize(Notifier::EMPTY_NOTIFIER, router());

	return 0;
}

void
EmpowerScheduler::push(int, Packet *p) {

	if (p->length() < sizeof(struct click_wifi)) {
			click_chatter("%{element} :: %s :: packet too small: %d vs %d",
					      this,
						  __func__,
						  p->length(),
						  sizeof(struct click_ether));
			p->kill();
			return;
		}

	struct click_wifi *w = (struct click_wifi *) p->data();
	EtherAddress dst = EtherAddress(w->i_addr3);
	EtherAddress bssid = EtherAddress(w->i_addr2);


	// Let's assume only downlink traffic. The destination should be the client.
	EmpowerClientQueue * ecq = _lvap_queues.get_pointer(bssid);

	/*if (!ecq) {
		p->kill();
		return;
	}
	*/

	ecq->_mutex.acquire_write();
	if (ecq->_nb_pkts == ecq->_max_size)
	{
		click_chatter("%{element} :: %s :: Packets buffer is full for station %s. Dropped packets %d. Nb_pkts %d",
							  this,
							  __func__,
							  dst.unparse().c_str(),
							  ecq->_dropped_packets,
							  ecq->_nb_pkts);
		ecq->_dropped_packets++;
		p->kill();
		return;
	}
	ecq->_mutex.release_write();

	ecq->_mutex.acquire_write();
	if (_empty_scheduler_queues > 0 && ecq->_nb_pkts == 0)
		_empty_scheduler_queues--;

	ecq->_packets[ecq->_tail] = p;
	ecq->_tail = (ecq->_tail + 1) % ecq->_max_size;
	ecq->_nb_pkts++;
	click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. New push packet in queue %s. Nb packets now %d. Empty queues %d ----- ",
																						 this,
																						 __func__,
																						 dst.unparse().c_str(),
																						 ecq->_nb_pkts,
																						 _empty_scheduler_queues);
	ecq->_mutex.release_write();

	_notifier.wake();
}


Packet *
EmpowerScheduler::pull(int)
{
	bool delivered_packet = false;

	_lvap_queues_mutex.acquire_read();
	if (_lvap_queues.size() == _empty_scheduler_queues)
	{
		_notifier.sleep();
		click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. Go to sleep damn. emtpy queues %d ----- ",
																								 this,
																								 __func__,
																								 _empty_scheduler_queues);
		_lvap_queues_mutex.release_read();
		return 0;
	}
	_lvap_queues_mutex.release_read();

	while (!delivered_packet && _lvap_queues.size() != _empty_scheduler_queues)
	{

		EtherAddress lvap_next_delireved_client = _rr_order.front();
		EmpowerClientQueue * queue =  _lvap_queues.get_pointer(lvap_next_delireved_client);

		queue->_mutex.acquire_write();
		if (queue->_nb_pkts > 0 )
		{
			Packet * next_packet = queue->_packets[queue->_head];

			if (queue->_first_pkt)
			{
				if (_quantum_div == 0)
				{
					compute_system_quantum(queue->_sta, 1460);
				}

				queue->_quantum += _quantum_div;
				queue->_first_pkt = false;

			}
			// compute time
			int estimated_transm_time = pkt_transmission_time(queue->_sta, (int)next_packet->length());

			if (queue->_quantum >= estimated_transm_time)
			{
				delivered_packet = true;
				queue->_head = (queue->_head + 1) % queue->_max_size;
				queue->_nb_pkts--;
				queue->_quantum -= estimated_transm_time;
				queue->_total_consumed_time += estimated_transm_time;
				queue->_transmitted_packets++;

				click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. PULL. Packet transmitted in queue  %s. Remaining quantum %d. Remaining packets %d Total consumed time %d. Total transm packets %d---- ",
																														 this,
																														 __func__,
																														 lvap_next_delireved_client.unparse().c_str(),
																														 queue->_quantum,
																														 queue->_nb_pkts,
																														 queue->_total_consumed_time,
																														 queue->_transmitted_packets);

				if (queue->_nb_pkts == 0 )
				{
					queue->_quantum = 0;
					_empty_scheduler_queues ++;
					click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. PULL. No packets in queue lvap %s. Emtpy queues %d. ----- ",
																									 this,
																									 __func__,
																									 lvap_next_delireved_client.unparse().c_str(),
																									 _empty_scheduler_queues);

				}

				return next_packet;
			}
		}
		queue->_first_pkt = true;
		queue->_mutex.release_write();
		_lvap_queues_mutex.acquire_write();
		_rr_order.push_back(lvap_next_delireved_client);
		_rr_order.pop_front();
		_lvap_queues_mutex.release_write();
	}
	return 0;
}

void EmpowerScheduler::compute_system_quantum(EtherAddress sta, int pkt_length)
{
		EmpowerStationState *ess = _el->lvaps()->get_pointer(sta);
		TxPolicyInfo * tx_policy = _el->get_tx_policies(ess->_iface_id)->lookup(sta);
		int lowest_rate = tx_policy->_mcs[0];
		int nb_retransm = 0;

		int transm_time = (int) calc_transmit_time(lowest_rate, pkt_length);
		int backoff = (int) calc_backoff(lowest_rate, nb_retransm);
		int total_time = (int) calc_usecs_wifi_packet(pkt_length, lowest_rate, nb_retransm);

		_quantum_div = total_time;
}


int EmpowerScheduler::pkt_transmission_time(EtherAddress next_delireved_client, int pkt_length)
{
	MinstrelDstInfo * nfo = _el->get_dst_info(next_delireved_client);
	int rate, nb_retransm, success_prob;

	if (nfo)
	{
		rate = (nfo->rates[nfo->max_tp_rate]);
		// Probabilities must be divided by 180 to obtain a percentage 97.88
		success_prob = nfo->probability[nfo->max_tp_rate];
		// To obtain the number of retransmissions, it must be 1/(percentg./100) -> 180*100 = 18000
		if (success_prob != 0)
		{
			success_prob = 18000/success_prob;
			nb_retransm = (int) ((1 / success_prob) + 0.5); // To truncate properly
			// In case the nb_transm is higher than 1 it is also considering the first transm
			// For example... prob success = 0.8 -> 1/0.8 = 1.25. It will sent the packets, 1.25 times.
			// When truncating it becomes 1, but the number of retransmissions is 0. The first one is the transmission.
			if (nb_retransm >= 1)
				nb_retransm --;
		}
		else
			nb_retransm = 0;
	}
	else
	{
		EmpowerStationState *ess = _el->lvaps()->get_pointer(next_delireved_client);
		TxPolicyInfo * tx_policy = _el->get_tx_policies(ess->_iface_id)->lookup(next_delireved_client);

		rate = tx_policy->_mcs[0];
		nb_retransm = 0;
	}

	int transm_time = (int) calc_transmit_time(rate, pkt_length);
	int backoff = (int) calc_backoff(rate, nb_retransm);
	int total_time = (int) calc_usecs_wifi_packet(pkt_length, rate, nb_retransm);

	click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. Rate %d, nb_retrans %d length %d transm_time %d, backoff %d, total_time %d success_prob %d----- ",
																					 this,
																					 __func__,
																					 rate,
																					 nb_retransm,
																					 pkt_length,
																					 transm_time,
																					 backoff,
																					 total_time,
																					 success_prob);
	return total_time;
}

enum {
	H_DEBUG,
	H_LVAP_QUEUES,
	H_QUEUES_ORDER
};

String EmpowerScheduler::read_handler(Element *e, void *thunk) {
	EmpowerScheduler *td = (EmpowerScheduler *) e;
	switch ((uintptr_t) thunk) {
	case H_DEBUG:
		return String(td->_debug) + "\n";
	case H_LVAP_QUEUES: {
		StringAccum sa;
		for (LVAPQueuesIter it = td->lvap_queues()->begin(); it.live(); it++) {
			sa << "sta ";
			sa << it.value()._sta.unparse();
			sa << " lvap_bssid ";
			sa << it.value()._lvap.unparse();
			sa << " head ";
			sa << it.value()._head;
			sa << " tail ";
			sa << it.value()._tail;
			sa << " dropped_packets ";
			sa << it.value()._dropped_packets;
			sa << " nb_pkts ";
			sa << it.value()._nb_pkts;
			sa << " quantum ";
			sa << it.value()._quantum;
			sa << " consumed_time ";
			sa << it.value()._total_consumed_time;
			sa << " first_pkt ";
			sa << it.value()._first_pkt;
			sa << " transmitted_packets ";
			sa << it.value()._transmitted_packets;
			sa << "\n";
		}

		return sa.take_string();
	}
	case H_QUEUES_ORDER: {
		StringAccum sa;
		for (int i = 0; i < td->rr_order().size(); i++) {
			sa << "sta ";
			sa << td->rr_order().at(i).unparse();
			sa << "\n";
		}

		return sa.take_string();
	}
	default:
		return String();
	}
}

int EmpowerScheduler::write_handler(const String &in_s, Element *e,
		void *vparam, ErrorHandler *errh) {

	EmpowerScheduler *f = (EmpowerScheduler *) e;
	String s = cp_uncomment(in_s);

	switch ((intptr_t) vparam) {
	case H_DEBUG: {    //debug
		bool debug;
		if (!BoolArg().parse(s, debug))
			return errh->error("debug parameter must be boolean");
		f->_debug = debug;
		break;
	}
	}
	return 0;
}

void EmpowerScheduler::add_handlers() {
	add_read_handler("debug", read_handler, (void *) H_DEBUG);
	add_read_handler("lvap_queues", read_handler, (void *) H_LVAP_QUEUES);
	add_read_handler("queues_order", read_handler, (void *) H_QUEUES_ORDER);
	add_write_handler("debug", write_handler, (void *) H_DEBUG);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(EmpowerScheduler)
ELEMENT_REQUIRES(userlevel)


