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
CLICK_DECLS


EmpowerScheduler::EmpowerScheduler() :
	_el(0), _debug(false) {
}

EmpowerScheduler::~EmpowerScheduler() {
	/*

	TransmissionTime* phya = new TransmissionTime(16, 24, 12246, 134, 16, 34, 9, 15, 1023);
	TransmissionTime* phyb = new TransmissionTime(72, 48, 12224, 112, 10, 50, 20, 31, 1023);
	TransmissionTime* phyg = new TransmissionTime(16, 24, 12246, 134, 10, 50, 20, 31, 1023);

	_waiting_times.set((int)EMPOWER_PHY_80211a, phya);
	_waiting_times.set((int)EMPOWER_PHY_80211b, phyb);
	_waiting_times.set((int)EMPOWER_PHY_80211g, phyg);
	*/

}

int EmpowerScheduler::configure(Vector<String> &conf,
		ErrorHandler *errh) {

	_notifier.initialize(Notifier::EMPTY_NOTIFIER, router());

	return Args(conf, this, errh)
			.read_m("EL", ElementCastArg("EmpowerLVAPManager"), _el)
			.read("DEBUG", _debug)
			.complete();

}

/*void *
EmpowerScheduler::cast(const char *n) {
	if (strcmp(n, "EmpowerScheduler") == 0)
		return (EmpowerScheduler *) this;
	else if (strcmp(n, Notifier::EMPTY_NOTIFIER) == 0)
		return static_cast<Notifier *>(&_notifier);
}
*/

int EmpowerScheduler::initialize(ErrorHandler *) {
	_empty_scheduler_queues = 0;
	_quantum_div = 0;

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
	EmpowerStationState *ess = _el->lvaps()->get_pointer(dst);

	if (!ess) {
		p->kill();
		return;
	}

	// Let's assume only downlink traffic. The destination should be the client.
	EmpowerClientQueue * ecq = _lvap_queues.get_pointer(ess->_lvap_bssid);

	if (!ecq) {
		p->kill();
		return;
	}


	/*
	if (!ecq->_phy)
	{
		struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);
		// In case the OFDM modulation is not found, this is a 11b client
		if (!(ceh->channel_flags & IEEE80211_CHAN_OFDM))
			ecq->_phy = EMPOWER_PHY_80211b;
		else
			ecq->_phy = EMPOWER_PHY_80211g;
	}
	*/

	if (ecq->_nb_pkts == ecq->_max_size)
	{
		click_chatter("%{element} :: %s :: Packets buffer is full for station %s. Dropped packets %d",
							  this,
							  __func__,
							  dst.unparse().c_str(),
							  ecq->_dropped_packets);
		ecq->_dropped_packets++;
		p->kill();
		return;
	}

	if (_empty_scheduler_queues != 0 && ecq->_nb_pkts == 0)
	{
		_empty_scheduler_queues--;
		click_chatter("%{element} :: %s :: Scheduler queues were empty. Now a packet has been enqueued %d",
									  this,
									  __func__,
									  _empty_scheduler_queues);
	}

	ecq->_packets[ecq->_tail] = p;
	ecq->_tail = (ecq->_tail + 1) % ecq->_max_size;
	ecq->_nb_pkts++;

	if (_empty_scheduler_queues == 0 || (_lvap_queues.size() == _empty_scheduler_queues))
	{
		_notifier.wake();
		click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. Wake up damn ----- ",
																						 this,
																						 __func__);
	}
}


Packet *
EmpowerScheduler::pull(int)
{
	bool delivered_packet = false;

	if (_lvap_queues.size() == _empty_scheduler_queues)
	{
		_notifier.sleep();
		click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. Go to sleep damn ----- ",
																								 this,
																								 __func__);
		return 0;
	}

	while (!delivered_packet && _lvap_queues.size() != _empty_scheduler_queues)
	{

		EtherAddress lvap_next_delireved_client = _rr_order.front();

		click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. PULL. Next queue lvap %s ----- ",
																				 this,
																				 __func__,
																				 lvap_next_delireved_client.unparse().c_str());

		EmpowerClientQueue * queue =  _lvap_queues.get_pointer(lvap_next_delireved_client);

		if (queue->_nb_pkts == 0)
		{
			queue->_quantum = 0;
			_empty_scheduler_queues ++;
			click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. PULL. No packets in queue lvap %s. Empty queues %d----- ",
																							 this,
																							 __func__,
																							 lvap_next_delireved_client.unparse().c_str(),
																							 _empty_scheduler_queues);
		}
		else
		{
			Packet * next_packet = queue->_packets[queue->_head];

			if (queue->_first_pkt)
			{
				if (_quantum_div == 0)
				{
					click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. PULL. First quantum div %f ----- ",
																															 this,
																															 __func__,
																															 _quantum_div);
					compute_system_quantum(queue->_sta, 1460);

				}

				queue->_quantum += _quantum_div;
				queue->_first_pkt = false;

			}
			// compute time

			float estimated_transm_time = pkt_transmission_time(queue->_sta, (int)next_packet->length());

			click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. PULL. Estimated time %f to deliver packet in queue %s. Quantum %d ----- ",
																						 this,
																						 __func__,
																						 estimated_transm_time,
																						 lvap_next_delireved_client.unparse().c_str(),
																						 queue->_quantum);

			if (queue->_quantum >= estimated_transm_time)
			{
				delivered_packet = true;
				queue->_head = (queue->_head + 1) % queue->_max_size;
				queue->_nb_pkts--;
				queue->_quantum -= estimated_transm_time;
				queue->_total_consumed_time += estimated_transm_time;

				click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. PULL. Packet transmitted in queue  %s. Remaining quantum %d. Total consumed time %d ---- ",
																														 this,
																														 __func__,
																														 lvap_next_delireved_client.unparse().c_str(),
																														 queue->_quantum,
																														 queue->_total_consumed_time);

				return next_packet;
			}
		}
		queue->_first_pkt = true;
		_rr_order.push_back(lvap_next_delireved_client);
		_rr_order.pop_front();
		click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. PULL. Queue  %s has been placed at the end----- ",
																									 this,
																									 __func__,
																									 lvap_next_delireved_client.unparse().c_str());
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

/*float EmpowerScheduler::pkt_transmission_time(EtherAddress next_delireved_client, Packet * next_packet)
{
	MinstrelDstInfo * nfo = get_dst_info(next_delireved_client);

	EmpowerClientQueue * queue =  _lvap_queues.get_pointer(next_delireved_client);
	int8_t rate = (nfo->rates[nfo->max_tp_rate])/2;
	uint32_t pkt_length = next_packet->length();
	int8_t lowest_rate = (nfo->rates[0])/2;

	struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(next_packet);


	TransmissionTime* tt = _waiting_times.get(queue->_phy);


	int nb_retransm = (int) (nfo->probability[nfo->max_tp_rate] + 0.5); // To truncate properly


	float estimated_time = 0;
	int max_retries = ceh->max_tries;
	int max_retries1 = max_retries + ceh->max_tries1;
	int max_retries2 = max_retries1 + ceh->max_tries2;
	int max_retries3 = max_retries2 + ceh->max_tries3;

	for (int i = 1; i <= nb_retransm; i++)
	{
		if (i <= max_retries)
		{
			float backoff_time = (i*tt->_cw_max + tt->_cw_min) / 2;
			float payload_time = (pkt_length * 8) / ceh->rate;
			float data_time = tt->_plcp_preamb + (tt->_plcp_header/ceh->rate) + (tt->_mac_header_body/ceh->rate) + payload_time;
			float ack_time = tt->_plcp_preamb + (tt->_plcp_header/ceh->rate) + (tt->_ack_mac_header/ceh->rate);
			estimated_time += tt->_difs + backoff_time + tt->_sifs + data_time + ack_time;
			max_retries--;
		}
		else if (i <= max_retries1)
		{
			float backoff_time = (i*tt->_cw_max + tt->_cw_min) / 2;
			float payload_time = (pkt_length * 8) / ceh->rate1;
			float data_time = tt->_plcp_preamb + (tt->_plcp_header/ceh->rate1) + (tt->_mac_header_body/ceh->rate1) + payload_time;
			float ack_time = tt->_plcp_preamb + (tt->_plcp_header/ceh->rate1) + (tt->_ack_mac_header/ceh->rate1);
			estimated_time += tt->_difs + backoff_time + tt->_sifs + data_time + ack_time;
			max_retries1--;
		}
		else if (i <= max_retries2)
		{
			float backoff_time = (i*tt->_cw_max + tt->_cw_min) / 2;
			float payload_time = (pkt_length * 8) / ceh->rate2;
			float data_time = tt->_plcp_preamb + (tt->_plcp_header/ceh->rate2) + (tt->_mac_header_body/ceh->rate2) + payload_time;
			float ack_time = tt->_plcp_preamb + (tt->_plcp_header/ceh->rate2) + (tt->_ack_mac_header/ceh->rate2);
			estimated_time += tt->_difs + backoff_time + tt->_sifs + data_time + ack_time;
			max_retries2--;
		}
		else if (i <= max_retries3)
		{
			float backoff_time = (i*tt->_cw_max + tt->_cw_min) / 2;
			float payload_time = (pkt_length * 8) / ceh->rate3;
			float data_time = tt->_plcp_preamb + (tt->_plcp_header/ceh->rate3) + (tt->_mac_header_body/ceh->rate3) + payload_time;
			float ack_time = tt->_plcp_preamb + (tt->_plcp_header/ceh->rate3) + (tt->_ack_mac_header/ceh->rate3);
			estimated_time += tt->_difs + backoff_time + tt->_sifs + data_time + ack_time;
			max_retries3--;
		}
	}

	return estimated_time;
}
*/

/*
float EmpowerScheduler::pkt_transmission_time(EtherAddress next_delireved_client, EtherAddress lvap_bssid, Packet * next_packet)
{
	MinstrelDstInfo * nfo = _el->get_dst_info(next_delireved_client);

	EmpowerClientQueue * queue =  _lvap_queues.get_pointer(lvap_bssid);
	int8_t rate = (nfo->rates[nfo->max_tp_rate])/2;
	uint32_t pkt_length = next_packet->length();
	TransmissionTime* tt = _waiting_times.get(queue->_phy);

	float backoff_time = (tt->_cw_max + tt->_cw_min) / 2;
	float payload_time = (pkt_length * 8) / rate;
	float data_time = tt->_plcp_preamb + (tt->_plcp_header/rate) + (tt->_mac_header_body/rate) + payload_time;
	float ack_time = tt->_plcp_preamb + (tt->_plcp_header/rate) + (tt->_ack_mac_header/rate);

	return tt->_difs + backoff_time + tt->_sifs + data_time + ack_time;
}
*/

int EmpowerScheduler::pkt_transmission_time(EtherAddress next_delireved_client, int pkt_length)
{
	MinstrelDstInfo * nfo = _el->get_dst_info(next_delireved_client);
	int rate, nb_retransm;

	if (nfo)
	{
		rate = (nfo->rates[nfo->max_tp_rate]);
		nb_retransm = (int) (nfo->probability[nfo->max_tp_rate] + 0.5) - 1; // To truncate properly
	}
	else
	{
		click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. NFO Null pointer ----- ",
																			 this,
																			 __func__);
		EmpowerStationState *ess = _el->lvaps()->get_pointer(next_delireved_client);
		TxPolicyInfo * tx_policy = _el->get_tx_policies(ess->_iface_id)->lookup(next_delireved_client);
		rate = tx_policy->_mcs[0];
		nb_retransm = 0;
	}

	click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. Rate %d, nb_retrans %d length %d ----- ",
																				 this,
																				 __func__,
																				 rate,
																				 nb_retransm,
																				 pkt_length);

	int transm_time = (int) calc_transmit_time(rate, pkt_length);
	int backoff = (int) calc_backoff(rate, nb_retransm);
	int total_time = (int) calc_usecs_wifi_packet(pkt_length, rate, nb_retransm);

	click_chatter("%{element} :: %s :: ----- SCHEDULER ELEMENT. Rate %d, nb_retrans %d length %d transm_time %d, backoff %d, total_time %d ----- ",
																					 this,
																					 __func__,
																					 rate,
																					 nb_retransm,
																					 pkt_length,
																					 transm_time,
																					 backoff,
																					 total_time);
	return total_time;
}

enum {
	H_DEBUG
};

String EmpowerScheduler::read_handler(Element *e, void *thunk) {
	EmpowerScheduler *td = (EmpowerScheduler *) e;
	switch ((uintptr_t) thunk) {
	case H_DEBUG:
		return String(td->_debug) + "\n";
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
	add_write_handler("debug", write_handler, (void *) H_DEBUG);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(EmpowerScheduler)
ELEMENT_REQUIRES(userlevel)


