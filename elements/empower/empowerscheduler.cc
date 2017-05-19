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
CLICK_DECLS


EmpowerScheduler::EmpowerScheduler() :
	_rc(0), _debug(false) {
}

EmpowerScheduler::~EmpowerScheduler() {
	TransmissionTime* phya = new TransmissionTime(16, 24, 12246, 134, 16, 34, 9, 15, 1023);
	TransmissionTime* phyb = new TransmissionTime(72, 48, 12224, 112, 10, 50, 20, 31, 1023);
	TransmissionTime* phyg = new TransmissionTime(16, 24, 12246, 134, 10, 50, 20, 31, 1023);
	//TransmissionTime phyg = new TransmissionTime(16, 24, 12246, 134, 10, 28, 20, 15, 1023);

	_waiting_times.set((int)EMPOWER_PHY_80211a, phya);
	_waiting_times.set((int)EMPOWER_PHY_80211b, phyb);
	_waiting_times.set((int)EMPOWER_PHY_80211g, phyg);

	/*TransmissionTime phya = new TransmissionTime(16, 34, 9, 15, 1023);
	TransmissionTime phybg = new TransmissionTime(10, 50, 20, 31, 1023);

	_waiting_times.set(EMPOWER_PHY_80211a, phya);
	_waiting_times.set(EMPOWER_PHY_80211bg, phybg);
	*/
}

int EmpowerScheduler::configure(Vector<String> &conf,
		ErrorHandler *errh) {

	return Args(conf, this, errh)
			.read_m("RC", ElementCastArg("Minstrel"), _rc)
			.read("DEBUG", _debug)
			.complete();

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
	EtherAddress dst = EtherAddress(w->i_addr1);

	// Let's assume only downlink traffic. The destination should be the client.
	EmpowerClientQueue * ecq = _lvap_queues.get_pointer(dst);
	if (!ecq->_phy)
	{
		struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);
		// In case the OFDM modulation is not found, this is a 11b client
		if (!(ceh->channel_flags & IEEE80211_CHAN_OFDM))
			ecq->_phy = EMPOWER_PHY_80211b;
		else
			ecq->_phy = EMPOWER_PHY_80211g;
	}
	int tail = ecq->_tail;
	int max_pkts = ecq->_max_size;
	int nb_pkts = ecq->_nb_pkts;

	if (nb_pkts == max_pkts)
	{
		click_chatter("%{element} :: %s :: Packets buffer is full for station %s",
							  this,
							  __func__,
							  dst.unparse().c_str());
		p->kill();
		return;
	}

	if (nb_pkts == 0)
		_empty_scheduler_queues--;

	ecq->_packets[tail] = p;
	_lvap_queues.get_pointer(dst)->_tail = (tail + 1) % max_pkts;
	// TODO. Return? destroy packet?


	if (_empty_scheduler_queues == 0)
		_notifier.wake();
}


Packet *
EmpowerScheduler::pull(int)
{
	bool delivered_packet = false;

	if (_lvap_queues.size() == _empty_scheduler_queues)
	{
		_notifier.sleep();
		return 0;
	}

	while (!delivered_packet && _lvap_queues.size() != _empty_scheduler_queues)
	{
		EtherAddress next_delireved_client = _rr_order.front();
		_rr_order.pop_front();

		EmpowerClientQueue * queue =  _lvap_queues.get_pointer(next_delireved_client);

		if (queue->_nb_pkts == 0)
		{
			queue->_quantum = 0;
			_empty_scheduler_queues ++;
		}
		else
		{
			if (queue->_first_pkt)
			{
				queue->_quantum += _quantum_div;
				queue->_first_pkt = false;
			}
			// compute time
			Packet * next_packet = queue->_packets[queue->_head];
			float estimated_transm_time = pkt_transmission_time(next_delireved_client, next_packet);

			if (queue->_quantum >= estimated_transm_time)
			{
				delivered_packet = true;
				queue->_head = (queue->_head + 1) % queue->_max_size;
				queue->_nb_pkts--;
				return next_packet;
			}
		}
		queue->_first_pkt = true;
		_rr_order.push_back(next_delireved_client);
	}
	return 0;
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

float EmpowerScheduler::pkt_transmission_time(EtherAddress next_delireved_client, Packet * next_packet)
{
	MinstrelDstInfo * nfo = get_dst_info(next_delireved_client);

	EmpowerClientQueue * queue =  _lvap_queues.get_pointer(next_delireved_client);
	int8_t rate = (nfo->rates[nfo->max_tp_rate])/2;
	uint32_t pkt_length = next_packet->length();
	TransmissionTime* tt = _waiting_times.get(queue->_phy);

	float backoff_time = (tt->_cw_max + tt->_cw_min) / 2;
	float payload_time = (pkt_length * 8) / rate;
	float data_time = tt->_plcp_preamb + (tt->_plcp_header/rate) + (tt->_mac_header_body/rate) + payload_time;
	float ack_time = tt->_plcp_preamb + (tt->_plcp_header/rate) + (tt->_ack_mac_header/rate);

	return tt->_difs + backoff_time + tt->_sifs + data_time + ack_time;
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


