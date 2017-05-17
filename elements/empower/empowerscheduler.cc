/*
 * empowerscheduler.cc
 *
 *  Created on: May 15, 2017
 *      Author: estefania
 */

#include <elements/standard/counter.hh>
#include <elements/wifi/minstrel.hh>
#include <elements/wifi/transmissionpolicy.hh>
#include <elements/wifi/availablerates.hh>
#include "empowerpacket.hh"
#include "empowerrxstats.hh"
#include "empowercqm.hh"
#include "empowerscheduler.hh"
#include "empowerlvapmanager.hh"
CLICK_DECLS


EmpowerScheduler::EmpowerScheduler() :
		_el(0), _debug(false) {
}

EmpowerScheduler::~EmpowerScheduler() {
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
				      sizeof(struct click_wifi));
		p->kill();
		return;
	}

	struct click_wifi *w = (struct click_wifi *) p->data();
	uint8_t dir = w->i_fc[1] & WIFI_FC1_DIR_MASK;

	EtherAddress dst;
	EtherAddress src;
	EtherAddress bssid;

	switch (dir) {
	case WIFI_FC1_DIR_NODS:
		dst = EtherAddress(w->i_addr1);
		break;
	case WIFI_FC1_DIR_TODS:
		dst = EtherAddress(w->i_addr3);
		break;
	case WIFI_FC1_DIR_FROMDS:
		dst = EtherAddress(w->i_addr1);
		break;
	case WIFI_FC1_DIR_DSTODS:
		dst = EtherAddress(w->i_addr1);
		break;
	default:
		click_chatter("%{element} :: %s :: invalid dir %d",
					  this,
					  __func__,
					  dir);
		p->kill();
		return;
	}

	// Let's assume only downlink traffic. The destination should be the client.
	//_lvap_queues.get_pointer(dst)->_packets.push_back(*p);


	int tail = _lvap_queues.get_pointer(dst)->_tail;
	int head = _lvap_queues.get_pointer(dst)->_head;
	int max_pkts = _lvap_queues.get_pointer(dst)->_max_size;
	int nb_pkts = _lvap_queues.get_pointer(dst)->_nb_pkts;
	//if ((tail + 1) %  max_pkts == head)
	if (nb_pkts == max_pkts)
	{
		click_chatter("%{element} :: %s :: Packets buffer is full for station %s",
							  this,
							  __func__,
							  src.unparse().c_str());
		p->kill();
		return;
	}

	_lvap_queues.get_pointer(dst)->_packets[tail];
	_lvap_queues.get_pointer(dst)->_tail = (tail + 1) % max_pkts;
	// TODO. Return? destroy packet?

	//notifiers.wakeup y sleep en pull si no hay colas
	if (_empty_scheduler_queues == 0)
		_notifier.wake();
}


Packet*
EmpowerScheduler::schedule_packet()
{
	int i;
	int nb_clients = _rr_order.size();

	for (i = 0; i < nb_clients; i++)
	{
		bool first_queue_transm = true;
		bool all_pkts_sent = false;
		EtherAddress next_delireved_client = _rr_order.pop_front();

		// Figure out how much time I need to deliver this packet.
		EmpowerClientQueue * queue =  _lvap_queues.get_pointer(next_delireved_client);

		if (queue->_nb_pkts == 0)
		{
			_empty_scheduler_queues ++;
			continue;
		}

		queue->_quantum += _quantum_div;

		while(queue->_nb_pkts > 0)
		{
			if (first_queue_transm)
			{
				_empty_scheduler_queues--;
				first_queue_transm = false;
			}

			Packet * next_packet = queue->_packets[queue->_head];
			MinstrelDstInfo * nfo = get_dst_info(next_delireved_client);
			int8_t rate = nfo->rates[nfo->max_tp_rate];
			uint32_t pkt_length = next_packet->length();

			// time in seconds
			float estimated_transm_time = (pkt_length * 8) / rate;

			// There is not enough time for this client to deliver a packet. Let's move to the
			// next client because any packet has been sent
			//if (queue->_quantum < estimated_transm_time && !succ_transm)
			if (queue->_quantum < estimated_transm_time)
				continue;

			// There is time to deliver the packet.
			queue->_head = (queue->_head + 1) % queue->_max_size;
			queue->_nb_pkts--;
			queue->_quantum -= estimated_transm_time;

			if (queue->_nb_pkts == 0)
				_empty_scheduler_queues ++;

			return next_packet;
		}

		_rr_order.push_back(next_delireved_client);
	}

	return 0;
}


Packet *
EmpowerScheduler::pull(int)
{
	if (_lvap_queues.size() == _empty_scheduler_queues)
		_notifier.sleep();

    Packet *p = schedule_packet();
	return p;
}



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


