/*
 * empowerqosscheduler.cc
 *
 *  Created on: Oct 30, 2017
 *      Author: Estefania Coronado
 */

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <click/standard/scheduleinfo.hh>
#include <clicknet/ether.h>
#include <clicknet/wifi.h>
#include <clicknet/llc.h>
#include <clicknet/ip.h>
#include <elements/wifi/bitrate.hh>
#include <algorithm>
#include "empowerqosscheduler.hh"
CLICK_DECLS


EmpowerQoSScheduler::EmpowerQoSScheduler() :
	_el(0), _debug(false) {
}

EmpowerQoSScheduler::~EmpowerQoSScheduler() {
}

int EmpowerQoSScheduler::configure(Vector<String> &conf,
		ErrorHandler *errh) {

	_notifier.initialize(Notifier::EMPTY_NOTIFIER, router());

	return Args(conf, this, errh)
			.read_m("EL", ElementCastArg("EmpowerLVAPManager"), _el)
			.read("DEBUG", _debug)
			.complete();

}

void *
EmpowerQoSScheduler::cast(const char *n)
{
    if (strcmp(n, Notifier::EMPTY_NOTIFIER) == 0)
    	return static_cast<Notifier *>(&_notifier);
    else
    	return Element::cast(n);
}

int EmpowerQoSScheduler::initialize(ErrorHandler *) {
	_drops = 0;
	_bdrops = 0;
	_sleepiness = 0;
	_empty_slices = 0;
	_system_quantum = 1470;
	_default_dscp = 0;
	_notifier.initialize(Notifier::EMPTY_NOTIFIER, router());

	return 0;
}

void
EmpowerQoSScheduler::push(int, Packet *p) {

	const click_ip *ip = p->ip_header();
	int dscp = (int)ip->ip_tos >> 2;

	if (p->length() < sizeof(struct click_ether)) {
		click_chatter("%{element} :: %s :: packet too small: %d vs %d", this,
				__func__, p->length(), sizeof(struct click_ether));
		p->kill();
		return;
	}

	click_ether *eh = (click_ether *) p->data();
	EtherAddress dst = EtherAddress(eh->ether_dhost);

	// TODO. Add BSSID info to the queues (taken from the vaps)
	// TODO. The default queue / other queues are created with the add vaps
	// There is no default queue. If nothing matches or if it is bcast/mcast -> dscp 0
	// unicast traffic
	if (!dst.is_broadcast() && !dst.is_group()) {

		EmpowerStationState *ess = _el->get_ess(dst);

		if (!ess) {
			click_chatter("%{element} :: %s :: Unknown station %s",
						  this,
						  __func__,
						  dst.unparse().c_str());
			p->kill();
			return;
		}

		String ssid = ess->_ssid;
		BufferQueueInfo slice_key (dscp, ssid);
		BufferQueue * slice = _slices.get(slice_key);

		// The dscp does not match any queue. The traffic is enqueued in the default queue
		// The default queue does not aggregate
		if (!slice){
			click_chatter("%{element} :: %s :: The requested slice SSID %s DSCP %d does not exist",
					this, __func__,
					ssid.c_str(),
					dscp);
			// This dscp does not exist. The default queue for this tenant is used instead
			BufferQueueInfo slice_key (_default_dscp, ssid);
			dscp = _default_dscp;
			slice = _slices.get(slice_key);
		}

		enqueue_unicast_frame(dst, slice, p, ess->_lvap_bssid);
		return;
	}

	// Broadcast and multicast frames are copied in the default queue of each tenant.
	// If the tenant is unique, the packet is cloned for each destination address but it is not aggregated
	// since the default queue does not aggregate by the moment.
	// If the tenant is shared, the frame is just enqueued holding the original DA.

	for (TrafficRulesQueuesIter it_slices = _slices.begin(); it_slices.live(); it_slices++) {
		if (it_slices.key()._dscp != _default_dscp) {
			continue;
		}
		Packet *q = p->clone();
		if (!q) {
			continue;
		}
		if (it_slices.value()->_tenant_type == EMPOWER_TYPE_UNIQUE) {
			for (LVAPIter it = _el->lvaps()->begin(); it.live(); it++) {
				if (it.value()._ssid != it_slices.key()._tenant) {
					continue;
				}
				BufferQueueInfo slice_key (_default_dscp, it.value()._ssid);
				BufferQueue * slice = _slices.get(slice_key);
				// Clone the packet for each lvap in this tenant
				Packet *pq = q->clone();
				if (!pq) {
					continue;
				}
				// Change the DA to the unicast one
				// TODO. Not to change the address if the dst is broadcast
				WritablePacket *unicast_pkt = pq->uniqueify();
				if (!unicast_pkt) {
					slice->_dropped_packets++;
					slice->_dropped_msdus ++;
					slice->_dropped_bytes += unicast_pkt->length();
					_drops++;
					_bdrops += unicast_pkt->length();
					unicast_pkt->kill();
					return;
				}
				click_ether *ethh = unicast_pkt->ether_header();
				memcpy(ethh->ether_dhost, &it.value()._sta, 6);
				enqueue_unicast_frame(dst,slice, (Packet *) unicast_pkt, it.value()._lvap_bssid);
			}
		} else {
			// EMPOWER_TYPE_SHARED
			// TODO. If the tenant is shared... the frame should be duplicated as many as VAPs (as many as bssids)
			// if the the policy is legacy.
			// if it is dms... the DA does not change, but the bssid is set to each lvap (so.. as many as lvaps)
			BufferQueueInfo slice_key (_default_dscp,it_slices.key()._tenant);
			BufferQueue * slice = _slices.get(slice_key);
			FrameInfo * new_frame = new FrameInfo();

			for (int i = 0; i < _el->num_ifaces(); i++) {
				TxPolicyInfo * tx_policy = _el->get_tx_policies(i)->lookup(dst);

				if (tx_policy->_tx_mcast == TX_MCAST_DMS) {
					// dms mcast policy, duplicate the frame for each station in
					// each bssid and use unicast destination addresses. note that
					// a given station cannot be in more than one bssid, so just
					// track if the frame has already been delivered to a given
					// station.

					Vector<EtherAddress> sent;
					for (LVAPIter it = _el->lvaps()->begin(); it.live(); it++) {
						// TODO. This should be checked? What about the ARP or similar traffic?
						if (it.value()._ssid != it_slices.key()._tenant) {
							continue;
						}
						EtherAddress sta = it.value()._sta;
						if (it.value()._iface_id != i) {
							continue;
						}
						if (!it.value()._set_mask) {
							continue;
						}
						if (!it.value()._authentication_status) {
							continue;
						}
						if (!it.value()._association_status) {
							continue;
						}
						if (find(sent.begin(), sent.end(), sta) != sent.end()) {
							continue;
						}
						sent.push_back(sta);
						Packet *q = p->clone();
						if (!q) {
							continue;
						}
						// TODO. Is this sta or dst?
						enqueue_unicast_frame(sta, slice, q, it.value()._lvap_bssid);
					}

				} else if (tx_policy->_tx_mcast == TX_MCAST_UR) {

					// TODO: implement

				} else {

					// legacy mcast policy, just send the frame as it is, minstrel will
					// pick the rate from the transmission policies table

					Vector<EtherAddress> sent;

					for (LVAPIter it = _el->lvaps()->begin(); it.live(); it++) {
						// TODO. This should be checked? What about the ARP or similar traffic?
						if (it.value()._ssid != it_slices.key()._tenant) {
							continue;
						}

						EtherAddress bssid = it.value()._lvap_bssid;
						if (it.value()._iface_id != i) {
							continue;
						}
						if (!it.value()._set_mask) {
							continue;
						}
						if (!it.value()._authentication_status) {
							continue;
						}
						if (!it.value()._association_status) {
							continue;
						}
						if (find(sent.begin(), sent.end(), bssid) != sent.end()) {
							continue;
						}
						sent.push_back(bssid);
						Packet *q = p->clone();
						if (!q) {
							continue;
						}
						enqueue_unicast_frame(dst, slice, q, bssid);
					}

				}


			new_frame->_frame = q->uniqueify();
			if (!new_frame->_frame) {
				new_frame->_frame->kill();
				slice->_dropped_packets++;
				return;
			}
			new_frame->_frame_length = new_frame->_frame->length();
			new_frame->_dst = dst;

			if (slice->_frames.size() == 0)
				_empty_slices--;

			slice->_frames.push_back(new_frame);
			new_frame->_complete = true;
			}
		}
	}
}

void
EmpowerQoSScheduler::enqueue_unicast_frame(EtherAddress dst, BufferQueue * slice, Packet * p, EtherAddress bssid)
{
	if (_current_frame_clients.find(dst) == _current_frame_clients.end()) {
		FrameInfo * new_frame = new FrameInfo();
		new_frame->_frame = p->uniqueify();
		if (!new_frame->_frame) {
			new_frame->_frame->kill();
			slice->_dropped_packets++;
			return;
		}
		new_frame->_frame_length = new_frame->_frame->length();
		new_frame->_dst = dst;
		new_frame->_bssid = bssid;
		if (slice->_frames.size() == 0)
			_empty_slices--;
		slice->_frames.push_back(new_frame);

		if (slice->_aggregate) {
			_current_frame_clients.set(dst, new_frame);
		} else {
			new_frame->_complete = true;
		}
		return;
	}

	FrameInfo * current_frame = _current_frame_clients.get(dst);

	if (((current_frame->_frame_length + p->length()) > slice->_max_length) || current_frame->_complete) {
		current_frame->_complete = true;
		FrameInfo * new_frame = new FrameInfo();

		new_frame->_frame = p->uniqueify();
		if (!new_frame->_frame) {
			new_frame->_frame->kill();
			slice->_dropped_packets++;
			return;
		}
		new_frame->_frame_length = new_frame->_frame->length();
		new_frame->_dst = dst;
		new_frame->_bssid = bssid;
		_current_frame_clients.set(dst, new_frame);
		slice->_frames.push_back(new_frame);
	} else {
		WritablePacket *q = current_frame->_frame->put(p->length());
		if (!q) {
			_current_frame_clients.erase(_current_frame_clients.find(dst));
			slice->discard_frame(current_frame);
			slice->_dropped_packets++;
			return;
		}
		current_frame->_frame = q;
		memcpy(current_frame->_frame->data() + current_frame->_frame_length, p->data(), p->length());
		current_frame->_frame_length += current_frame->_frame->length();
		current_frame->_msdus++;
		current_frame->_average_time_diff = std::max(current_frame->_average_time_diff, (Timestamp::now() - current_frame->_last_frame_time));
		current_frame->_last_frame_time = Timestamp::now();
	}
	// Check if it can wait for the next frame to complete this one
	if ((frame_transmission_time(dst, current_frame->_frame_length) + current_frame->_average_time_diff) > slice->_max_delay) {
		current_frame->_complete = true;
	}
}

Packet *
EmpowerQoSScheduler::pull(int)
{
	bool delivered_packet = false;

	if (_slices.size() == _empty_slices) {
		// TODO. Check the behavior of the notifier
		_notifier.sleep();
		click_chatter("%{element} :: %s :: ----- All the buffer queues are empty: %d ----- ",
										 this,
										 __func__,
										 _empty_slices);
		return 0;
	}

	// TODO. Add ordering in a slice by...? expiration time?
	while (!delivered_packet && _slices.size() != _empty_slices) {
		BufferQueueInfo queue_info = _rr_order.front();
		BufferQueue * slice =  _slices.get(queue_info);

		//queue->_mutex.acquire_write();
		while (slice->_frames.size()) {
			// TODO. By the moment is done taking the first one. This must be improved
			// TODO. What happens if I go to a queue and the packet is not still completed? Shall I wait? Shall I take the next one?
			FrameInfo *next_frame = slice->pull();
			_current_frame_clients.erase(_current_frame_clients.find(next_frame->_dst));
			// If the transmission time + the time that the frame has been in the queue exceeds the delay deadline
			// this frame is discarded
			int transm_time = frame_transmission_time(next_frame->_dst, next_frame->_frame_length);
			if (!slice->check_delay_deadline(next_frame, transm_time)) {
				// If it is the first time of this queue and it is not empty, a new deficit must be assigned
				if (slice->_first_pkt) {
					// TODO. compute quantum
					//slice->_quantum = 1000; // TODO. CHANGE OF COURSE
					slice->_deficit += slice->_quantum;
					slice->_first_pkt = false;
				}
				if (slice->_deficit >= transm_time) {
					delivered_packet = true;
					slice->_deficit -= transm_time;
					slice->_total_consumed_time += transm_time;
					slice->_transmitted_packets ++;
					slice->_transmitted_msdus += next_frame->_msdus;
					slice->_transmitted_bytes += next_frame->_frame_length;

					click_chatter("%{element} :: %s :: ----- PULL in slice (%d, %s) for station  %s. Remaining deficit %d. "
							"Remaining packets %d (Consumption: time %d packets %d msdus %d bytes %d ---- ",
																			 this,
																			 __func__,
																			 queue_info._dscp,
																			 queue_info._tenant.c_str(),
																			 next_frame->_dst.unparse().c_str(),
																			 slice->_deficit,
																			 (slice->_frames.size() - 1),
																			 slice->_total_consumed_time,
																			 slice->_transmitted_packets,
																			 slice->_transmitted_msdus,
																			 slice->_transmitted_bytes);

					if (slice->_frames.size() == 0) {
						slice->_deficit = 0;
						_empty_slices ++;
					}

					slice->remove_frame_from_queue(next_frame);
					return empower_wifi_encap(next_frame);
				}
			} else {
				slice->_dropped_packets++;
				slice->_dropped_msdus += next_frame->_msdus;
				slice->_dropped_bytes += next_frame->_frame_length;
				_drops++;
				_bdrops += next_frame->_frame_length;
				slice->discard_frame(next_frame);
			}
		}
		slice->_first_pkt = true;
		_rr_order.push_back(queue_info);
		_rr_order.pop_front();
	}
	return 0;
}

int
EmpowerQoSScheduler::frame_transmission_time(EtherAddress next_delireved_client, int pkt_length)
{
	MinstrelDstInfo * nfo = _el->get_dst_info(next_delireved_client);
	EmpowerStationState *ess = _el->lvaps()->get_pointer(next_delireved_client);
	TxPolicyInfo * tx_policy = _el->get_tx_policies(ess->_iface_id)->lookup(next_delireved_client);

	int rate, nb_retransm = 0;
	uint32_t usecs = 1000000;

	if (nfo) {
		rate = (nfo->rates[nfo->max_tp_rate]);
		// Probabilities must be divided by 180 to obtain a percentage 97.88
		int success_prob = nfo->probability[nfo->max_tp_rate];
		// To obtain the number of retransmissions, it must be 1/(percentg./100) -> 180*100 = 18000
		success_prob = 18000/success_prob;
		nb_retransm = (int) ((1 / success_prob) + 0.5); // To truncate properly
		// In case the nb_transm is higher than 1 it is also considering the first transm
		// For example... prob success = 0.8 -> 1/0.8 = 1.25. It will sent the packets, 1.25 times.
		// When truncating it becomes 1, but the number of retransmissions is 0. The first one is the transmission.
		if (nb_retransm >= 1)
			nb_retransm --;
	}
	else {
		rate = tx_policy->_mcs[0];
	}

	if(tx_policy->_ht_mcs.size()) {
		usecs = calc_usecs_wifi_packet_ht(pkt_length, rate, nb_retransm);
	}
	else {
		usecs = calc_usecs_wifi_packet(pkt_length, rate, nb_retransm);
	}

	return (int)usecs;
}

String
EmpowerQoSScheduler::list_slices()
{
	StringAccum sa;
	for (TrafficRulesQueuesIter it =_slices.begin(); it.live(); it++) {
		sa << "Tenant ";
		sa << it.key()._tenant;
		if (it.value()->_tenant_type == EMPOWER_TYPE_SHARED) {
			sa << " Shared";
		} else {
			sa << " Unique";
		}
		sa << " dscp ";
		sa << it.key()._dscp;
		sa << " parent priority ";
		sa << it.value()->_parent_priority;
		sa << " priority ";
		sa << it.value()->_priority;
		if (it.value()->_aggregate) {
			sa << " AGGR.";
		} else {
			sa << " NON AGGR.";
		}
		sa << " max. delay ";
		sa << it.value()->_max_delay;
		sa << " max. length ";
		sa << it.value()->_max_length;
		sa << " deficit ";
		sa << it.value()->_deficit;
		sa << " quantum ";
		sa << it.value()->_quantum;
		sa << "\n";
		sa << " cons. time ";
		sa << it.value()->_total_consumed_time;
		sa << " dropped pkts ";
		sa << it.value()->_dropped_packets;
		sa << " dropped msdus ";
		sa << it.value()->_dropped_msdus;
		sa << " dropped bytes ";
		sa << it.value()->_dropped_bytes;
		sa << " transm. msdus ";
		sa << it.value()->_transmitted_msdus;
		sa << " transm. pkts ";
		sa << it.value()->_transmitted_packets;
		sa << " transm. bytes ";
		sa << it.value()->_transmitted_bytes;
		sa << "\n";
	}
	return sa.take_string();
}

void
EmpowerQoSScheduler::request_slice(int dscp, String tenant, empower_tenant_types tenant_type, int priority,
		int parent_priority, bool amsdu_aggregation)
{
	BufferQueueInfo queue_info(dscp, tenant);

	if (_slices.find(queue_info) == _slices.end()) {
		// TODO. Decide how to set the priority and parent_priority
		int max_delay = map_dscp_to_delay(dscp);
		BufferQueue * slice = new BufferQueue (tenant_type, priority, parent_priority, amsdu_aggregation, max_delay);
		_slices.set(queue_info, slice);

		_rr_order.push_back(queue_info);
		_empty_slices++;
	}
}

void
EmpowerQoSScheduler::remove_slice_resources(int dscp, String tenant)
{
	int tenant_air_time_portion = 0;


}

void
EmpowerQoSScheduler::release_slice(int dscp, String tenant)
{
	BufferQueueInfo slice_key (dscp, tenant);
	BufferQueue * slice = _slices.get(slice_key);

	if (!slice){
		click_chatter("%{element} :: %s :: The requested slice SSID %s DSCP %d does not exist",
				this, __func__,
				tenant.c_str(),
				dscp);
		return;
	}

	// Calculates the sum of the priorities of the remaining queues from the same tenant
	int tenant_priorities = 0;
	for (TrafficRulesQueuesIter it_slices = _slices.begin(); it_slices.live(); it_slices++) {
		if (it_slices.key()._tenant == tenant && it_slices.key()._dscp != dscp) {
			tenant_priorities += it_slices.value()->_priority;
		}
	}

	// The bandwidth is reassigned to the other queues from the same tenant
	for (TrafficRulesQueuesIter it_slices = _slices.begin(); it_slices.live(); it_slices++) {
		if (it_slices.key()._tenant == tenant && it_slices.key()._dscp != dscp) {
			it_slices.value()->_priority = (slice->_priority * it_slices.value()->_priority) / tenant_priorities;
		}
	}

	// If the queue was empty, the empty slices counter should be decreased
	if (slice->_frames.size() == 0)
		_empty_slices--;

	// The frames in the inner queues are also deleted
	for (Vector<FrameInfo*>::iterator it = slice->_frames.begin(); it != slice->_frames.end(); it++) {
		(*it)->_frame->kill();
		delete (*it);
	}
	slice->_frames.clear();

	// The queue is erased from the scheduler and the RR order
	for (Vector <BufferQueueInfo>::iterator it = _rr_order.begin(); it != _rr_order.end(); )
	   if((*it) == slice_key) {
	      it = _rr_order.erase(it);
	      break;
	   }
	delete slice;
	_slices.erase(_slices.find(slice_key));
}

Packet *
EmpowerQoSScheduler::empower_wifi_encap(FrameInfo * next_frame)
{
	Packet *p = (Packet *) next_frame->_frame;
	click_ether *eh = (click_ether *) p->data();
	EtherAddress src = EtherAddress(eh->ether_shost);
//	EtherAddress dst = EtherAddress(eh->ether_dhost);
	EtherAddress dst = next_frame->_dst;

	// unicast traffic
	if (!dst.is_broadcast() && !dst.is_group()) {
		EmpowerStationState *ess = _el->get_ess(dst);
		TxPolicyInfo *txp = _el->get_txp(dst);
		if (!ess) {
			p->kill();
			return 0;
		}
		if (!ess->_set_mask) {
			p->kill();
			return 0;
		}
		if (!ess->_authentication_status) {
			click_chatter("%{element} :: %s :: station %s not authenticated",
						  this,
						  __func__,
						  dst.unparse().c_str());
			p->kill();
			return 0;
		}
		if (!ess->_association_status) {
			click_chatter("%{element} :: %s :: station %s not associated",
						  this,
						  __func__,
						  dst.unparse().c_str());
			p->kill();
			return 0;
		}
		Packet * p_out = wifi_encap(p, dst, src, ess->_lvap_bssid);
		txp->update_tx(p->length());
		SET_PAINT_ANNO(p_out, ess->_iface_id);
		return p_out;
	}

	// broadcast and multicast traffic, we need to transmit one frame for each unique
	// bssid. this is due to the fact that we can have the same bssid for multiple LVAPs.
	Packet * p_out = wifi_encap(p, dst, src, next_frame->_bssid);
	TxPolicyInfo * tx_policy =_el->get_txp(dst);
	tx_policy->update_tx(p->length());
	SET_PAINT_ANNO(p_out, i);
	return p_out;
}

Packet *
EmpowerQoSScheduler::wifi_encap(Packet *q, EtherAddress dst, EtherAddress src, EtherAddress bssid) {

    WritablePacket *p_out = q->uniqueify();

	if (!p_out) {
		p_out->kill();
		return 0;
	}

	uint8_t mode = WIFI_FC1_DIR_FROMDS;
	uint16_t ethtype;

    memcpy(&ethtype, p_out->data() + 12, 2);

	p_out->pull(sizeof(struct click_ether));
	p_out = p_out->push(sizeof(struct click_llc));

	if (!p_out) {
		p_out->kill();
		return 0;
	}

	memcpy(p_out->data(), WIFI_LLC_HEADER, WIFI_LLC_HEADER_LEN);
	memcpy(p_out->data() + 6, &ethtype, 2);

	if (!(p_out = p_out->push(sizeof(struct click_wifi)))) {
		p_out->kill();
		return 0;
	}

	struct click_wifi *w = (struct click_wifi *) p_out->data();

	memset(p_out->data(), 0, sizeof(click_wifi));
	w->i_fc[0] = (uint8_t) (WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_DATA);
	w->i_fc[1] = 0;
	w->i_fc[1] |= (uint8_t) (WIFI_FC1_DIR_MASK & mode);

	memcpy(w->i_addr1, dst.data(), 6);
	memcpy(w->i_addr2, bssid.data(), 6);
	memcpy(w->i_addr3, src.data(), 6);

	return p_out;
}

int
EmpowerQoSScheduler::map_dscp_to_delay(int dscp)
{
	int delay = 5000;

	switch (dscp) {
	case 8:
		delay = 5000;
		break;
	case 16:
		delay = 5000;
		break;
	case 0:
		delay = 3000;
		break;
	case 24:
		delay = 3000;
		break;
	case 32:
		delay = 400;
		break;
	case 40:
		delay = 400;
		break;
	case 48:
		delay = 150;
		break;
	case 56:
		delay = 150;
		break;
	default:
		click_chatter("%{element} :: %s :: invalid dscp %d",
					  this,
					  __func__,
					  dscp);
		return 5000;
	return delay;
	}
}
void
EmpowerQoSScheduler::add_handlers()
{
	add_read_handler("drops", read_handler, (void*)H_DROPS);
	add_read_handler("byte_drops", read_handler, (void*)H_BYTEDROPS);
	add_read_handler("list_queues", read_handler, (void*)H_LIST_QUEUES);
}
