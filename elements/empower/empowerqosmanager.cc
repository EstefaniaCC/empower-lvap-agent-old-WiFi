/*
 * EmpowerQoSManager.cc
 *
 *  Created on: Oct 30, 2017
 *      Author: Estefania Coronado
 */

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <click/args.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/packet_anno.hh>
#include <clicknet/ether.h>
#include <clicknet/wifi.h>
#include <clicknet/llc.h>
#include <clicknet/ip.h>
#include <elements/wifi/bitrate.hh>
#include <algorithm>
#include "empowerqosmanager.hh"
CLICK_DECLS

EmpowerQoSManager::EmpowerQoSManager() :
	_el(0), _debug(false) {
}

EmpowerQoSManager::~EmpowerQoSManager() {
}

int EmpowerQoSManager::configure(Vector<String> &conf,
		ErrorHandler *errh) {

	_notifier.initialize(Notifier::EMPTY_NOTIFIER, router());

	return Args(conf, this, errh)
			.read_m("EL", ElementCastArg("EmpowerLVAPManager"), _el)
			.read("DEBUG", _debug)
			.complete();
}

void *
EmpowerQoSManager::cast(const char *n)
{
    if (strcmp(n, "EmpowerQoSManager") == 0)
    	return (EmpowerQoSManager *) this;
    else if (strcmp(n, Notifier::EMPTY_NOTIFIER) == 0)
    	return static_cast<Notifier *>(&_notifier);
	else
		return SimpleQueue::cast(n);
}

int EmpowerQoSManager::initialize(ErrorHandler *) {
	_drops = 0;
	_bdrops = 0;
	_sleepiness = 0;
	_empty_traffic_rules = 0;
	_system_quantum = 1470;
	_default_dscp = 0;
	_notifier.initialize(Notifier::EMPTY_NOTIFIER, router());

	return 0;
}

void
EmpowerQoSManager::push(int, Packet *p) {
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
	EtherAddress src = EtherAddress(eh->ether_shost);
	uint8_t iface_id = PAINT_ANNO(p);

	click_chatter("%{element} :: %s :: Push. Dst %s Src %s iface %d",
										this, __func__,
										dst.unparse().c_str(),
										src.unparse().c_str(),
										iface_id);

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

		// The lvap is not attached to this interface
		if (ess->_iface_id != iface_id){
			p->kill();
			return;
		}

		if (!ess->_set_mask) {
			p->kill();
			return;
		}
		if (!ess->_authentication_status) {
			click_chatter("%{element} :: %s :: station %s not authenticated",
						  this,
						  __func__,
						  dst.unparse().c_str());
			p->kill();
			return;
		}
		if (!ess->_association_status) {
			click_chatter("%{element} :: %s :: station %s not associated",
						  this,
						  __func__,
						  dst.unparse().c_str());
			p->kill();
			return;
		}

		String ssid = ess->_ssid;
		BufferQueue * tr_queue = get_traffic_rule(dscp, ssid);

		if (tr_queue) {
			click_chatter("%{element} :: %s :: Queue found in unicast SSID %s DSCP %d exists. Dst %s",
							this, __func__,
							ssid.c_str(),
							dscp,
							dst.unparse().c_str());
		}

		// The dscp does not match any queue. The traffic is enqueued in the default queue
		// The default queue does not aggregate
		if (!tr_queue){
			click_chatter("%{element} :: %s :: The requested traffic rule SSID %s DSCP %d does not exist",
					this, __func__,
					ssid.c_str(),
					dscp);
			// This dscp does not exist. The default queue for this tenant is used instead
			dscp = _default_dscp;
			tr_queue = get_traffic_rule(dscp, ssid);

			// TODO. Add a new queue is the tenant is not there for an incoming packet
//			if (!tr_queue) {
//				empower_tenant_types tenant_type = ((ess->_lvap_bssid == ess->_net_bssid) ? EMPOWER_TYPE_UNIQUE : EMPOWER_TYPE_SHARED);
//				request_traffic_rule(dscp, ssid, tenant_type, 100, 100, false, false, false); // parent_priority must be set by the controller
//				// TODO. Send message to the controller to register it.
//			}
		}

		enqueue_unicast_frame(dst, tr_queue, p, ess->_lvap_bssid, ess->_iface_id);
		return;
	}

	// Broadcast and multicast frames are copied in the default queue of each tenant.
	// If the tenant is unique, the packet is cloned for each destination address but it is not aggregated
	// since the default queue does not aggregate by the moment.
	// If the tenant is shared, the frame is just enqueued holding the original DA.

	for (TrafficRulesQueuesIter it_tr_queues = _traffic_rules.begin(); it_tr_queues.live(); it_tr_queues++) {
		if (it_tr_queues.key()._dscp != _default_dscp) {
			continue;
		}
		Packet *q = p->clone();
		if (!q) {
			continue;
		}

		if (it_tr_queues.value()->_tenant_type == EMPOWER_TYPE_UNIQUE) {
			for (LVAPIter it = _el->lvaps()->begin(); it.live(); it++) {
				if (it.value()._ssid != it_tr_queues.key()._tenant) {
					continue;
				}

				// Clone the packet for each lvap in this tenant
				Packet *pq = q->clone();
				if (!pq) {
					continue;
				}

				// The lvap is not attached to this interface
				if (it.value()._iface_id != iface_id){
					pq->kill();
					return;
				}

				BufferQueue * tr_queue = get_traffic_rule(_default_dscp, it.value()._ssid);
				if (tr_queue) {
					click_chatter("%{element} :: %s :: Multicast unique Queue found in unicast SSID %s DSCP %d exists. Dst %s",
									this, __func__,
									it.value()._ssid.c_str(),
									_default_dscp,
									dst.unparse().c_str());
				}


				// Change the DA to the unicast one
				// TODO. Not to change the address if the dst is broadcast
				WritablePacket *unicast_pkt = pq->uniqueify();
				if (!unicast_pkt) {
					tr_queue->_dropped_packets++;
					tr_queue->_dropped_msdus ++;
					tr_queue->_dropped_bytes += unicast_pkt->length();
					_drops++;
					_bdrops += unicast_pkt->length();
					unicast_pkt->kill();
					return;
				}

				click_ether *ethh = reinterpret_cast<click_ether *>(unicast_pkt->data());

				memcpy(ethh->ether_dhost, it.value()._sta.data(), 6);
				enqueue_unicast_frame(dst,tr_queue, (Packet *) unicast_pkt, it.value()._lvap_bssid, it.value()._iface_id);
			}
		} else {
			// EMPOWER_TYPE_SHARED
			// If the tenant is shared the frame should be duplicated as many as VAPs (as many as bssids) if the the policy is legacy.
			// if it is DMS the DA does not change, but the bssid is set to each lvap (as many as lvaps)
			BufferQueueInfo tr_key (_default_dscp,it_tr_queues.key()._tenant);
			BufferQueue * tr_queue = get_traffic_rule(_default_dscp,it_tr_queues.key()._tenant);

			TxPolicyInfo * tx_policy = _el->get_tx_policies(iface_id)->lookup(dst);

			if (tx_policy->_tx_mcast == TX_MCAST_DMS) {
				click_chatter("%{element} :: %s :: Multicast shared dms",
														this, __func__);
				// dms mcast policy, duplicate the frame for each station in
				// each bssid and use unicast destination addresses. note that
				// a given station cannot be in more than one bssid, so just
				// track if the frame has already been delivered to a given
				// station.

				Vector<EtherAddress> sent;
				for (LVAPIter it = _el->lvaps()->begin(); it.live(); it++) {
					// TODO. This should be checked? What about the ARP or similar traffic?
					if (it.value()._ssid != it_tr_queues.key()._tenant) {
						continue;
					}

					// If the lvap_bssid and the net_bssid is the same, it means this client is
					// attached to a unique tenant instead of to a shared one
					if (it.value()._lvap_bssid == it.value()._net_bssid) {
						continue;
					}

					EtherAddress sta = it.value()._sta;
					if (it.value()._iface_id != iface_id) {
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
					enqueue_unicast_frame(sta, tr_queue, q, it.value()._lvap_bssid, it.value()._iface_id);
				}

			} else if (tx_policy->_tx_mcast == TX_MCAST_UR) {

				// TODO: implement

			} else {

				click_chatter("%{element} :: %s :: Multicast shared legacy o bdcast",
														this, __func__);

				// legacy mcast policy, just send the frame as it is, minstrel will
				// pick the rate from the transmission policies table

				Vector<EtherAddress> sent;

				for (LVAPIter it = _el->lvaps()->begin(); it.live(); it++) {
					// TODO. This should be checked? What about the ARP or similar traffic?
//						if (it.value()._ssid != it_tr_queues.key()._tenant) {
//							continue;
//						}
					EtherAddress bssid = it.value()._lvap_bssid;

					// If the lvap_bssid and the net_bssid is the same, it means this client is
					// attached to a unique tenant instead of to a shared one
					if (it.value()._lvap_bssid == it.value()._net_bssid) {
						continue;
					}

					if (it.value()._iface_id != iface_id) {
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
					enqueue_unicast_frame(dst, tr_queue, q, bssid, it.value()._iface_id);
				}

			}

		}
	}
}

void
EmpowerQoSManager::enqueue_unicast_frame(EtherAddress dst, BufferQueue * tr_queue, Packet * p, EtherAddress bssid, int iface) {
	click_chatter("%{element} :: %s :: enqueue function",
											this, __func__);

	if (!tr_queue) {
		click_chatter("%{element} :: %s :: The queue does not exist",
														this, __func__);
		return;
	}

	if (_clients_current_frame.find(dst) == _clients_current_frame.end()) {
		click_chatter("%{element} :: %s :: frame not in clients hashmap dst %s",
												this, __func__,
												dst.unparse().c_str());
		FrameInfo * new_frame = new FrameInfo();
		new_frame->_frame = p->uniqueify();
		if (!new_frame->_frame) {
			click_chatter("%{element} :: %s :: The frame does not exist",
													this, __func__);
			new_frame->_frame->kill();
			tr_queue->_dropped_packets++;
			return;
		}
		new_frame->_frame_length = new_frame->_frame->length();
		new_frame->_msdus = 1;
		new_frame->_dst = dst;
		new_frame->_bssid = bssid;
		new_frame->_iface = iface;

		if (tr_queue->_frames.size() == 0) {
			_empty_traffic_rules--;
		}

		tr_queue->_buffer_queue_lock.acquire_write();
		BufferQueueInfo key = get_traffic_rule_info(tr_queue);

		if (tr_queue->_amsdu_aggregation) {
			_clients_current_frame.set(dst, new_frame);

			click_chatter("%{element} :: %s :: setting element in clients hashmap for dst %s dscp %d tenant %s",
																this, __func__,
																dst.unparse().c_str(),
																key._dscp,
																key._tenant.c_str());
		} else {
			new_frame->_complete = true;
		}

		tr_queue->_frames.push_back(new_frame);
		_notifier.wake();
		tr_queue->_buffer_queue_lock.release_write();
	} else {

		click_chatter("%{element} :: %s :: frame in clients hashmap",
														this, __func__);

		FrameInfo * current_frame = _clients_current_frame.get(dst);

		if (((current_frame->_frame_length + (int)p->length()) > tr_queue->_max_length) || current_frame->_complete) {
			current_frame->_complete = true;
			FrameInfo * new_frame = new FrameInfo();

			new_frame->_frame = p->uniqueify();
			if (!new_frame->_frame) {
				new_frame->_frame->kill();
				tr_queue->_dropped_packets++;
				return;
			}
			new_frame->_frame_length = new_frame->_frame->length();
			new_frame->_msdus++;
			new_frame->_dst = dst;
			new_frame->_bssid = bssid;
			new_frame->_iface = iface;
			_clients_current_frame.set(dst, new_frame);
			tr_queue->_buffer_queue_lock.acquire_write();
			tr_queue->_frames.push_back(new_frame);
			_notifier.wake();
			tr_queue->_buffer_queue_lock.release_write();
		} else {
			WritablePacket *q = current_frame->_frame->put(p->length());
			if (!q) {
				tr_queue->_buffer_queue_lock.acquire_write();
				_clients_current_frame.erase(_clients_current_frame.find(dst));
				tr_queue->discard_frame(current_frame);
				tr_queue->_dropped_packets++;
				tr_queue->_buffer_queue_lock.release_write();
				return;
			}
			current_frame->_frame = q;
			click_chatter("%{element} :: %s :: not complete. adding frame",
															this, __func__);
			memcpy(current_frame->_frame->data() + current_frame->_frame_length, p->data(), p->length());
			current_frame->_frame_length += current_frame->_frame->length();
			current_frame->_msdus++;
			current_frame->_average_time_diff = std::max(current_frame->_average_time_diff, (Timestamp::now() - current_frame->_last_frame_time));
			current_frame->_last_frame_time = Timestamp::now();
		}
		// Check if it can wait for the next frame to complete this one
		int transm_time = frame_transmission_time(dst, current_frame->_frame_length, iface);
		if (tr_queue->_deadline_discard &&
				((Timestamp::make_usec(transm_time) + current_frame->_average_time_diff) > Timestamp::make_usec(tr_queue->_max_delay))) {
			current_frame->_complete = true;
		}
	}
}

Packet *
EmpowerQoSManager::pull(int) {
	bool delivered_packet = false;

	if (_traffic_rules.size() == _empty_traffic_rules) {
		// TODO. Check the behavior of the notifier
		_notifier.sleep();
		click_chatter("%{element} :: %s :: ----- All the buffer queues are empty: %d ----- ",
										 this,
										 __func__,
										 _empty_traffic_rules);
		return 0;
	}

	// TODO. Add ordering in a slice by...? expiration time?
	while (!delivered_packet && _traffic_rules.size() != _empty_traffic_rules) {
		BufferQueueInfo queue_info = _rr_order.front();
		BufferQueue * tr_queue =  _traffic_rules.get(queue_info);

		while (tr_queue && tr_queue->_frames.size()) {
			// TODO. By the moment is done taking the first one. This must be improved
			// TODO. What happens if I go to a queue and the packet is not still completed? Shall I wait? Shall I take the next one?
			FrameInfo *next_frame = tr_queue->pull();
			if (tr_queue->_amsdu_aggregation) {
				_clients_current_frame.erase(_clients_current_frame.find(next_frame->_dst));
			}

			// If the transmission time + the time that the frame has been in the queue exceeds the delay deadline
			// this frame is discarded
			int transm_time = frame_transmission_time(next_frame->_dst, next_frame->_frame_length, next_frame->_iface);
			if (!tr_queue->_deadline_discard ||
					(tr_queue->_deadline_discard && !tr_queue->check_delay_deadline(next_frame, transm_time))) {
				// If it is the first time of this queue and it is not empty, a new deficit must be assigned
				if (tr_queue->_first_pkt) {
					// TODO. compute quantum
					//slice->_quantum = 1000; // TODO. CHANGE OF COURSE
					tr_queue->_deficit += tr_queue->_quantum;
					tr_queue->_first_pkt = false;
					click_chatter("%{element} :: %s :: ----- First packet. Adding deficit. Deficit %d, quantum %d ----- ",
																 this,
																 __func__,
																 tr_queue->_deficit,
																 tr_queue->_quantum);
				}
				if (tr_queue->_deficit >= transm_time) {
					delivered_packet = true;
					tr_queue->_deficit -= transm_time;
					tr_queue->_total_consumed_time += transm_time;
					tr_queue->_transmitted_packets ++;
					tr_queue->_transmitted_msdus += next_frame->_msdus;
					tr_queue->_transmitted_bytes += next_frame->_frame_length;

					EtherAddress dst = next_frame->_dst;

					tr_queue->remove_frame_from_queue(next_frame);

					click_chatter("%{element} :: %s :: ----- PULL in traffic rule queue (%d, %s) for station  %s. Remaining deficit %d. "
							"Remaining packets %d (Consumption: time %d packets %d msdus %d bytes %d ---- ",
																			 this,
																			 __func__,
																			 queue_info._dscp,
																			 queue_info._tenant.c_str(),
																			 dst.unparse().c_str(),
																			 tr_queue->_deficit,
																			 tr_queue->_frames.size(),
																			 tr_queue->_total_consumed_time,
																			 tr_queue->_transmitted_packets,
																			 tr_queue->_transmitted_msdus,
																			 tr_queue->_transmitted_bytes);

					if (tr_queue->_frames.size() == 0) {
						tr_queue->_deficit = 0;
						_empty_traffic_rules ++;
					}
					return empower_wifi_encap(next_frame);
				} else {
					break;
				}
			} else {
				tr_queue->_dropped_packets++;
				tr_queue->_dropped_msdus += next_frame->_msdus;
				tr_queue->_dropped_bytes += next_frame->_frame_length;
				_drops++;
				_bdrops += next_frame->_frame_length;
				tr_queue->discard_frame(next_frame);
			}
		}

		tr_queue->_first_pkt = true;
		_rr_order.push_back(queue_info);
		_rr_order.pop_front();
	}
	click_chatter("%{element} :: %s :: ----- There is no more packets----- ",
												 this,
												 __func__);
	return 0;
}

int
EmpowerQoSManager::frame_transmission_time(EtherAddress next_delireved_client, int pkt_length, int iface) {

	int rate, nb_retransm = 0;
	uint32_t usecs = 1000000;
	TxPolicyInfo * tx_policy = _el->get_tx_policies(iface)->supported(next_delireved_client);
	MinstrelDstInfo * nfo = _el->get_dst_info(next_delireved_client);

	if (!next_delireved_client.is_group() && !next_delireved_client.is_broadcast() &&
			nfo && nfo->rates.size() > 0 && nfo->max_tp_rate < nfo->rates.size()) {
		rate = (nfo->rates[nfo->max_tp_rate]);
		// Probabilities must be divided by 180 to obtain a percentage 97.88
		int success_prob = nfo->probability[nfo->max_tp_rate];
		if (success_prob > 0) {
			// To obtain the number of retransmissions, it must be 1/(percentg./100) -> 180*100 = 18000
			success_prob = 18000/success_prob;
			nb_retransm = (int) ((1 / success_prob) + 0.5); // To truncate properly
		} else {
			nb_retransm = 0;
		}
		// In case the nb_transm is higher than 1 it is also considering the first transm
		// For example... prob success = 0.8 -> 1/0.8 = 1.25. It will sent the packets, 1.25 times.
		// When truncating it becomes 1, but the number of retransmissions is 0. The first one is the transmission.
		if (nb_retransm >= 1)
			nb_retransm --;
	} else {
		if(!tx_policy || tx_policy->_ht_mcs.size() == 0) {
			Vector<int> rates = _el->get_tx_policies(iface)->lookup(next_delireved_client)->_mcs;
			rate = (rates.size()) ? rates[0] : 2;
		}
		else {
			Vector<int> ht_rates = _el->get_tx_policies(iface)->lookup(next_delireved_client)->_ht_mcs;
			rate = (ht_rates.size()) ? ht_rates[0] : 2;
		}
	}

	if(tx_policy && tx_policy->_ht_mcs.size()) {
		usecs = calc_usecs_wifi_packet_ht(pkt_length, rate, nb_retransm);
	}
	else {
		usecs = calc_usecs_wifi_packet(pkt_length, rate, nb_retransm);
	}

	return usecs;
}

String
EmpowerQoSManager::list_traffic_rules() {
	StringAccum sa;
	for (TrafficRulesQueuesIter it =_traffic_rules.begin(); it.live(); it++) {
		if (it.value()->_tenant_type == EMPOWER_TYPE_SHARED) {
			sa << "Shared";
		} else {
			sa << "Unique";
		}
		sa << " tenant ";
		sa << it.key()._tenant;
		sa << " dscp ";
		sa << it.key()._dscp;
		sa << " parent priority ";
		sa << it.value()->_parent_priority;
		sa << " priority ";
		sa << it.value()->_priority;
		if (it.value()->_amsdu_aggregation) {
			sa << " A-MSDU aggr.";
		} else {
			sa << " Non A-MSDU aggr.";
		}
		if (it.value()->_ampdu_aggregation) {
			sa << " A-MPDU aggr.";
		} else {
			sa << " Non A-MPDU aggr.";
		}
		if (it.value()->_deadline_discard) {
			sa << " Deadline drop";
		} else {
			sa << " Non deadline drop";
		}
		sa << " max. delay ";
		sa << it.value()->_max_delay;
		sa << " max. length ";
		sa << it.value()->_max_length;
		sa << " deficit ";
		sa << it.value()->_deficit;
		sa << " quantum ";
		sa << it.value()->_quantum;
		sa << " consumed time ";
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
		sa << " packets in the queue ";
		sa << it.value()->_frames.size();
		sa << "\n";
	}
//	click_chatter("%{element} :: %s :: ----- %s ---- ",
//									 this,
//									 __func__,
//									 sa.take_string().c_str());
	return sa.take_string();
}

String
EmpowerQoSManager::list_traffic_rule(BufferQueue * traffic_rule) {
	StringAccum sa;
	BufferQueueInfo key = get_traffic_rule_info(traffic_rule);
	if (traffic_rule->_tenant_type == EMPOWER_TYPE_SHARED) {
		sa << "Shared";
	} else {
		sa << "Unique";
	}
	sa << " tenant ";
	sa << key._tenant;
	sa << " dscp ";
	sa << key._dscp;
	sa << " parent priority ";
	sa << traffic_rule->_parent_priority;
	sa << " priority ";
	sa << traffic_rule->_priority;
	if (traffic_rule->_amsdu_aggregation) {
		sa << " A-MSDU aggr.";
	} else {
		sa << " Non A-MSDU aggr.";
	}
	if (traffic_rule->_ampdu_aggregation) {
		sa << " A-MPDU aggr.";
	} else {
		sa << " Non A-MPDU aggr.";
	}
	if (traffic_rule->_deadline_discard) {
		sa << " Deadline drop";
	} else {
		sa << " Non deadline drop";
	}
	sa << " max. delay ";
	sa << traffic_rule->_max_delay;
	sa << " max. length ";
	sa << traffic_rule->_max_length;
	sa << " deficit ";
	sa << traffic_rule->_deficit;
	sa << " quantum ";
	sa << traffic_rule->_quantum;
	sa << " consumed time ";
	sa << traffic_rule->_total_consumed_time;
	sa << " dropped pkts ";
	sa << traffic_rule->_dropped_packets;
	sa << " dropped msdus ";
	sa << traffic_rule->_dropped_msdus;
	sa << " dropped bytes ";
	sa << traffic_rule->_dropped_bytes;
	sa << " transm. msdus ";
	sa << traffic_rule->_transmitted_msdus;
	sa << " transm. pkts ";
	sa << traffic_rule->_transmitted_packets;
	sa << " transm. bytes ";
	sa << traffic_rule->_transmitted_bytes;
	sa << " packets in the queue ";
	sa << traffic_rule->_frames.size();
	sa << "\n";

//	click_chatter("%{element} :: %s :: ----- %s ---- ",
//								 this,
//								 __func__,
//								 sa.take_string().c_str());

	return sa.take_string();
}

String
EmpowerQoSManager::list_user_frames() {
	StringAccum sa;
	for (UserFramesIter it =_clients_current_frame.begin(); it.live(); it++) {
		sa << "Client ";
		sa << it.key().unparse();
		sa << " arrival time ";
		sa << it.value()->_arrival_time;
		sa << " average time diff ";
		sa << it.value()->_average_time_diff;
		sa << " _last frame time ";
		sa << it.value()->_last_frame_time;
		if (it.value()->_complete) {
			sa << " complete";
		} else {
			sa << " not complete";
		}
		sa << " frame length ";
		sa << it.value()->_frame_length;
		sa << " msdus ";
		sa << it.value()->_msdus;
		sa << " dst ";
		sa << it.value()->_dst.unparse();
		sa << " bssid ";
		sa << it.value()->_bssid.unparse();
		sa << " iface ";
		sa << it.value()->_iface;
		sa << "\n";
	}
//	click_chatter("%{element} :: %s :: ----- %s ---- ",
//									 this,
//									 __func__,
//									 sa.take_string().c_str());
	return sa.take_string();
}

void
EmpowerQoSManager::request_traffic_rule(int dscp, String tenant, empower_tenant_types tenant_type, int priority,
		int parent_priority, bool amsdu_aggregation, bool ampdu_aggregation, bool deadline_discard) {

	BufferQueueInfo queue_info(dscp, tenant);
	BufferQueue * tr_queue;

	_traffic_rules_lock.acquire_write();

	if (_traffic_rules.find(queue_info) == _traffic_rules.end()) {
		// TODO. Decide how to set the priority and parent_priority
		int max_delay = map_dscp_to_delay(dscp);

		click_chatter("%{element} :: %s :: Requesting traffic rule tenant %s dscp %d tenant type %d priority %d"
					"parent priority %d max delay %d %s %s %s",
								  this,
								  __func__,
								  tenant.c_str(),
								  dscp,
								  tenant_type,
								  priority,
							      parent_priority,
								  max_delay,
								  amsdu_aggregation ? "A-MSDU aggr." : "no A-MSDU aggr.",
								  ampdu_aggregation ? "A-MPDU aggr." : "no A-MSDU aggr.",
								  deadline_discard ? "dealine" : "no deadline");

		BufferQueue * tr_queue = new BufferQueue (tenant_type, priority, parent_priority, max_delay,
				amsdu_aggregation, ampdu_aggregation, deadline_discard);
		_traffic_rules.set(queue_info, tr_queue);
		_rr_order.push_back(queue_info);
		_empty_traffic_rules++;
	}

	_traffic_rules_lock.release_write();
}

void
EmpowerQoSManager::remove_traffic_rule_resources(int dscp, String tenant) {
	int tenant_air_time_portion = 0;


}

void
EmpowerQoSManager::release_traffic_rule(int dscp, String tenant) {
	BufferQueueInfo tr_key (dscp, tenant);
	BufferQueue * tr_queue = get_traffic_rule(dscp, tenant);

	if (!tr_queue){
		click_chatter("%{element} :: %s :: The requested traffic rule queue SSID %s DSCP %d does not exist",
				this, __func__,
				tenant.c_str(),
				dscp);
		return;
	}

	_traffic_rules_lock.acquire_write();

	// Calculates the sum of the priorities of the remaining queues from the same tenant
	int tenant_priorities = 0;
	for (TrafficRulesQueuesIter it_tr_queues = _traffic_rules.begin(); it_tr_queues.live(); it_tr_queues++) {
		if (it_tr_queues.key()._tenant == tenant && it_tr_queues.key()._dscp != dscp) {
			tenant_priorities += it_tr_queues.value()->_priority;
		}
	}

	// The bandwidth is reassigned to the other queues from the same tenant
	for (TrafficRulesQueuesIter it_tr_queues = _traffic_rules.begin(); it_tr_queues.live(); it_tr_queues++) {
		if (it_tr_queues.key()._tenant == tenant && it_tr_queues.key()._dscp != dscp) {
			it_tr_queues.value()->_priority = (tr_queue->_priority * it_tr_queues.value()->_priority) / tenant_priorities;
		}
	}

	// If the queue was empty, the empty queues counter should be decreased
	if (tr_queue->_frames.size() == 0)
		_empty_traffic_rules--;

	// The frames in the inner queues are also deleted
	for (Vector<FrameInfo*>::iterator it = tr_queue->_frames.begin(); it != tr_queue->_frames.end(); it++) {
		(*it)->_frame->kill();
		delete (*it);
	}
	tr_queue->_frames.clear();

	// The queue is erased from the scheduler and the RR order
	for (Vector <BufferQueueInfo>::iterator it = _rr_order.begin(); it != _rr_order.end(); )
	   if((*it) == tr_key) {
	      it = _rr_order.erase(it);
	      break;
	   }
	delete tr_queue;
	_traffic_rules.erase(_traffic_rules.find(tr_key));

	_traffic_rules_lock.release_write();
}

Packet *
EmpowerQoSManager::empower_wifi_encap(FrameInfo * next_frame) {
	if (!next_frame) {
		click_chatter("%{element} :: %s :: The next frame is not valid",
								  this,
								  __func__);
		return 0;
	}

	Packet *p = (Packet *) next_frame->_frame;
	if (!next_frame) {
		click_chatter("%{element} :: %s :: The next frame is not valid",
								  this,
								  __func__);
		return 0;
	}
	click_ether *eh = (click_ether *) p->data();
	EtherAddress src = EtherAddress(eh->ether_shost);
//	EtherAddress dst = EtherAddress(eh->ether_dhost);
	EtherAddress dst = next_frame->_dst;

	TxPolicyInfo *tx_policy = _el->get_tx_policies(next_frame->_iface)->lookup(dst);

	// unicast traffic
	if (!dst.is_broadcast() && !dst.is_group()) {
		EmpowerStationState *ess = _el->get_ess(dst);
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
		tx_policy->update_tx(p->length());
		return p_out;
	}

	// broadcast and multicast traffic, we need to transmit one frame for each unique
	// bssid. this is due to the fact that we can have the same bssid for multiple LVAPs.
	Packet * p_out = wifi_encap(p, dst, src, next_frame->_bssid);
	tx_policy->update_tx(p->length());
	return p_out;
}

Packet *
EmpowerQoSManager::wifi_encap(Packet *q, EtherAddress dst, EtherAddress src, EtherAddress bssid) {

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
EmpowerQoSManager::map_dscp_to_delay(int dscp) {
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
		delay = 5000;
	}
	return delay;
}

enum { H_DROPS,
	H_DEBUG,
	H_BYTEDROPS,
	H_LIST_QUEUES
};

void
EmpowerQoSManager::add_handlers()
{
	add_read_handler("drops", read_handler, (void*)H_DROPS);
	add_read_handler("byte_drops", read_handler, (void*)H_BYTEDROPS);
	add_read_handler("list_queues", read_handler, (void*)H_LIST_QUEUES);
	add_write_handler("debug", write_handler, (void *) H_DEBUG);
}

int EmpowerQoSManager::write_handler(const String &in_s, Element *e,
		void *vparam, ErrorHandler *errh) {

	EmpowerQoSManager *f = (EmpowerQoSManager *) e;
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

String
EmpowerQoSManager::read_handler(Element *e, void *thunk)
{
	EmpowerQoSManager *c = (EmpowerQoSManager *)e;
	switch ((intptr_t)thunk) {
	case H_DEBUG:
		return String(c->_debug) + "\n";
	case H_DROPS:
		return(String(c->drops()) + "\n");
	case H_BYTEDROPS:
		return(String(c->bdrops()) + "\n");
	case H_LIST_QUEUES:
		return(c->list_traffic_rules());
	default:
		return "<error>\n";
	}
}

CLICK_ENDDECLS
EXPORT_ELEMENT(EmpowerQoSManager)
