/*
 * empowerigmpmembership.{cc,hh} -- handle igmp join requests (EmPOWER Access Point)
 * Estefania Coronado
 *
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "empowerigmpmembership.hh"
#include <click/args.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <click/error.hh>
#include <clicknet/wifi.h>
#include <elements/wifi/minstrel.hh>
#include "empowerpacket.hh"
#include "empowerlvapmanager.hh"
CLICK_DECLS

EmpowerIgmpMembership::EmpowerIgmpMembership() :
		_el(0), _debug(false) {
}

EmpowerIgmpMembership::~EmpowerIgmpMembership() {
}

int EmpowerIgmpMembership::configure(Vector<String> &conf,
		ErrorHandler *errh) {

	int ret = Args(conf, this, errh)
              .read_m("EL", ElementCastArg("EmpowerLVAPManager"), _el)
			  .read("DEBUG", _debug).complete();

	return ret;

}

void EmpowerIgmpMembership::push(int, Packet *p) {

	if (p->length() < sizeof(struct click_ether)) {
			click_chatter("%{element} :: %s :: packet too small: %d vs %d",
					      this,
					      __func__,
					      p->length(),
					      sizeof(struct click_ether));
			p->kill();
			return;
		}

	click_ether *eh = (click_ether *) p->data();

	EtherAddress src = EtherAddress(eh->ether_shost);
	EtherAddress dst = EtherAddress(eh->ether_dhost);

	int ether_type =



}

void EmpowerAssociationResponder::send_association_response(EtherAddress dst,
		uint16_t status, int iface_id) {

    EmpowerStationState *ess = _el->get_ess(dst);
	ess->_association_status = true;

	if (_debug) {
		click_chatter("%{element} :: %s :: association %s assoc_id %d",
				      this,
				      __func__,
				      dst.unparse().c_str(),
				      ess->_assoc_id);
	}

	int max_len = sizeof(struct click_wifi) + 2 + /* cap_info */
											  2 + /* status  */
											  2 + /* assoc_id */
											  2 + WIFI_RATES_MAXSIZE + /* rates */
											  2 + WIFI_RATES_MAXSIZE + /* xrates */
											  0;

	WritablePacket *p = Packet::make(max_len);

	if (!p) {
		click_chatter("%{element} :: %s :: cannot make packet!",
				      this,
				      __func__);
		return;
	}

	struct click_wifi *w = (struct click_wifi *) p->data();

	w->i_fc[0] = WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_MGT
			| WIFI_FC0_SUBTYPE_ASSOC_RESP;
	w->i_fc[1] = WIFI_FC1_DIR_NODS;

	memcpy(w->i_addr1, dst.data(), 6);
	memcpy(w->i_addr2, ess->_lvap_bssid.data(), 6);
	memcpy(w->i_addr3, ess->_lvap_bssid.data(), 6);

	w->i_dur = 0;
	w->i_seq = 0;

	uint8_t *ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);
	int actual_length = sizeof(struct click_wifi);

	uint16_t cap_info = 0;
	cap_info |= WIFI_CAPINFO_ESS;
	*(uint16_t *) ptr = cpu_to_le16(cap_info);
	ptr += 2;
	actual_length += 2;

	*(uint16_t *) ptr = cpu_to_le16(status);
	ptr += 2;
	actual_length += 2;

	*(uint16_t *) ptr = cpu_to_le16(0xc000 | ess->_assoc_id);
	ptr += 2;
	actual_length += 2;

	/* rates */

	TransmissionPolicies * tx_table = _el->get_tx_policies(iface_id);

	Vector<int> rates = tx_table->lookup(ess->_sta)->_mcs;
	ptr[0] = WIFI_ELEMID_RATES;
	ptr[1] = WIFI_MIN(WIFI_RATE_SIZE, rates.size());
	for (int x = 0; x < WIFI_MIN(WIFI_RATE_SIZE, rates.size()); x++) {
		ptr[2 + x] = (uint8_t) rates[x];
		if (rates[x] == 2 || rates[x] == 12) {
			ptr[2 + x] |= WIFI_RATE_BASIC;
		}
	}
	ptr += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());
	actual_length += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());

	int num_xrates = rates.size() - WIFI_RATE_SIZE;
	if (num_xrates > 0) {
		/* rates */
		ptr[0] = WIFI_ELEMID_XRATES;
		ptr[1] = num_xrates;
		for (int x = 0; x < num_xrates; x++) {
			ptr[2 + x] = (uint8_t) rates[x + WIFI_RATE_SIZE];
			if (rates[x + WIFI_RATE_SIZE] == 2 || rates[x + WIFI_RATE_SIZE] == 12) {
				ptr[2 + x] |= WIFI_RATE_BASIC;
			}
		}
		ptr += 2 + num_xrates;
		actual_length += 2 + num_xrates;
	}

	p->take(max_len - actual_length);

	_el->send_status_lvap(dst);

	SET_PAINT_ANNO(p, iface_id);
	output(0).push(p);

}

enum {
	H_DEBUG
};

String EmpowerAssociationResponder::read_handler(Element *e, void *thunk) {
	EmpowerAssociationResponder *td = (EmpowerAssociationResponder *) e;
	switch ((uintptr_t) thunk) {
	case H_DEBUG:
		return String(td->_debug) + "\n";
	default:
		return String();
	}
}

int EmpowerAssociationResponder::write_handler(const String &in_s, Element *e,
		void *vparam, ErrorHandler *errh) {

	EmpowerAssociationResponder *f = (EmpowerAssociationResponder *) e;
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

void EmpowerAssociationResponder::add_handlers() {
	add_read_handler("debug", read_handler, (void *) H_DEBUG);
	add_write_handler("debug", write_handler, (void *) H_DEBUG);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(EmpowerAssociationResponder)
