/*
 * empowercollisionsniffer.cc
 *
 *  Created on: Jun 8, 2017
 *      Author: estefania
 */


#include <click/config.h>
#include "empowercollisionsniffer.hh"
#include <click/args.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <click/error.hh>
#include <clicknet/wifi.h>
#include <elements/wifi/minstrel.hh>
#include "empowerpacket.hh"
#include "empowerlvapmanager.hh"
#include <click/string.hh>
CLICK_DECLS

void send_surrounding_aps_trigger_callback(Timer *timer, void *data) {
	// send summary
	SummaryTrigger *summary = (SummaryTrigger *) data;
	summary->_ers->lock.acquire_write();
	summary->_el->send_summary_trigger(summary);
	summary->_sent++;
	summary->_ers->lock.release_write();
	if (summary->_limit > 0 && summary->_sent >= (unsigned) summary->_limit) {
		summary->_ers->del_summary_trigger(summary->_trigger_id);
		return;
	}
	// re-schedule the timer
	timer->schedule_after_msec(summary->_period);
}

EmpowerCollisionSniffer::EmpowerCollisionSniffer() :
		_el(0), _debug(false) {
}

EmpowerCollisionSniffer::~EmpowerCollisionSniffer() {
}

int EmpowerCollisionSniffer::initialize(ErrorHandler *) {
	_timer.initialize(this);
	_timer.schedule_now();
	return 0;
}

int EmpowerCollisionSniffer::configure(Vector<String> &conf,
		ErrorHandler *errh) {

	int ret = Args(conf, this, errh)
              .read_m("EL", ElementCastArg("EmpowerLVAPManager"), _el)
			  .read("DEBUG", _debug).complete();

	return ret;

}

Packet *
EmpowerCollisionSniffer::simple_action(Packet *p) {

	if (p->length() < sizeof(struct click_wifi)) {
		click_chatter("%{element} :: %s :: Packet too small: %d Vs. %d",
				      this,
				      __func__,
				      p->length(),
				      sizeof(struct click_wifi));
		p->kill();
		return 0;
	}

	struct click_wifi *w = (struct click_wifi *) p->data();

	unsigned wifi_header_size = sizeof(struct click_wifi);

	if ((w->i_fc[1] & WIFI_FC1_DIR_MASK) == WIFI_FC1_DIR_DSTODS)
		wifi_header_size += WIFI_ADDR_LEN;

	if (WIFI_QOS_HAS_SEQ(w))
		wifi_header_size += sizeof(uint16_t);

	struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);

	if ((ceh->magic == WIFI_EXTRA_MAGIC) && ceh->pad && (wifi_header_size & 3))
		wifi_header_size += 4 - (wifi_header_size & 3);

	if (p->length() < wifi_header_size) {
		return p;
	}

	int type = w->i_fc[0] & WIFI_FC0_TYPE_MASK;
	int subtype = w->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;
	uint8_t *ptr;
	String ssid_str = "";
	char* ssid = "";



	// The SSID of the network can be obtained from the beacon frames
	if (type == WIFI_FC0_TYPE_MGT && subtype == WIFI_FC0_SUBTYPE_BEACON)
	{
		ptr = (uint8_t *) (w+1);

		//uint8_t *ts = ptr;
		ptr += 8;

		uint16_t beacon_int = le16_to_cpu(*(uint16_t *) ptr);
		ptr += 2;

		uint16_t capability = le16_to_cpu(*(uint16_t *) ptr);
		ptr += 2;

		uint8_t *end  = (uint8_t *) p->data() + p->length();
		uint8_t *ssid_l = NULL;

		while (ptr < end)
		{
			switch (*ptr)
			{
				case WIFI_ELEMID_SSID:
					ssid_l = ptr;
					break;
			}
			ptr += ptr[1] + 2;
		}

		if (ssid_l && ssid_l[1]) {
			ssid_str = String((char *) ssid_l + 2, WIFI_MIN((int)ssid_l[1], WIFI_NWID_MAXSIZE));
			ssid = new char[ssid_str.length() + 1];
			strcpy(ssid, ssid_str.c_str());

		}
	}

	EtherAddress ra = EtherAddress(w->i_addr1);
	EtherAddress ta = EtherAddress(w->i_addr2);
	EtherAddress bssid = EtherAddress(w->i_addr3);

	int8_t rssi;
	memcpy(&rssi, &ceh->rssi, sizeof(rssi));

	int16_t channel;
	memcpy(&channel, &ceh->channel, sizeof(channel));

	uint8_t iface_id = PAINT_ANNO(p);

	lock.acquire_write();
	update_surrounding_aps(bssid, channel, iface_id, ssid);
	lock.release_write();

	return p;

}

void EmpowerCollisionSniffer::update_surrounding_aps(EtherAddress bssid, int16_t channel, uint8_t iface_id, char* ssid) {

	DomainInfo *nfo = aps.get_pointer(bssid);

	if (!nfo) {
		aps[bssid] = DomainInfo();
		nfo = aps.get_pointer(bssid);
		nfo->_iface_id = iface_id;
		nfo->_ap = bssid;
		nfo->_channel = channel;
		nfo->_ssid = ssid;

		click_chatter("%{element} :: %s :: NEW AP %s",
									  this,
									  __func__,
									  bssid.unparse().c_str());
	}



	// Add sample
	nfo->add_sample(ssid, channel);

}


enum {
	H_DEBUG
};

String EmpowerCollisionSniffer::read_handler(Element *e, void *thunk) {
	EmpowerCollisionSniffer *td = (EmpowerCollisionSniffer *) e;
	switch ((uintptr_t) thunk) {
	case H_DEBUG:
		return String(td->_debug) + "\n";
	default:
		return String();
	}
}

int EmpowerCollisionSniffer::write_handler(const String &in_s, Element *e,
		void *vparam, ErrorHandler *errh) {

	EmpowerCollisionSniffer *f = (EmpowerCollisionSniffer *) e;
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

void EmpowerCollisionSniffer::add_handlers() {
	add_read_handler("debug", read_handler, (void *) H_DEBUG);
	add_write_handler("debug", write_handler, (void *) H_DEBUG);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(EmpowerCollisionSniffer)

