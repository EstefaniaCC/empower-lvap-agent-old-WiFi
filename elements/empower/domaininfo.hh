#ifndef CLICK_EMPOWER_DOMAININFO_HH
#define CLICK_EMPOWER_DOMAININFO_HH
#include <click/straccum.hh>
#include <click/etheraddress.hh>
#include <click/hashcode.hh>
#include <click/timer.hh>
#include <click/vector.hh>
#include "frame.hh"
CLICK_DECLS

class DomainInfo {
public:
	EtherAddress _ap;
	int _channel;
	char * _ssid;
	unsigned _silent_window_count;
	int _iface_id;
	Timestamp _last_received;

	DomainInfo() {
		_ap = EtherAddress();
		_silent_window_count = 0;
		_iface_id = -1;
		_channel = 0;
		_ssid = "";
	}

	~DomainInfo() {
	}

	void update() {
	}

	void add_sample(char * ssid, int16_t channel) {
		_last_received.assign_now();
		_channel = channel;
		_ssid = ssid;
	}

	String unparse() {
		Timestamp now = Timestamp::now();
		StringAccum sa;
		Timestamp age = now - _last_received;
		sa << _ap.unparse();
		sa << " channel " << _channel;
		sa << " ssid " << _ssid;
		sa << " last_received " << age;
		sa << " silent_window_count " << _silent_window_count;
		sa << " iface_id " << _iface_id << "\n";
		return sa.take_string();
	}
};

CLICK_ENDDECLS
#endif /* CLICK_EMPOWER_DOMAININFO_HH */
