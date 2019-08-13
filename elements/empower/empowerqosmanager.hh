// -*- mode: c++; c-basic-offset: 2 -*-
#ifndef CLICK_EMPOWERQOSMANAGER_HH
#define CLICK_EMPOWERQOSMANAGER_HH
#include <click/config.h>
#include <click/element.hh>
#include <clicknet/ether.h>
#include <click/notifier.hh>
#include <click/etheraddress.hh>
#include <click/bighashmap.hh>
#include <click/hashmap.hh>
#include <click/hashtable.hh>
#include <click/straccum.hh>
#include <clicknet/wifi.h>
#include <clicknet/llc.h>
#include <click/args.hh>
#include <click/error.hh>
#include <elements/standard/simplequeue.hh>
CLICK_DECLS

/*
=c

EmpowerQOSManager(EL, DEBUG)

=s EmPOWER

Converts Ethernet packets to 802.11 packets with a LLC header. Setting
the appropriate BSSID given the destination address. An EmPOWER Access
Point generates one virtual BSSID called LVAP for each active station.
Also maintains a dedicated queue for each pair tenant/dscp.

=d

Strips the Ethernet header off the front of the packet and pushes
an 802.11 frame header and LLC header onto the packet.

Arguments are:

=item EL
An EmpowerLVAPManager element

=item DEBUG
Turn debug on/off

=back 8

=a EmpowerWifiDecap
*/

class EtherPair {
  public:

    EtherAddress _ra;
    EtherAddress _ta;

    EtherPair() {
    }

    EtherPair(EtherAddress ra, EtherAddress ta) : _ra(ra), _ta(ta) {
    }

    EtherPair(const EtherPair &pair) : _ra(pair._ra), _ta(pair._ta) {
    }

    inline hashcode_t hashcode() const {
    		return CLICK_NAME(hashcode)(_ra) + CLICK_NAME(hashcode)(_ta);
    }

    inline bool operator==(EtherPair other) const {
    		return (other._ra == _ra && other._ta == _ta);
    }

    inline bool operator!=(EtherPair other) const {
    		return (other._ra != _ra || other._ta != _ta);
    }

	String unparse() {
		StringAccum result;
		result << "(" << _ra.unparse() << ", " << _ta.unparse() << ")";
		return result.take_string();
	}

};

class AggregationQueue {

public:
	uint32_t _quantum;
	WritablePacket * _amsdu;
	uint32_t _current_amsdu_frames;

	AggregationQueue(uint32_t capacity, EtherPair pair) {
		_q = new Packet*[capacity];
		_deficit = 0;
		_quantum = 0;
		_capacity = capacity;
		_pair = pair;
		_nb_pkts = 0;
		_drops = 0;
		_head = 0;
		_tail = 0;
		_amsdu = 0;
		_current_amsdu_frames = 0;
		for (unsigned i = 0; i < _capacity; i++) {
			_q[i] = 0;
		}
	}

	String unparse() {
		StringAccum result;
		_queue_lock.acquire_read();
		result << _pair.unparse() << " -> status: " << _nb_pkts << "/" << _capacity << "\n";
		_queue_lock.release_read();
		return result.take_string();
	}

	~AggregationQueue() {
		_queue_lock.acquire_write();
		for (uint32_t i = 0; i < _capacity; i++) {
			if (_q[i]) {
				_q[i]->kill();
			}
		}
		delete[] _q;

		if (_amsdu) {
		    _amsdu->kill();
		}

		_queue_lock.release_write();
	}

	Packet* pull() {
		Packet* p = 0;
		_queue_lock.acquire_write();
		if (_nb_pkts > 0) {
			p = _q[_head];
			_q[_head] = 0;
			_head++;
			_head %= _capacity;
			_nb_pkts--;
		}
		_queue_lock.release_write();
		return p;
	}

	bool push(Packet* p) {
		bool result = false;
		_queue_lock.acquire_write();
		if (_nb_pkts == _capacity) {
			_drops++;
			result = false;
		} else {
			_q[_tail] = p;
			_tail++;
			_tail %= _capacity;
			_nb_pkts++;
			result = true;
		}
		_queue_lock.release_write();
		return result;
	}

    const Packet* top() {
      Packet* p = 0;
      _queue_lock.acquire_write();
      if(_head != _tail) {
        p = _q[(_head+1) % _capacity];
      }
      _queue_lock.release_write();
      return p;
    }

	uint32_t top_length() {
	    const Packet* p = top();

	    if (p) {
	        return top()->length();
	    }

	    return 0;
	}

    uint32_t nb_pkts() { return _nb_pkts; }
    EtherPair pair() { return _pair; }

private:

	ReadWriteLock _queue_lock;
	Packet** _q;

	uint32_t _capacity;
	uint32_t _deficit;
	EtherPair _pair;
	uint32_t _nb_pkts;
	uint32_t _drops;
	uint32_t _head;
	uint32_t _tail;
};

typedef HashTable<EtherPair, AggregationQueue*> AggregationQueues;
typedef AggregationQueues::iterator AQIter;

class Slice {
  public:

    String _ssid;
    int _dscp;

    Slice() : _ssid(""), _dscp(0) {
    }

    Slice(String ssid, int dscp) : _ssid(ssid), _dscp(dscp) {
    }

    inline hashcode_t hashcode() const {
    		return CLICK_NAME(hashcode)(_ssid) + CLICK_NAME(hashcode)(_dscp);
    }

    inline bool operator==(Slice other) const {
    		return (other._ssid == _ssid && other._dscp == _dscp);
    }

    inline bool operator!=(Slice other) const {
    		return (other._ssid != _ssid || other._dscp != _dscp);
    }

	String unparse() {
		StringAccum result;
		result << _ssid << ":" << _dscp;
		return result.take_string();
	}

};

class SliceQueue {

public:

    AggregationQueues _queues;
	Vector<EtherPair> _active_list;

	Slice _slice;
    uint32_t _capacity;
    uint32_t _size;
    uint32_t _drops;
    uint32_t _deficit;
    uint32_t _quantum;
    bool _amsdu_aggregation;
    uint32_t _max_aggr_length;
    uint32_t _deficit_used;
    uint32_t _max_queue_length;
    uint32_t _tx_packets;
    uint32_t _tx_bytes;
    uint32_t _scheduler;

    SliceQueue(Slice slice, uint32_t capacity, uint32_t quantum, bool amsdu_aggregation, uint32_t scheduler) :
                _slice(slice), _capacity(capacity), _size(0), _drops(0), _deficit(0),
                _quantum(quantum), _amsdu_aggregation(amsdu_aggregation), _max_aggr_length(2304),
                _deficit_used(0), _max_queue_length(0), _tx_packets(0), _tx_bytes(0), _scheduler(scheduler) {
	}

	~SliceQueue() {
		AQIter itr = _queues.begin();
		while (itr != _queues.end()) {
			AggregationQueue *aq = itr.value();
			delete aq;
			itr++;
		}
		_queues.clear();
	}

	uint32_t size() { return _size; }

    Packet * wifi_encap(Packet *p, EtherAddress ra, EtherAddress sa, EtherAddress ta) {

        WritablePacket *q = p->uniqueify();

        if (!q) {
            return 0;
        }

        uint8_t mode = WIFI_FC1_DIR_FROMDS;
        uint16_t ethtype;

        memcpy(&ethtype, q->data() + 12, 2);

        q->pull(sizeof(struct click_ether));
        q = q->push(sizeof(struct click_llc));

        if (!q) {
            q->kill();
            return 0;
        }

        memcpy(q->data(), WIFI_LLC_HEADER, WIFI_LLC_HEADER_LEN);
        memcpy(q->data() + 6, &ethtype, 2);

        q = q->push(sizeof(struct click_wifi));

        if (!q) {
            q->kill();
            return 0;
        }

        struct click_wifi *w = (struct click_wifi *) q->data();

        memset(q->data(), 0, sizeof(click_wifi));

        w->i_fc[0] = (uint8_t) (WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_DATA | WIFI_FC0_SUBTYPE_DATA);
        w->i_fc[1] = 0;
        w->i_fc[1] |= (uint8_t) (WIFI_FC1_DIR_MASK & mode);

        memcpy(w->i_addr1, ra.data(), 6);
        memcpy(w->i_addr2, ta.data(), 6);
        memcpy(w->i_addr3, sa.data(), 6);

        return q;
    }

    WritablePacket * msdu_encap(WritablePacket *amsdu, uint32_t &current_amsdu_frames, Packet *p, EtherAddress ra, EtherAddress sa, EtherAddress ta) {

        // The A-MSDU did not exist so far
        if (current_amsdu_frames == 0) {

            amsdu = p->uniqueify();

            if (!amsdu) {
                return 0;
            }

            uint8_t mode = WIFI_FC1_DIR_FROMDS;
            uint16_t ethtype;

            memcpy(&ethtype, amsdu->data() + 12, 2);

            amsdu->pull(sizeof(struct click_ether));
            amsdu = amsdu->push(sizeof(struct click_llc));

            if (!amsdu) {
                return 0;
            }

            memcpy(amsdu->data(), WIFI_LLC_HEADER, WIFI_LLC_HEADER_LEN);
            memcpy(amsdu->data() + 6, &ethtype, 2);

            // First A-MSDU subframe
            amsdu = amsdu->push(sizeof(struct click_wifi_amsdu_subframe_header));

            if (!amsdu) {
                return 0;
            }

            struct click_wifi_amsdu_subframe_header *wa = (struct click_wifi_amsdu_subframe_header *) (amsdu->data());
            memset(amsdu->data(), 0, sizeof(click_wifi_amsdu_subframe_header));

            memcpy(wa->da, ra.data(), 6);
            memcpy(wa->sa, sa.data(), 6);

            uint16_t len = (uint16_t) (amsdu->length() - sizeof(click_wifi_amsdu_subframe_header));
            wa->len = htons(len);

            // QoS Control field for enabling A-MSDU aggregation
            amsdu = amsdu->push((sizeof(struct click_wifi) + sizeof(struct click_qos_control)));

            if (!amsdu) {
                return 0;
            }

            struct click_wifi *w = (struct click_wifi *) amsdu->data();
            memset(amsdu->data(), 0, sizeof(click_wifi));

            w->i_fc[0] = (uint8_t) (WIFI_FC0_VERSION_0 | (WIFI_FC0_TYPE_DATA | WIFI_FC0_SUBTYPE_QOS));
            w->i_fc[1] = 0;
            w->i_fc[1] |= (uint8_t) (WIFI_FC1_DIR_MASK & mode);

            memcpy(w->i_addr1, ra.data(), 6);
            memcpy(w->i_addr2, ta.data(), 6);
            memcpy(w->i_addr3, sa.data(), 6);

            struct click_qos_control *z = (struct click_qos_control *) (amsdu->data() + sizeof(click_wifi));
            memset(amsdu->data()  + sizeof(click_wifi), 0, sizeof(click_qos_control));

            z->qos_control = (uint16_t) WIFI_QOS_CONTROL_QOS_AMSDU_PRESENT_MASK;

            current_amsdu_frames++;

            return amsdu;
        }

        uint16_t ethtype;
        WritablePacket *q = p->uniqueify();
        WritablePacket *aggr_amsdu = amsdu->uniqueify();

        memcpy(&ethtype, q->data() + 12, 2);
        q->pull(sizeof(struct click_ether));
        q = q->push(sizeof(struct click_llc));

        if (!q) {
            return 0;
        }

        memcpy(q->data(), WIFI_LLC_HEADER, WIFI_LLC_HEADER_LEN);
        memcpy(q->data() + 6, &ethtype, 2);

        // A-MSDU substructure creation
        q = q->push(sizeof(struct click_wifi_amsdu_subframe_header));
        if (!q) {
            return 0;
        }

        struct click_wifi_amsdu_subframe_header *w = (struct click_wifi_amsdu_subframe_header *) (q->data());
        memset(q->data(), 0, sizeof(click_wifi_amsdu_subframe_header));

        uint16_t len = (uint16_t) (q->length() - sizeof(click_wifi_amsdu_subframe_header));

        memcpy(w->da, ra.data(), 6);
        memcpy(w->sa, sa.data(), 6);
        w->len = htons(len);

        uint32_t current_length = amsdu->length();
        aggr_amsdu = aggr_amsdu->put(q->length());
        if (!aggr_amsdu) {
            return 0;
        }

        memcpy((aggr_amsdu->data() + current_length), q->data(), q->length());

        current_amsdu_frames++;
        q->kill();

        return aggr_amsdu;
    }

    bool enqueue(Packet *p, EtherAddress ra, EtherAddress ta) {

    	EtherPair pair = EtherPair(ra, ta);

		if (_queues.find(pair) == _queues.end()) {
			AggregationQueue *queue = new AggregationQueue(_capacity, pair);
			_queues.set(pair, queue);
			_active_list.push_back(pair);
		}

		AggregationQueue *queue = _queues.get(pair);

		if (queue->push(p)) {
			// check if ra is in active list
			if (find(_active_list.begin(), _active_list.end(), pair) == _active_list.end()) {
				_active_list.push_back(pair);
			}
			if (queue->nb_pkts() > _max_queue_length) {
				_max_queue_length = queue->nb_pkts();
			}
			 _size++;
			return true;
		}

		_drops++;
		return false;

    }

    Packet *dequeue() {

            if (_active_list.empty()) {
                return 0;
            }

            EtherPair pair = _active_list[0];
            _active_list.pop_front();

            AQIter active = _queues.find(pair);
            AggregationQueue* queue = active.value();

            Packet *p = queue->pull();

            if (!p) {
                return dequeue();
            }

            _size--;
            click_ether *eh = (click_ether *) p->data();
            EtherAddress src = EtherAddress(eh->ether_shost);

            if (_amsdu_aggregation) {
                // Allowing a single A-MSDU
                uint32_t p_length = (p->length() - sizeof(click_ether) + sizeof(click_wifi_amsdu_subframe_header));
                queue->_amsdu = msdu_encap(queue->_amsdu, queue->_current_amsdu_frames, p, queue->pair()._ra, src, queue->pair()._ta);

                if (queue->top() && !max_aggr_exceeded(queue->_amsdu, queue->top_length(), 3)) {

                    _active_list.push_front(pair);

                    // Add padding if more frames are needed
                    uint16_t padding = calculate_padding(p_length);
                    queue->_amsdu = queue->_amsdu->put(padding);
                    if (!queue->_amsdu) {
                        queue->_amsdu->kill();
                        return 0;
                    }
                    return dequeue();
                } else {
                    _active_list.push_back(pair);

                   if (queue->_amsdu) {
                       Packet *aggr = queue->_amsdu;
                       queue->_current_amsdu_frames = 0;
                       queue->_amsdu = 0;
                       return aggr;
                   }
                   return 0;
                }
            }
            p = wifi_encap(p, queue->pair()._ra, src, queue->pair()._ta);
            _active_list.push_back(pair);

            return p;
        }

    uint16_t calculate_padding (uint32_t amsdu_size) {
        uint16_t padding = (4 - (amsdu_size % 4 )) % 4;
        return padding;
    }

    bool max_aggr_exceeded (Packet * p, uint32_t next_length, uint32_t padding) {
        if ((p->length() + next_length + padding) > _max_aggr_length) {
            return true;
        }
        return false;
    }

	String unparse() {
		StringAccum result;
		result << _slice.unparse();
		result << " -> capacity: " << _capacity << ", ";
		result << "quantum: " << _quantum << "\n";
		AQIter itr = _queues.begin();
		while (itr != _queues.end()) {
			AggregationQueue *aq = itr.value();
			result << "  " << aq->unparse();
			itr++;
		}
		return result.take_string();
	}

};

typedef HashTable<Slice, SliceQueue*> Slices;
typedef Slices::iterator SIter;

typedef HashTable<Slice, Packet*> HeadTable;
typedef HeadTable::iterator HItr;

class EmpowerQOSManager: public Element {

public:

	EmpowerQOSManager();
	~EmpowerQOSManager();

	const char *class_name() const { return "EmpowerQOSManager"; }
	const char *port_count() const { return PORTS_1_1; }
	const char *processing() const { return PUSH_TO_PULL; }
    void *cast(const char *);

	int configure(Vector<String> &, ErrorHandler *);

	void push(int, Packet *);
	Packet *pull(int);

	void add_handlers();
	void set_default_slice(String);
	void set_slice(String, int, uint32_t, bool, uint32_t);
	void del_slice(String, int);

	Slices * slices() { return &_slices; }

private:

	ReadWriteLock _lock;

    enum { SLEEPINESS_TRIGGER = 9 };

    ActiveNotifier _empty_note;
	class EmpowerLVAPManager *_el;
	class Minstrel * _rc;

	Slices _slices;
    HeadTable _head_table;
	Vector<Slice> _active_list;

    int _sleepiness;
    uint32_t _capacity;
    uint32_t _quantum;

    int _iface_id;

    bool _debug;

	void store(String, int, Packet *, EtherAddress, EtherAddress);
	String list_slices();

	static int write_handler(const String &, Element *, void *, ErrorHandler *);
	static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif
