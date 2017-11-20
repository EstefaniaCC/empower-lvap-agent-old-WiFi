/*
 * EmpowerQoSManager.hh
 *
 *  Created on: Oct 30, 2017
 *      Author: Estefania Coronado
 */

#ifndef CLICK_EMPOWER_EMPOWERQOSMANAGER_HH_
#define CLICK_EMPOWER_EMPOWERQOSMANAGER_HH_
#include <click/config.h>
#include <click/element.hh>
#include <click/timer.hh>
#include <click/etheraddress.hh>
#include <click/ipaddress.hh>
#include <click/hashtable.hh>
#include <click/timestamp.hh>
#include <click/confparse.hh>
#include <clicknet/wifi.h>
#include <click/sync.hh>
#include <click/notifier.hh>
#include <click/string.hh>
#include <elements/standard/simplequeue.hh>
#include "empowerpacket.hh"
#include "empowerlvapmanager.hh"
CLICK_DECLS

class FrameInfo {
public:
	uint64_t _arrival_time;
	uint64_t _average_time_diff;
	uint64_t _last_frame_time;
	bool _complete;
	WritablePacket * _frame; // It can be a simple or an aggregated frame
	int _frame_length; // In case of aggregation this length and the one of the frame may not be the same
	int _msdus;
	EtherAddress _dst;
	EtherAddress _bssid;
	int _iface;
	FrameInfo() {
		_arrival_time = Timestamp::now().usecval();
		_last_frame_time = Timestamp::now().usecval();
		_complete = false;
		_average_time_diff = 0; // It should be the time needed to transmit this frame
		_frame_length = 0;
		_msdus = 0;
		_frame = 0;
		_dst = EtherAddress();
		_bssid = EtherAddress();
		_iface = -1;
	}

	~FrameInfo() {
	}

	void list_frame_info() {
//		StringAccum sa;
//		sa << "Client ";
//		sa << _dst.unparse();
//		sa << " arrival time ";
//		sa << _arrival_time;
//		sa << " average time diff ";
//		sa << _average_time_diff;
//		sa << " _last frame time ";
//		sa << _last_frame_time;
//		if (_complete) {
//			sa << " complete";
//		} else {
//			sa << " not complete";
//		}
//		sa << " frame length ";
//		sa << _frame_length;
//		sa << " msdus ";
//		sa << _msdus;
//		sa << " bssid ";
//		sa << _bssid.unparse();
//		sa << " iface ";
//		sa << _iface;
//		sa << "\n";

		click_chatter("%{element} :: %s :: ----- %s ---- ",
										 this,
										 __func__,
										 _dst.unparse().c_str());
//		return sa.take_string();
	}

	inline bool operator==(const FrameInfo &a) {
		return (a._arrival_time == _arrival_time && a._average_time_diff == _average_time_diff
				&& a._bssid == _bssid && a._complete == _complete && a._dst == _dst
				&& a._frame == _frame && a._frame_length && _frame_length
				&& a._last_frame_time && _last_frame_time && a._msdus == _msdus);
	}
};


class BufferQueueInfo {
public:
	int _dscp;
	String _tenant;

	BufferQueueInfo(uint16_t dscp, String tenant):
			_dscp(dscp), _tenant(tenant){
		}

	BufferQueueInfo(){
		_dscp = -1;
		_tenant = "";
	}

	~BufferQueueInfo() {
	}

//	inline bool
//	operator==(const BufferQueueInfo &a, const BufferQueueInfo &b)
//	{
//	    return (a._dscp == b._dscp && !(a._tenant.compare(b._tenant)));
//	}

	inline size_t hashcode() const {
		return (_tenant.hashcode());
	}

	inline bool
	operator==(const BufferQueueInfo &b)
	{
	    return (_dscp == b._dscp && _tenant == b._tenant);
	}
};

class BufferQueue {
public:
	empower_tenant_types _tenant_type;
	int _priority;
	int _parent_priority;
	bool _amsdu_aggregation;
	bool _ampdu_aggregation;
	bool _deadline_discard;
	int _max_delay;
	int _max_length;
	int _deficit;
	int _quantum;
	bool _first_pkt;
	int _total_consumed_time;
	int _dropped_packets;
	int _dropped_msdus;
	int _dropped_bytes;
	int _transmitted_packets;
	int _transmitted_msdus;
	int _transmitted_bytes;

	FrameInfo** _frames;
	int _capacity;
	int _size;
	int _head;
	int _tail;
	ReadWriteLock _buffer_queue_lock;

	BufferQueue(empower_tenant_types tenant_type, uint8_t priority, uint8_t parent_priority, uint8_t max_delay,
			bool amsdu_aggregation, bool ampdu_aggregation, bool deadline_discard):
		_tenant_type(tenant_type), _priority(priority), _parent_priority(parent_priority), _max_delay(max_delay),
		_amsdu_aggregation(amsdu_aggregation), _ampdu_aggregation(ampdu_aggregation), _deadline_discard(deadline_discard){
		_max_length = 7935;
		_deficit = 0;
		_quantum = 1000;
		_first_pkt = true;
		_total_consumed_time = 0;
		_dropped_packets = 0;
		_dropped_msdus = 0;
		_dropped_bytes = 0;
		_transmitted_packets = 0;
		_transmitted_msdus = 0;
		_transmitted_bytes = 0;
		_head = 0;
		_tail = 0;
		_size = 0;
		_capacity = 16384;
		_frames = new FrameInfo*[_capacity];
	}

	~BufferQueue() {
		if (_head < _tail) {
			for(int i = _head; i < _tail; i++) {
				if(_frames[i]) {
					_frames[i]->_frame->kill();
				}
			}
		} else {
			for (int i = _head; i < _capacity; i++) {
				if(_frames[i]) {
					_frames[i]->_frame->kill();
				}
			}
			for (int i = 0; i < _tail; i++) {
				if(_frames[i]) {
					_frames[i]->_frame->kill();
				}
			}
		}
		delete[] _frames;
	}

	FrameInfo* pull() {
//		_buffer_queue_lock.acquire_write();
		FrameInfo * next_frame = _frames[_head];
//		_head = (_head + 1) % _capacity;
//		_buffer_queue_lock.release_write();
		return next_frame;
	}

	bool push(FrameInfo *new_frame) {
//		_buffer_queue_lock.acquire_write();
		if (_size >= _capacity) {
			return false;
		}
		_frames[_tail] = new_frame;
		_tail = (_tail + 1) % _capacity;
		_size++;
//		_buffer_queue_lock.release_write();
		return true;
	}

//	Packet* get_next_packet() {
//		Packet* p = 0;
//		_buffer_queue_lock.acquire_write();
//
//		// If the queue is deleted, I should also delete all the frames in the aggregated frame if the aggregated
//		// property is set to true
//		FrameInfo * next_frame = _frames.front();
//		p = next_frame->_frame;
//		_buffer_queue_lock.release_write();
//		return p;
//	}

	void discard_frame(FrameInfo * current_frame) {
//		_buffer_queue_lock.acquire_write();
		bool remove = remove_frame_from_queue(current_frame);
		if (remove) {
			delete current_frame;
		}
//		_buffer_queue_lock.release_write();
	}

	bool remove_frame_from_queue(FrameInfo * current_frame) {
//		click_chatter("%{element} :: %s :: is valid 2",
//																		  this,
//																		  __func__);

//		click_chatter("%{element} :: %s :: beginning. head %d",
//															  this,
//															  __func__,
//															  _head);
//		click_chatter("%{element} :: %s :: beginning. tail %d",
//																	  this,
//																	  __func__,
//																	  _tail);
//		click_chatter("%{element} :: %s :: beginning. size %d",
//																	  this,
//																	  __func__,
//																	  _size);

//		_buffer_queue_lock.acquire_write();

		if (_head <= _tail) {
			for (int i = _head; i < _tail; i++) {
				if (_frames[i] == current_frame) {
					for (int j = i; j > _head; j--) {
						_frames[j] = _frames[j - 1];
					}
					_head++;
					_size--;
					return true;
				}
			}
		}
		else {
			for (int i = _head; i < _capacity; i++) {
				if (_frames[i] == current_frame) {
					for (int j = i; j > _head; j--) {
						_frames[j] = _frames[j - 1];
					}
					_head = (_head + 1) % _capacity;
					_size--;
					return true;
				}
			}
			for (int i = 0; i < _tail; i++) {
				if (_frames[i] == current_frame) {
					for (int j = i; j < _tail - 1; j++) {
						_frames[j] = _frames[j + 1];
					}
					_tail = (_tail == 0) ? _capacity - 1 : _tail - 1;
					_size--;
					return true;
				}
			}
		}

		return false;

//		_buffer_queue_lock.release_write();
	}

	bool check_delay_deadline(FrameInfo *frame, int transmission_time) {
		uint64_t time_now = Timestamp::now().usecval();
		uint64_t elapsed_time = (time_now - frame->_arrival_time);
		if ((elapsed_time + transmission_time) > _max_delay)
			return true;
		return false;
	}

};

typedef HashTable<EtherAddress, FrameInfo *> UserFrames;
typedef UserFrames::iterator UserFramesIter;

inline bool operator==(const BufferQueueInfo &a, const BufferQueueInfo &b) {
	return (a._dscp == b._dscp && !(a._tenant.compare(b._tenant)));
}

typedef HashTable <BufferQueueInfo, BufferQueue *> TrafficRulesQueues;
typedef TrafficRulesQueues::iterator TrafficRulesQueuesIter;

class EmpowerQoSManager : public SimpleQueue { public:

	EmpowerQoSManager();
    ~EmpowerQoSManager();

    const char* class_name() const		{ return "EmpowerQoSManager"; }
    const char *port_count() const		{ return PORTS_1_1; }
    const char* processing() const		{ return PUSH_TO_PULL; }
    void *cast(const char *);

    int configure(Vector<String> &conf, ErrorHandler *);
    int initialize(ErrorHandler *);

    void push(int port, Packet *);
    Packet *pull(int port);

    void add_handlers();

    int drops() { return(_drops); }
    int bdrops() { return(_bdrops); }
    int incorrect_lvap_drops() { return(_incorrect_lvap_drops); }
    int clone_malformed_drops() { return(_clone_malformed_drops); }
    int bad_queue_drops() { return(_bad_queue_drops); }
    int enqueued_unicast_frames() { return(_enqueued_unicast_frames); }
    int pulled_frames() { return(_pulled_frames); }
    int pushed_unicast_frames() { return(_pushed_unicast_frames); }
    int sleeping_times() { return(_sleeping_times); }
    int system_quantum() { return(_system_quantum); }
    TrafficRulesQueues* get_traffic_rules() { return &_traffic_rules; }

    String list_traffic_rules();
    String list_traffic_rule(BufferQueue *);
    String list_user_frames();
    void request_traffic_rule(int, String, empower_tenant_types, int, int, bool, bool, bool);
    void release_traffic_rule(int, String);
    void remove_traffic_rule_resources(int, String);
    int frame_transmission_time(EtherAddress, int, int);
    int map_dscp_to_delay(int);
    void enqueue_unicast_frame(EtherAddress, BufferQueue *, Packet *, EtherAddress, int);
    Packet * empower_wifi_encap(FrameInfo *);
    Packet *wifi_encap(Packet *, EtherAddress, EtherAddress, EtherAddress);

    ReadWriteLock get_traffic_rules_lock() {
    	return _traffic_rules_lock;
    }

    int default_dscp() {
		return _default_dscp;
	}

    BufferQueue * get_traffic_rule(int dscp, String tenant) {
    	BufferQueueInfo tr_key (dscp, tenant);
    	BufferQueue *traffic_queue = _traffic_rules.get(tr_key);
		return traffic_queue;
	}

    BufferQueueInfo  get_traffic_rule_info(BufferQueue * traffic_rule) {
    	BufferQueueInfo buffer = BufferQueueInfo();
    	for (TrafficRulesQueuesIter it_tr_queues = _traffic_rules.begin(); it_tr_queues.live(); it_tr_queues++) {
    		if (it_tr_queues.value() == traffic_rule) {
    			buffer = it_tr_queues.key();
    		}
    	}
    	return buffer;
   }

  protected:

    enum { SLEEPINESS_TRIGGER = 9 };

    int _sleepiness;
    ActiveNotifier _notifier;
    class EmpowerLVAPManager *_el;

    TrafficRulesQueues _traffic_rules;
    UserFrames _clients_current_frame;
    ReadWriteLock _traffic_rules_lock;

    BufferQueueInfo *_rr_order;
    int _next;
    int _last;
    int _max_rules;

    int _default_dscp;
    int _system_quantum;
    int _drops;
    int _bdrops;
    unsigned int _empty_traffic_rules;
    bool _debug;

    int _incorrect_lvap_drops;
    int _clone_malformed_drops;
    int _bad_queue_drops;
    int _enqueued_unicast_frames;
    int _pulled_frames;
    int _pushed_unicast_frames;
    int _sleeping_times;

    uint64_t push_init_time, push_middle_time, push_end_time;
    uint64_t pull_init_time, pull_end_time;
    uint64_t enqueue_init_time, enqueue_middle_time, enqueue_end_time;

    int compute_deficit(Packet*);
    static int write_handler(const String &, Element *, void *, ErrorHandler *);
    static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif
