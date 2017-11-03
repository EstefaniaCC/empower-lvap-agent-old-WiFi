/*
 * empowerqosscheduler.hh
 *
 *  Created on: Oct 30, 2017
 *      Author: Estefania Coronado
 */

#ifndef ELEMENTS_EMPOWER_EMPOWERQOSSCHEDULER_HH_
#define ELEMENTS_EMPOWER_EMPOWERQOSSCHEDULER_HH_
#include <click/config.h>
#include <click/element.hh>
#include <click/timer.hh>
#include <click/etheraddress.hh>
#include <click/ipaddress.hh>
#include <click/hashtable.hh>
#include <click/timestamp.hh>
#include <clicknet/wifi.h>
#include <click/sync.hh>
#include <click/notifier.hh>
#include <elements/standard/simplequeue.hh>
#include "empowerpacket.hh"

class FrameInfo {
public:
	Timestamp _arrival_time;
	Timestamp _average_time_diff;
	Timestamp _last_frame_time;
	bool _complete;
	WritablePacket * _frame; // It can be a simple or an aggregated frame
	int _frame_length; // In case of aggregation this length and the one of the frame may not be the same
	int _msdus;
	EtherAddress _dst;
	EtherAddress _bssid;
	FrameInfo() {
		_arrival_time = Timestamp::now();
		_last_frame_time = Timestamp::now();
		_complete = false;
		_average_time_diff = 0; // It should be the time needed to transmit this frame
		_frame_length = 0;
		_msdus = 1;
		_frame = 0;
		_dst = 0; // TODO. Can this be done?
		_bssid = 0; // TODO. Can this be done?
	}

	~FrameInfo() {
	}
};


class BufferQueueInfo {
public:
	int _dscp;
	String _tenant;

	BufferQueueInfo(uint16_t dscp, String tenant):
			_dscp(dscp), _tenant(tenant){
		}

	~BufferQueueInfo() {
	}

//	inline bool
//	operator==(const BufferQueueInfo &a, const BufferQueueInfo &b)
//	{
//	    return (a._dscp == b._dscp && a._tenant == b._tenant);
//	}

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
	bool _aggregate;
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
	Vector<FrameInfo*> _frames;

	ReadWriteLock _buffer_queue_lock;

	BufferQueue(empower_tenant_types tenant_type, uint8_t priority, uint8_t parent_priority, bool aggregate):
		_tenant_type(tenant_type), _priority(priority), _parent_priority(parent_priority), _aggregate(aggregate){
		_max_delay = 100;
		_max_length = 7935;
		_deficit = 0;
		_quantum = 0;
		_first_pkt = true;
		_total_consumed_time = 0;
		_dropped_packets = 0;
		_dropped_msdus = 0;
		_dropped_bytes = 0;
		_transmitted_packets = 0;
		_transmitted_msdus = 0;
		_transmitted_bytes = 0;
	}

	~BufferQueue() {
		for (Vector<FrameInfo*>::iterator it = _frames.begin(); it != _frames.end(); it++) {
			(*it)->_frame->kill();
			delete (*it);
		}
	}

	FrameInfo* pull() {
		_buffer_queue_lock.acquire_write();
		FrameInfo * next_frame = _frames.front();
		_buffer_queue_lock.release_write();
	}

	Packet* get_next_packet() {
		Packet* p = 0;
		_buffer_queue_lock.acquire_write();

		// If the queue is deleted, I should also delete all the frames in the aggregated frame if the aggregated
		// property is set to true
		FrameInfo * next_frame = _frames.front();
		p = next_frame->_frame;
		_buffer_queue_lock.release_write();
		return p;
	}

	void discard_frame(FrameInfo * current_frame) {
		_buffer_queue_lock.acquire_write();
		for (Vector<FrameInfo*>::iterator it = _frames.begin(); it != _frames.end(); it++) {
			if (*it == current_frame) {
				current_frame->_frame->kill();
				delete current_frame;
				break;
			}
		}
		_buffer_queue_lock.release_write();
	}

	void remove_frame_from_queue(FrameInfo * current_frame) {
		_buffer_queue_lock.acquire_write();
		for (Vector<FrameInfo*>::iterator it = _frames.begin(); it != _frames.end(); it++) {
			if (*it == current_frame) {
				delete it;
				break;
			}
		}
		_buffer_queue_lock.release_write();
	}

	bool check_delay_deadline(FrameInfo *frame, int transm_time) {
		if (((Timestamp::now() - frame->_arrival_time) + transm_time) > _max_delay)
			return true;
		return false;
	}

};

typedef HashTable<EtherAddress, FrameInfo *> UserFrames;
typedef UserFrames::iterator UserFramesIter;

typedef HashTable <BufferQueueInfo, BufferQueue *> TrafficRulesQueues;
typedef TrafficRulesQueues::iterator TrafficRulesQueuesIter;


class EmpowerQoSScheduler : public SimpleQueue { public:

	EmpowerQoSScheduler();
    ~EmpowerQoSScheduler();

    const char* class_name() const		{ return "EmpowerQoSScheduler"; }
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
    int system_quantum() { return(_system_quantum); }

    TrafficRulesQueues* get_slices() { return &_slices; }
    String list_slices();
    void request_slice(int, String, empower_tenant_types, int, int, bool);
    void release_slice(int, String);
    void remove_slice_resources(int, String);
    int frame_transmission_time(EtherAddress, int);
    int map_dscp_to_delay(int);
    void enqueue_unicast_frame(EtherAddress, BufferQueue *, Packet *);
    Packet * empower_wifi_encap(Packet *);
    Packet *wifi_encap(Packet *, EtherAddress, EtherAddress, EtherAddress);

    ReadWriteLock * get_slices_lock() {
    	return _slices_lock;
    }

    int default_dscp() {
		return _default_dscp;
	}

  protected:

    enum { SLEEPINESS_TRIGGER = 9 };

    int _sleepiness;
    ActiveNotifier _notifier;
    class EmpowerLVAPManager *_el;

    TrafficRulesQueues _slices;
    UserFrames _current_frame_clients;
    Vector <BufferQueueInfo> _rr_order;
    EtherAddress _next;
    HashTable<int, int> dscp_delay_relationship;
    ReadWriteLock _slices_lock;

    int _default_dscp;

    int _system_quantum;
    int _drops;
    int _bdrops;

    int _empty_slices;

    int compute_deficit(Packet*);
    static int write_handler(const String &, Element *, void *, ErrorHandler *);
    static String read_handler(Element *, void *);

};

#endif /* ELEMENTS_EMPOWER_EMPOWERQOSSCHEDULER_HH_ */
