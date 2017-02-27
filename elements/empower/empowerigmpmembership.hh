// -*- mode: c++; c-basic-offset: 2 -*-
#ifndef CLICK_EMPOWERIGMPMEMBERSHIP_HH
#define CLICK_EMPOWERIGMPMEMBERSHIP_HH
#include <click/element.hh>
#include <click/config.h>
CLICK_DECLS

/*
=c

EmpowerIgmpMembership(RL, EL, [, I<KEYWORDS>])

=s EmPOWER

Handle IGMP packets

=d

Keyword arguments are:

=over 8

=item RT
An AvailableRates element

=item EL
An EmpowerLVAPManager element

=item DEBUG
Turn debug on/off

=back 8

=a EmpowerLVAPManager
*/


enum empower_igmp_record_type {
	V3_MODE_IS_INCLUDE = 0x0,
	V3_MODE_IS_EXCLUDE = 0x1,
	V3_CHANGE_TO_INCLUDE_MODE = 0x2,
	V3_CHANGE_TO_EXCLUDE_MODE = 0x3,
	V3_ALLOW_NEW_SOURCES = 0x4,
	V3_BLOCK_OLD_SOURCES = 0x5,
	V2_JOIN_GROUP = 0x6,
	V2_LEAVE_GROUP = 0x7,
	V1_MEMBERSHIP_REPORT = 0x8,
	V1_V2_MEMBERSHIP_QUERY=0x9

};

// IGMPv1 and IGMPv2 messages have to be supported by an IGMPv3 router
struct igmpv1andv2message {
  unsigned char type;
  unsigned char responsetime;
  unsigned short checksum;
  unsigned int group;
};

// the query is used to detect other routers and the state of connected hosts
struct igmpv3query {
  unsigned char type;
  unsigned char responsecode;
  unsigned short checksum;
  unsigned int group;
  unsigned char s_and_qrv;
  unsigned char qqic;
  unsigned short no_of_sources;
  unsigned int sources[1];
};

// see RFC 3376 for details
struct grouprecord {
  unsigned char type;
  unsigned char aux_data_len;
  unsigned short no_of_sources;
  unsigned int multicast_address;
  unsigned int sources[1];
};

struct igmpv3report {
  unsigned char type;
  unsigned char reserved;
  unsigned short checksum;
  unsigned short reserved_short;
  unsigned short no_of_grouprecords;
  struct grouprecord grouprecords[1];
};

class EmpowerIgmpMembership: public Element {
public:

	EmpowerIgmpMembership();
	~EmpowerIgmpMembership();

	const char *class_name() const { return "EmpowerIgmpMembership"; }
	const char *port_count() const { return "1/1"; }
	const char *processing() const { return PUSH; }

	int configure(Vector<String> &, ErrorHandler *);
	void add_handlers();
	void push(int, Packet *);

private:

	class EmpowerLVAPManager *_el;

	bool _debug;

	// Read/Write handlers
	static String read_handler(Element *e, void *user_data);
	static int write_handler(const String &, Element *, void *, ErrorHandler *);

};

CLICK_ENDDECLS
#endif
