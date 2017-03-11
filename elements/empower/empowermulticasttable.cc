/*
 * empowermulticasttable.{cc,hh} -- handle IGMP groups (EmPOWER Access Point)
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
#include <click/args.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <click/error.hh>
#include <click/ipaddress.hh>
#include <clicknet/wifi.h>
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include "empowerpacket.hh"
#include "empowerlvapmanager.hh"
#include "igmppacket.hh"
#include "empowerigmpmembership.hh"
#include "empowermulticasttable.hh"
CLICK_DECLS

EmpowerMulticastTable::EmpowerMulticastTable() :
	_el(0), _debug(false) {
}

EmpowerMulticastTable::~EmpowerMulticastTable() {
}

int EmpowerMulticastTable::configure(Vector<String> &conf,
		ErrorHandler *errh) {

	int ret = Args(conf, this, errh)
              .read_m("EL", ElementCastArg("EmpowerLVAPManager"), _el)
			  .read("DEBUG", _debug).complete();

	return ret;

}

void EmpowerMulticastTable::push(int, Packet *p)
{

}

bool EmpowerMulticastTable::addgroup(IPAddress group)
{
	EmpowerMulticastGroup newgroup;
	newgroup.group = group;

	Vector<EmpowerMulticastGroup>::iterator i;
	for (i = multicastgroups.begin(); i != multicastgroups.end(); i++) {
		if (IPAddress((*i).group) == IPAddress(group))
			return false;
	}

	newgroup.mac_group = ip_mcast_addr_to_mac(group);
	multicastgroups.push_back(newgroup);
	const unsigned char *p = group.data();
	return true;

}

bool EmpowerMulticastTable::joingroup(EtherAddress sta, IPAddress group)
{
	EmpowerMulticastReceiver new_receiver;
	new_receiver.ess = _el->lvaps()->get_pointer(sta);

	Vector<EmpowerMulticastGroup>::iterator i;

	for (i = multicastgroups.begin(); i != multicastgroups.end(); i++)
	{
		if ((*i).group.addr() == group.addr())
		{
			Vector<EmpowerMulticastReceiver>::iterator a;
			for (a = (*i).receivers.begin(); a != (*i).receivers.end(); a++)
			{
				if ((*a).ess->_sta == sta)
				{
					click_chatter("%{element} :: %s :: Station %s already in group %x!",
							this, __func__, sta.unparse().c_str(), group._addr);
					return false;
				}
			}
			(*i).receivers.push_back(new_receiver);
			click_chatter("%{element} :: %s :: Station %s added to group %x!",
					this, __func__, sta.unparse().c_str(), group._addr);
		}
	}

	return true;
}


bool EmpowerMulticastTable::leavegroup(EtherAddress sta, IPAddress group)
{
	Vector<EmpowerMulticastGroup>::iterator i;

	for (i = multicastgroups.begin(); i != multicastgroups.end(); i++)
	{
		if ((*i).group.addr() == group.addr())
		{
			Vector<EmpowerMulticastReceiver>::iterator a;
			for (a = (*i).receivers.begin(); a != (*i).receivers.end(); a++)
			{
				if ((*a).ess->_sta == sta)
				{
					(*i).receivers.erase(a);
					click_chatter("%{element} :: %s :: Station %s added removed from group %x",
										this, __func__, sta.unparse().c_str(), group._addr);
					// The group is deleted if no more receivers belong to it
					if ((*i).receivers.begin() == (*i).receivers.end())
					{
						multicastgroups.erase(i);
						click_chatter("%{element} :: %s :: Group %s is empty. It is about to be deleted",
																this, __func__, group._addr);
						return true;
					}
					return true;
				}
			}

		}
		click_chatter("%{element} :: %s :: IGMP leave group request received from station %s not found in group %x",
													this, __func__, sta.unparse().c_str(), group._addr);
	}
	return false;
}

Vector<struct EmpowerMulticastReceiver> * EmpowerMulticastTable::getIGMPreceivers(EtherAddress group)
{
	Vector<struct EmpowerMulticastGroup>::iterator i;

	for (i = multicastgroups.begin(); i != multicastgroups.end(); i++)
	{
		if (i->mac_group == group)
		{
			return &(i->receivers);
			break;
		}
	}

	return NULL;
}



enum {
	H_DEBUG
};

String EmpowerMulticastTable::read_handler(Element *e, void *thunk) {
	EmpowerMulticastTable *td = (EmpowerMulticastTable *) e;
	switch ((uintptr_t) thunk) {
	case H_DEBUG:
		return String(td->_debug) + "\n";
	default:
		return String();
	}
}

int EmpowerMulticastTable::write_handler(const String &in_s, Element *e,
		void *vparam, ErrorHandler *errh) {

	EmpowerMulticastTable *f = (EmpowerMulticastTable *) e;
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

void EmpowerMulticastTable::add_handlers() {
	add_read_handler("debug", read_handler, (void *) H_DEBUG);
	add_write_handler("debug", write_handler, (void *) H_DEBUG);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(EmpowerMulticastTable)
