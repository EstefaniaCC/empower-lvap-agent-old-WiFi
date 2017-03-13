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
#include "igmppacket.hh"
#include "empowerigmpmembership.hh"
#include "empowermulticasttable.hh"
CLICK_DECLS

EmpowerMulticastTable::EmpowerMulticastTable() :
	_debug(false) {
}

EmpowerMulticastTable::~EmpowerMulticastTable() {
}

int EmpowerMulticastTable::configure(Vector<String> &conf,
		ErrorHandler *errh) {

	int ret = Args(conf, this, errh)
			  .read("DEBUG", _debug).complete();

	return ret;

}

bool EmpowerMulticastTable::addgroup(IPAddress group)
{
	const unsigned char *p = group.data();

	click_chatter("%{element} :: %s :: ADD GROUP for %d.%d.%d.%d",
										  this,
										  __func__, p[0], p[1], p[2], p[3]);

	EmpowerMulticastGroup newgroup;
	newgroup.group = group;

	Vector<EmpowerMulticastGroup>::iterator i;
	for (i = multicastgroups.begin(); i != multicastgroups.end(); i++) {
		if (IPAddress((*i).group) == IPAddress(group))
			return false;
	}

	newgroup.mac_group = ip_mcast_addr_to_mac(group);
	multicastgroups.push_back(newgroup);
	return true;

}

bool EmpowerMulticastTable::joingroup(EtherAddress sta, IPAddress group)
{
	const unsigned char *p = group.data();

	click_chatter("%{element} :: %s :: JOIN GROUP for %d.%d.%d.%d",
										  this,
										  __func__, p[0], p[1], p[2], p[3]);

	EmpowerMulticastReceiver new_receiver;
	new_receiver.sta = sta;

	Vector<EmpowerMulticastGroup>::iterator i;

	for (i = multicastgroups.begin(); i != multicastgroups.end(); i++)
	{
		if ((*i).group.addr() == group.addr())
		{
			Vector<EmpowerMulticastReceiver>::iterator a;
			for (a = (*i).receivers.begin(); a != (*i).receivers.end(); a++)
			{
				if ((*a).sta == sta)
				{
					click_chatter("%{element} :: %s :: Station %s already in group %d.%d.%d.%d!",
							this, __func__, sta.unparse().c_str(), (*i).group.data()[0], (*i).group.data()[1],
							(*i).group.data()[2], (*i).group.data()[3]);
					return false;
				}
			}
			(*i).receivers.push_back(new_receiver);
			click_chatter("%{element} :: %s :: Station %s added to group %d.%d.%d.%d!",
					this, __func__, sta.unparse().c_str(), (*i).group.data()[0], (*i).group.data()[1],
					(*i).group.data()[2], (*i).group.data()[3]);
		}
	}

	return true;
}


bool EmpowerMulticastTable::leavegroup(EtherAddress sta, IPAddress group)
{
	const unsigned char *p = group.data();

	click_chatter("%{element} :: %s :: LEAVE GROUP for %d.%d.%d.%d",
										  this,
										  __func__, p[0], p[1], p[2], p[3]);

	Vector<EmpowerMulticastGroup>::iterator i;

	for (i = multicastgroups.begin(); i != multicastgroups.end(); i++)
	{
		if ((*i).group.addr() == group.addr())
		{
			Vector<EmpowerMulticastReceiver>::iterator a;
			for (a = (*i).receivers.begin(); a != (*i).receivers.end(); a++)
			{
				if ((*a).sta == sta)
				{
					(*i).receivers.erase(a);
					click_chatter("%{element} :: %s :: Station %s added removed from group %d.%d.%d.%d",
										this, __func__, sta.unparse().c_str(),
										(*i).group.data()[0], (*i).group.data()[1],
										(*i).group.data()[2], (*i).group.data()[3]);
					// The group is deleted if no more receivers belong to it
					if ((*i).receivers.begin() == (*i).receivers.end())
					{
						multicastgroups.erase(i);
						click_chatter("%{element} :: %s :: Group %d.%d.%d.%d is empty. It is about to be deleted",
																this, __func__, (*i).group.data()[0], (*i).group.data()[1],
																(*i).group.data()[2], (*i).group.data()[3]);
						return true;
					}
					return true;
				}
			}

		}
		click_chatter("%{element} :: %s :: IGMP leave group request received from station %s not found in group %d.%d.%d.%d",
													this, __func__, sta.unparse().c_str(), (*i).group.data()[0], (*i).group.data()[1],
													(*i).group.data()[2], (*i).group.data()[3]);
	}
	return false;
}

Vector<EmpowerMulticastTable::EmpowerMulticastReceiver>* EmpowerMulticastTable::getIGMPreceivers(EtherAddress group)
{
	click_chatter("%{element} :: %s :: RECEIVERS",
										  this,
										  __func__);

	Vector<struct EmpowerMulticastGroup>::iterator i;

	for (i = multicastgroups.begin(); i != multicastgroups.end(); i++)
	{
		if (i->mac_group == group)
		{
			click_chatter("%{element} :: %s :: Group %s found. The pointer should not be null %p",
													  this,
													  __func__, group.unparse().c_str(), &(i->receivers));
			return &(i->receivers);
			break;
		}
	}

	click_chatter("%{element} :: %s :: Group %s not found. The pointer is null",
														  this,
														  __func__, group.unparse().c_str(), &(i->receivers));

	return NULL;
}

bool EmpowerMulticastTable::leaveallgroups(EtherAddress sta)
{

	click_chatter("%{element} :: %s :: Leave all groups for sta %s",
										  this,
										  __func__, sta.unparse().c_str());

	Vector<EmpowerMulticastGroup>::iterator i;

	for (i = multicastgroups.begin(); i != multicastgroups.end(); i++)
	{
		Vector<EmpowerMulticastReceiver>::iterator a;
		for (a = (*i).receivers.begin(); a != (*i).receivers.end(); a++)
		{
			if ((*a).sta == sta)
			{
				(*i).receivers.erase(a);
				click_chatter("%{element} :: %s :: Station %s removed from group %d.%d.%d.%d",
									this, __func__, sta.unparse().c_str(),
									(*i).group.data()[0], (*i).group.data()[1],
									(*i).group.data()[2], (*i).group.data()[3]);
				// The group is deleted if no more receivers belong to it
				if ((*i).receivers.begin() == (*i).receivers.end())
				{
					multicastgroups.erase(i);
					click_chatter("%{element} :: %s :: Group %d.%d.%d.%d is empty. It is about to be deleted",
															this, __func__, (*i).group.data()[0], (*i).group.data()[1],
															(*i).group.data()[2], (*i).group.data()[3]);
				}
				break;
			}
		}
	}

	return true;
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
