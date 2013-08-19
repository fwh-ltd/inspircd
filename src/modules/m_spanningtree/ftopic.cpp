/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2010 Daniel De Graaf <danieldg@inspircd.org>
 *   Copyright (C) 2008 Robin Burchell <robin+git@viroteck.net>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "inspircd.h"
#include "commands.h"

/** FTOPIC command */
CmdResult CommandFTopic::Handle(User* user, std::vector<std::string>& params)
{
	Channel* c = ServerInstance->FindChan(params[0]);
	if (!c)
		return CMD_FAILURE;

	time_t ChanTS = ConvToInt(params[1]);
	if (!ChanTS)
		return CMD_INVALID;

	if (c->age < ChanTS)
		// Our channel TS is older, nothing to do
		return CMD_FAILURE;

	time_t ts = ConvToInt(params[2]);
	if (!ts)
		return CMD_INVALID;

	// Channel::topicset is initialized to 0 on channel creation, so their ts will always win if we never had a topic
	if (ts < c->topicset)
		return CMD_FAILURE;

	// The topic text is always the last parameter
	const std::string& newtopic = params.back();

	// If there is a setter in the message use that, otherwise use the message source
	const std::string& setter = ((params.size() > 4) ? params[3] : (ServerInstance->Config->FullHostInTopic ? user->GetFullHost() : user->nick));

	/*
	 * If the topics were updated at the exact same second, accept
	 * the remote only when it's "bigger" than ours as defined by
	 * string comparision, so non-empty topics always overridde
	 * empty topics if their timestamps are equal
	 *
	 * Similarly, if the topic texts are equal too, keep one topic
	 * setter and discard the other
	 */
	if (ts == c->topicset)
	{
		// Discard if their topic text is "smaller"
		if (c->topic > newtopic)
			return CMD_FAILURE;

		// If the texts are equal in addition to the timestamps, decide which setter to keep
		if ((c->topic == newtopic) && (c->setby >= setter))
			return CMD_FAILURE;
	}

	if (c->topic != newtopic)
	{
		// Update topic only when it differs from current topic
		c->topic.assign(newtopic, 0, ServerInstance->Config->Limits.MaxTopic);
		c->WriteChannel(user, "TOPIC %s :%s", c->name.c_str(), c->topic.c_str());
	}

	// Update setter and settime
	c->setby.assign(setter, 0, 128);
	c->topicset = ts;

	FOREACH_MOD(OnPostTopicChange, (user, c, c->topic));

	return CMD_SUCCESS;
}

// Used when bursting and in reply to RESYNC, contains topic setter as the 4th parameter
CommandFTopic::Builder::Builder(Channel* chan)
	: CmdBuilder("FTOPIC")
{
	push(chan->name);
	push_int(chan->age);
	push_int(chan->topicset);
	push(chan->setby);
	push_last(chan->topic);
}

// Used when changing the topic, the setter is the message source
CommandFTopic::Builder::Builder(User* user, Channel* chan)
	: CmdBuilder(user, "FTOPIC")
{
	push(chan->name);
	push_int(chan->age);
	push_int(chan->topicset);
	push_last(chan->topic);
}
