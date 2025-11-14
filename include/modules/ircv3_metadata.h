/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 * Copyright (C) 2024 Allen Day
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


#pragma once

#include "event.h"

namespace IRCv3
{
namespace Metadata
{
	enum TargetMask
	{
		TARGET_NONE    = 0,
		TARGET_USER    = 1 << 0,
		TARGET_CHANNEL = 1 << 1,
		TARGET_ALL     = TARGET_USER | TARGET_CHANNEL
	};

	struct TargetInfo
	{
		std::string name;
		User* user = NULL;
		Channel* chan = NULL;
		bool ischannel = false;

		TargetInfo() = default;

		explicit TargetInfo(User* u)
			: name(u ? u->nick : std::string())
			, user(u)
		{
		}

		explicit TargetInfo(Channel* c)
			: name(c ? c->name : std::string())
			, chan(c)
			, ischannel(true)
		{
		}
	};

	struct KeySpec
	{
		std::string name;
		unsigned int targets = TARGET_ALL;
		std::string visibility = "*";
		bool operonly = false;
		bool servicesonly = false;
		std::string setpriv;
		std::string viewpriv;
	};

class EventListener
	: public Events::ModuleEventListener
{
 public:
	EventListener(Module* mod, unsigned int eventprio = DefaultPriority)
		: ModuleEventListener(mod, "event/ircv3-metadata", eventprio)
	{
	}

		virtual ModResult OnPreMetadataSet(LocalUser* user, const TargetInfo& target, const std::string& key, std::string& value, bool removing)
		{
			return MOD_RES_PASSTHRU;
		}

		virtual void OnMetadataChanged(User* setter, const TargetInfo& target, const std::string& key, const std::string& value, bool removing)
		{
		}
	};

	class APIBase
		: public DataProvider
	{
	 public:
		APIBase(Module* mod)
			: DataProvider(mod, "ircv3metadata")
		{
		}

		/** Register or override the definition of a metadata key. */
		virtual bool RegisterKey(Module* owner, const KeySpec& spec) = 0;

		/** Remove all keys registered by the specified module. */
		virtual void UnregisterKeys(Module* owner) = 0;
	};

class API final
		: public dynamic_reference<APIBase>
	{
	 public:
		API(Module* mod)
			: dynamic_reference<APIBase>(mod, "ircv3metadata")
		{
		}
	};
}
}
