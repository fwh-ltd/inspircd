/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2024 Allen Day
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
#include "modules/geolocation.h"
#include "modules/ircv3_metadata.h"

class ModuleGeoMetadata final
	: public Module
{
private:
	Geolocation::API geoapi;
	IRCv3::Metadata::API metaapi;

	void UpdateGeoMetadata(User* user)
	{
		if (!geoapi || !metaapi)
			return;

		Geolocation::Location* location = geoapi->GetLocation(user);
		if (location)
		{
			metaapi->SetKey(user, "geo/country-code", location->GetCode());
			metaapi->SetKey(user, "geo/country", location->GetName());
		}
		else
		{
			metaapi->UnsetKey(user, "geo/country-code");
			metaapi->UnsetKey(user, "geo/country");
		}
	}

public:
	ModuleGeoMetadata()
		: Module(VF_VENDOR | VF_OPTCOMMON, "Sets IRCv3 metadata keys with geolocation data for users.")
		, geoapi(this)
		, metaapi(this)
	{
	}

	void init() override
	{
		if (!metaapi)
		{
			ServerInstance->Logs.Warning(MODNAME, "The ircv3_metadata module must be loaded for this module to work.");
			return;
		}

		IRCv3::Metadata::KeySpec countrycode;
		countrycode.name = "geo/country-code";
		countrycode.targets = IRCv3::Metadata::TARGET_USER;
		countrycode.servicesonly = true;
		metaapi->RegisterKey(this, countrycode);

		IRCv3::Metadata::KeySpec countryname;
		countryname.name = "geo/country";
		countryname.targets = IRCv3::Metadata::TARGET_USER;
		countryname.servicesonly = true;
		metaapi->RegisterKey(this, countryname);
	}

	void OnChangeRemoteAddress(LocalUser* user) override
	{
		UpdateGeoMetadata(user);
	}

	ModResult OnUserRegister(LocalUser* user) override
	{
		UpdateGeoMetadata(user);
		return MOD_RES_PASSTHRU;
	}

	void OnUserDisconnect(LocalUser* user) override
	{
		if (metaapi)
		{
			metaapi->UnsetKey(user, "geo/country-code");
			metaapi->UnsetKey(user, "geo/country");
		}
	}
};

MODULE_INIT(ModuleGeoMetadata)
