/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 * Bridges services account data into IRCv3 metadata so capable clients
 * can read account names and subscriptions via draft/metadata-2.
 */

#include "inspircd.h"
#include "modules/account.h"
#include "modules/ircv3_metadata.h"

namespace
{
	static const std::string AccountKey = "services/account-name";
}

class ModuleServicesMetadata final
	: public Module
	, public Account::EventListener
	, public IRCv3::Metadata::EventListener
{
 private:
	IRCv3::Metadata::API metadataapi;

	void SetAccountMetadata(User* user, const std::string& account)
	{
		if (!metadataapi || !user)
			return;

		LocalUser* local = IS_LOCAL(user);
		if (!local)
			return; // remote updates arrive via METADATA netburst already

		CommandBase::Params params;
		params.push_back(user->nick);
		params.push_back("SET");
		params.push_back(AccountKey);
		if (!account.empty())
			params.push_back(account);

		Command* cmd = ServerInstance->Parser.GetHandler("METADATA");
		if (cmd)
			cmd->Handle(local, params);
	}

	public:
	ModuleServicesMetadata()
		: Module(VF_VENDOR | VF_OPTCOMMON, "Mirrors services account names into IRCv3 metadata.")
		, Account::EventListener(this)
		, IRCv3::Metadata::EventListener(this)
		, metadataapi(this)
	{
	}

 void ReadConfig(ConfigStatus& status) override
	{
		if (!metadataapi)
			throw ModuleException(this, "m_services_metadata requires m_ircv3_metadata");

		IRCv3::Metadata::KeySpec spec;
		spec.name = AccountKey;
		spec.targets = IRCv3::Metadata::TARGET_USER;
		spec.visibility = "@"; // show to opers by default
		spec.operonly = false;
		spec.servicesonly = true;
		spec.setpriv = "users/metadata/service";
		spec.viewpriv = "users/auspex";

		metadataapi->RegisterKey(this, spec);
	}

 void OnAccountChange(User* user, const std::string& newaccount) override
	{
		SetAccountMetadata(user, newaccount);
	}

	ModResult OnPreMetadataSet(LocalUser* user, const IRCv3::Metadata::TargetInfo& target,
		const std::string& key, std::string& value, bool removing) override
	{
		if (key != AccountKey)
			return MOD_RES_PASSTHRU;

		if (!user->HasPrivPermission("users/metadata/service"))
			return MOD_RES_DENY;

		return MOD_RES_PASSTHRU;
	}

	void OnMetadataChanged(User* setter, const IRCv3::Metadata::TargetInfo& target,
		const std::string& key, const std::string& value, bool removing) override
	{
		if (key != AccountKey || !target.user)
			return;
	}

	void OnUnloadModule(Module* mod) override
	{
		if (mod == this && metadataapi)
			metadataapi->UnregisterKeys(this);
	}
};

MODULE_INIT(ModuleServicesMetadata)
