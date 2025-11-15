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

#include "inspircd.h"
#include "numerichelper.h"
#include "xline.h"

#ifdef USE_SYSTEM_UTFCPP
# include <utf8cpp/utf8.h>
#else
# include <utfcpp/core.h>
#endif

namespace
{
	struct KmerData final
	{
		unsigned int frequency = 0;
		time_t first_seen = 0;
		time_t last_seen = 0;
		insp::flat_set<std::string> ips;
	};

	enum class SpamAction
		: uint8_t
	{
		BLOCK,
		GLINE,
		SILENT
	};

	bool IsZeroWidth(uint32_t cp)
	{
		switch (cp)
		{
			case 0x00AD:
			case 0x180E:
			case 0x200B:
			case 0x200C:
			case 0x200D:
			case 0x2060:
			case 0xFEFF:
				return true;
		}
		return false;
	}
}

class ModuleKmerSpam final
	: public Module
{
private:
	insp::flat_map<std::string, KmerData> cache;
	SpamAction action = SpamAction::BLOCK;
	size_t kmersize = 4;
	size_t minlength = 10;
	double thresholdmin = 0.001;
	double thresholdmax = 0.1;
	double tau = 600.0;
	size_t maxcachesize = 100000;
	unsigned long cachettl = 600;
	unsigned long glineduration = 3600;
	std::string exemptmodes = "CoaA";
	std::string trustedmodes = "Vr";
	double trustedmultiplier = 5.0;
	time_t lastcleanup = 0;

public:
	ModuleKmerSpam()
		: Module(VF_VENDOR, "Detects duplicate private-message spam using k-mer fingerprints.")
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("kmerspam");
		kmersize = std::clamp(tag->getNum<size_t>("k", 4), static_cast<size_t>(3), static_cast<size_t>(6));
		minlength = tag->getNum<size_t>("minlength", 10, 6, 50);
		thresholdmin = tag->getNum<double>("threshold_min", 0.001, 0.0001, 1.0);
		thresholdmax = tag->getNum<double>("threshold_max", 0.1, 0.0001, 1.0);
		tau = tag->getNum<double>("tau", 600.0, 60.0, 7200.0);
		maxcachesize = tag->getNum<size_t>("max_cache_size", 100000, 1000, 500000);
		cachettl = tag->getDuration("cache_ttl", 600, 60, 3600);
		glineduration = tag->getDuration("gline_duration", 3600, 60, 86400);
		exemptmodes = tag->getString("exemptmodes", "CoaA");
		trustedmodes = tag->getString("trustedmodes", "Vr");
		trustedmultiplier = tag->getNum<double>("trusted_multiplier", 5.0, 1.0, 20.0);

		std::string actionstr = tag->getString("action", "block");
		std::transform(actionstr.begin(), actionstr.end(), actionstr.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		if (actionstr == "gline")
			action = SpamAction::GLINE;
		else if (actionstr == "silent")
			action = SpamAction::SILENT;
		else
			action = SpamAction::BLOCK;
	}

	ModResult OnUserPreMessage(User* user, MessageTarget& target, MessageDetails& details) override
	{
		LocalUser* local = IS_LOCAL(user);
		if (!local)
			return MOD_RES_PASSTHRU;

		// Only examine direct messages (PRIVMSG/TAGMSG to a single user).
		if (target.type != MessageTarget::TYPE_USER)
			return MOD_RES_PASSTHRU;

		const std::string normalized = NormalizeText(details.text);
		if (normalized.length() < minlength || normalized.length() < kmersize)
			return MOD_RES_PASSTHRU;

		const std::vector<std::string> kmers = ExtractKmers(normalized);
		if (kmers.empty())
			return MOD_RES_PASSTHRU;

		const double evalue = CalculateEValue(kmers);
		const double threshold = GetThreshold(local);
		if (evalue < threshold)
		{
			HandleDetection(local, target, normalized, evalue, threshold);
			return MOD_RES_DENY;
		}

		UpdateCache(kmers, local);
		return MOD_RES_PASSTHRU;
	}

	void OnBackgroundTimer(time_t curtime) override
	{
		CleanupCache(curtime, false);
	}

private:
	static bool IsAllowedChar(uint32_t cp)
	{
		return (cp >= 'a' && cp <= 'z') || (cp >= '0' && cp <= '9') || cp == '.' || cp == '-' || cp == '_';
	}

	std::string NormalizeText(const std::string& input) const
	{
		std::string normalized;
		normalized.reserve(input.size());

		try
		{
			utf8::iterator<std::string::const_iterator> it(input.begin(), input.begin(), input.end());
			utf8::iterator<std::string::const_iterator> itend(input.end(), input.begin(), input.end());
			while (it != itend)
			{
				uint32_t cp = *it;
				++it;

				if (IsZeroWidth(cp))
					continue;

				if (cp == ' ' || cp == '\t' || cp == '\n' || cp == '\r')
					continue;

				if (cp >= 'A' && cp <= 'Z')
					cp += 32;

				if (!IsAllowedChar(cp))
					continue;

				utf8::append(cp, std::back_inserter(normalized));
			}
		}
		catch (const utf8::exception&)
		{
			// Fall back to byte-wise filtering.
			for (unsigned char c : input)
			{
				uint32_t cp = c;

				if (IsZeroWidth(cp) || cp == ' ' || cp == '\t' || cp == '\n' || cp == '\r')
					continue;

				if (cp >= 'A' && cp <= 'Z')
					cp += 32;

				if (!IsAllowedChar(cp))
					continue;

				normalized.push_back(static_cast<char>(cp));
			}
		}

		return normalized;
	}

	std::vector<std::string> ExtractKmers(const std::string& text) const
	{
		std::vector<std::string> kmers;
		if (text.length() < kmersize)
			return kmers;

		kmers.reserve(text.length() - kmersize + 1);
		for (size_t idx = 0; idx <= text.length() - kmersize; ++idx)
			kmers.push_back(text.substr(idx, kmersize));
		return kmers;
	}

	double CalculateEValue(const std::vector<std::string>& kmers)
	{
		if (kmers.empty())
			return 1.0;

		const time_t now = ServerInstance->Time();
		CleanupCache(now, true);

		unsigned long total = 0;
		for (const auto& [_, entry] : cache)
			total += entry.frequency;

		if (!total)
			return 1.0;

		unsigned int overlap = 0;
		double expected = 0.0;
		for (const auto& kmer : kmers)
		{
			auto it = cache.find(kmer);
			if (it == cache.end())
				continue;

			overlap++;
			const double probability = static_cast<double>(it->second.frequency) / static_cast<double>(total);
			expected += probability;
		}

		if (!overlap)
			return 1.0;

		const double overlap_ratio = static_cast<double>(overlap) / static_cast<double>(kmers.size());
		const double expected_ratio = std::max(0.01, expected / static_cast<double>(kmers.size()));

		if (overlap_ratio <= expected_ratio)
			return 1.0;

		return std::exp(-(overlap_ratio - expected_ratio) * 10.0);
	}

	bool HasListedMode(LocalUser* user, const std::string& modes) const
	{
		if (!user || modes.empty())
			return false;
		for (const unsigned char ch : modes)
		{
			if (!ch)
				continue;
			if (user->IsModeSet(ch))
				return true;
		}
		return false;
	}

	double GetThreshold(LocalUser* user) const
	{
		if (!user)
			return thresholdmax;

		if (HasListedMode(user, exemptmodes))
			return 1.0;

		const double age = static_cast<double>(ServerInstance->Time() - user->signon);
		double threshold = thresholdmin + (thresholdmax - thresholdmin) * (1.0 - std::exp(-age / tau));
		if (HasListedMode(user, trustedmodes))
			threshold = std::min(1.0, threshold * trustedmultiplier);
		return std::min(1.0, threshold);
	}

	void HandleDetection(LocalUser* user, MessageTarget& target, const std::string& normalized, double evalue, double threshold)
	{
		User* dest = target.Get<User>();
		const std::string targetname = dest ? dest->nick : "*";
		ServerInstance->Logs.Normal(MODNAME, "k-mer spam: {} -> {} blocked (E={} threshold={}) text='{}'",
			user->GetRealHost(), targetname, evalue, threshold, normalized);

		switch (action)
		{
			case SpamAction::GLINE:
				IssueGLine(user);
				[[fallthrough]];
			case SpamAction::BLOCK:
				user->WriteNumeric(Numerics::CannotSendTo(dest, "Your message was blocked by the spam filter."));
				break;
			case SpamAction::SILENT:
				break;
		}
	}

	void IssueGLine(LocalUser* user)
	{
		auto* gline = new GLine(ServerInstance->Time(), glineduration, ServerInstance->Config->ServerName,
			"K-mer spam detected", user->GetBanUser(true), user->GetAddress());
		if (!ServerInstance->XLines->AddLine(gline, nullptr))
		{
			delete gline;
			return;
		}

		ServerInstance->SNO.WriteGlobalSno('x', "{} added a timed G-line on {} lasting {} for {}",
			gline->source, gline->Displayable(), Duration::ToString(glineduration), gline->reason);
		ServerInstance->XLines->ApplyLines();
	}

	void UpdateCache(const std::vector<std::string>& kmers, LocalUser* user)
	{
		const time_t now = ServerInstance->Time();
		const std::string ip = user->GetAddress();
		for (const auto& kmer : kmers)
		{
			KmerData& entry = cache[kmer];
			if (!entry.frequency)
				entry.first_seen = now;
			entry.frequency++;
			entry.last_seen = now;
			if (entry.ips.size() < 32)
				entry.ips.insert(ip);
		}

		EnforceCacheLimit();
	}

	void CleanupCache(time_t now, bool force)
	{
		if (!force && (now == lastcleanup || now - lastcleanup < 30))
			return;
		lastcleanup = now;

		for (auto it = cache.begin(); it != cache.end(); )
		{
			if ((now - it->second.last_seen) > static_cast<time_t>(cachettl))
				it = cache.erase(it);
			else
				++it;
		}
	}

	void EnforceCacheLimit()
	{
		while (cache.size() > maxcachesize)
		{
			auto oldest = cache.begin();
			for (auto it = std::next(cache.begin()); it != cache.end(); ++it)
			{
				if (it->second.last_seen < oldest->second.last_seen)
					oldest = it;
			}
			cache.erase(oldest);
		}
	}
};

MODULE_INIT(ModuleKmerSpam)
