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
#include "timeutils.h"
#include "xline.h"
#include "extension.h"
#include <cmath>
#include <deque>

#ifdef USE_SYSTEM_UTFCPP
# include <utf8cpp/utf8.h>
#else
# include <utfcpp/core.h>
#endif

namespace
{
	enum class SpamAction
		: uint8_t
	{
		DELAY,
		BLOCK,
		GLINE,
		SILENT
	};

	struct KmerData final
	{
		unsigned int frequency = 0;
		time_t last_seen = 0;
	};

	struct ReputationEntry final
	{
		double score = 0.0;
		time_t last_seen = 0;
	};

	struct TarpitMessage final
	{
		std::string command;
		std::string target;
		std::string message;
		time_t release = 0;
	};

	struct UserStats final
	{
		size_t early_messages = 0;
		size_t early_totalkmers = 0;
		insp::flat_set<std::string> early_distinct;
		double early_weight_sum = 0.0;
		time_t tarpit_until = 0;
		bool bypass = false;
		std::deque<TarpitMessage> queue;
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
	insp::flat_map<std::string, ReputationEntry> reputation;
	SimpleExtItem<UserStats> userstats;
	SpamAction action = SpamAction::DELAY;
	size_t kmersize = 4;
	size_t minlength = 12;
	size_t earlymaxmessages = 10;
	double earlyratio = 0.35;
	double earlyweight = 9.2;
	double spammythreshold = 0.30;
	size_t maxcachesize = 100000;
	unsigned long cachettl = 600;
	unsigned long reputationttl = 900;
	size_t warmupobservations = 5000;
	unsigned long tarpitdelay = 10;
	unsigned long glineduration = 3600;
	unsigned long totalobservations = 0;
	std::string exemptmodes = "CoaA";
	std::string trustedmodes = "Vr";
	time_t lastcachecleanup = 0;
	time_t lastreputationcleanup = 0;

public:
	ModuleKmerSpam()
		: Module(VF_VENDOR, "Detects duplicate private-message spam using k-mer fingerprints.")
		, userstats(this, "kmerspam-stats", ExtensionType::USER, true)
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("kmerspam");
		kmersize = std::clamp(tag->getNum<size_t>("k", 4), static_cast<size_t>(3), static_cast<size_t>(6));
		minlength = tag->getNum<size_t>("minlength", 12, 6, 80);
		earlymaxmessages = tag->getNum<size_t>("early_max_messages", 10, 1, 50);
		earlyratio = tag->getNum<double>("early_ratio", 0.35, 0.0, 1.0);
		earlyweight = tag->getNum<double>("early_weight", 9.2, 0.0, 30.0);
		spammythreshold = tag->getNum<double>("spammy_threshold", 0.30, 0.0, 1.0);
		maxcachesize = tag->getNum<size_t>("max_cache_size", 100000, 1000, 500000);
		cachettl = tag->getDuration("cache_ttl", 600, 60, 3600);
		reputationttl = tag->getDuration("reputation_ttl", 900, 60, 7200);
		warmupobservations = tag->getNum<size_t>("warmup_observations", 5000, 0, 1000000);
		tarpitdelay = tag->getDuration("tarpit_delay", 10, 1, 600);
		glineduration = tag->getDuration("gline_duration", 3600, 60, 86400);
		exemptmodes = tag->getString("exemptmodes", "CoaA");
		trustedmodes = tag->getString("trustedmodes", "Vr");

		std::string actionstr = tag->getString("action", "delay");
		std::transform(actionstr.begin(), actionstr.end(), actionstr.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		if (actionstr == "gline")
			action = SpamAction::GLINE;
		else if (actionstr == "block")
			action = SpamAction::BLOCK;
		else if (actionstr == "silent")
			action = SpamAction::SILENT;
		else
			action = SpamAction::DELAY;
	}

	ModResult OnUserPreMessage(User* user, MessageTarget& target, MessageDetails& details) override
	{
		LocalUser* local = IS_LOCAL(user);
		if (!local)
			return MOD_RES_PASSTHRU;

		if (HasListedMode(local, exemptmodes) || HasListedMode(local, trustedmodes))
			return MOD_RES_PASSTHRU;

		if (target.type != MessageTarget::TYPE_USER)
			return MOD_RES_PASSTHRU;

		UserStats* stats = GetStats(local);
		if (stats->bypass)
		{
			stats->bypass = false;
			return MOD_RES_PASSTHRU;
		}

		const std::string normalized = NormalizeText(details.text);
		if (normalized.length() < minlength || normalized.length() < kmersize)
			return MOD_RES_PASSTHRU;

		const std::vector<std::string> kmers = ExtractKmers(normalized);
		if (kmers.empty())
			return MOD_RES_PASSTHRU;

		const time_t now = ServerInstance->Time();

		if (totalobservations < warmupobservations)
		{
			UpdateCache(kmers, now);
			return MOD_RES_PASSTHRU;
		}

		const double msgweight = CalculateMessageWeight(kmers);
		const double spammy_ratio = CalculateSpammyRatio(kmers, now);

		UpdateEarlyStats(*stats, kmers, msgweight);
		const double ratio = GetEntropyRatio(*stats);
		const double weightavg = GetWeightAverage(*stats, msgweight);

		UpdateCache(kmers, now);

		const bool earlytrip = (stats->early_messages <= earlymaxmessages)
			&& (ratio < earlyratio) && (weightavg < earlyweight);
		const bool reputationtrip = (spammy_ratio > spammythreshold);

		bool shoulddelay = (now < stats->tarpit_until) || earlytrip || reputationtrip;

		if (!shoulddelay)
			return MOD_RES_PASSTHRU;

		if (earlytrip)
			MarkKmersSpammy(kmers, now);

		if (action == SpamAction::DELAY)
		{
			QueueMessage(*stats, local, target, details, now);
			return MOD_RES_DENY;
		}

		HandleDetection(local, target, normalized);
		return MOD_RES_DENY;
	}

	void OnBackgroundTimer(time_t curtime) override
	{
		CleanupCache(curtime);
		CleanupReputation(curtime);
		ProcessQueues(curtime);
	}

private:
	UserStats* GetStats(LocalUser* user)
	{
		auto* stats = userstats.Get(user);
		if (!stats)
		{
			stats = new UserStats;
			userstats.Set(user, stats);
		}
		return stats;
	}

	void UpdateEarlyStats(UserStats& stats, const std::vector<std::string>& kmers, double msgweight) const
	{
		if (stats.early_messages >= earlymaxmessages)
			return;

		stats.early_messages++;
		stats.early_totalkmers += kmers.size();
		stats.early_weight_sum += msgweight * kmers.size();
		for (const auto& kmer : kmers)
			stats.early_distinct.insert(kmer);
	}

	double GetEntropyRatio(const UserStats& stats) const
	{
		if (!stats.early_totalkmers)
			return 1.0;
		return static_cast<double>(stats.early_distinct.size()) / static_cast<double>(stats.early_totalkmers);
	}

	double GetWeightAverage(const UserStats& stats, double msgweight) const
	{
		if (!stats.early_totalkmers)
			return msgweight;
		return stats.early_weight_sum / static_cast<double>(stats.early_totalkmers);
	}

	double CalculateMessageWeight(const std::vector<std::string>& kmers) const
	{
		if (kmers.empty() || !totalobservations)
			return 0.0;

		double total = 0.0;
		for (const auto& kmer : kmers)
		{
			const auto it = cache.find(kmer);
			const double freq = (it == cache.end() ? 0.0 : static_cast<double>(it->second.frequency));
			total += std::log((static_cast<double>(totalobservations) + 1.0) / (freq + 1.0));
		}
		return total / static_cast<double>(kmers.size());
	}

	double CalculateSpammyRatio(const std::vector<std::string>& kmers, time_t now)
	{
		if (kmers.empty())
			return 0.0;

		size_t hits = 0;
		for (const auto& kmer : kmers)
		{
			auto it = reputation.find(kmer);
			if (it == reputation.end())
				continue;
			if ((now - it->second.last_seen) > static_cast<time_t>(reputationttl))
				continue;
			if (it->second.score > 0.0)
				hits++;
		}

		return static_cast<double>(hits) / static_cast<double>(kmers.size());
	}

	void MarkKmersSpammy(const std::vector<std::string>& kmers, time_t now)
	{
		for (const auto& kmer : kmers)
		{
			ReputationEntry& entry = reputation[kmer];
			entry.score += 1.0;
			entry.last_seen = now;
		}
	}

	void QueueMessage(UserStats& stats, LocalUser* user, MessageTarget& target, MessageDetails& details, time_t now)
	{
		User* dest = target.Get<User>();
		if (!dest)
			return;

		TarpitMessage pending;
		pending.command = (details.type == MessageType::NOTICE ? "NOTICE" : "PRIVMSG");
		pending.target = dest->nick;
		pending.message = details.text;
		pending.release = std::max(now, stats.tarpit_until) + tarpitdelay;
		stats.tarpit_until = pending.release;
		stats.queue.push_back(pending);

		user->WriteNotice("Your message has been delayed by the spam filter.");
		ServerInstance->Logs.Debug(MODNAME, "Delaying message from {} to {} until {}",
			user->nick, pending.target, pending.release);
	}

	void ProcessQueues(time_t now)
	{
		const UserManager::LocalList& locals = ServerInstance->Users.GetLocalUsers();
		for (const auto& it : locals)
		{
			LocalUser* user = it;
			auto* stats = userstats.Get(user);
			if (!stats)
				continue;

			bool released = false;
			while (!stats->queue.empty() && stats->queue.front().release <= now)
			{
				TarpitMessage msg = stats->queue.front();
				stats->queue.pop_front();

				if (user->quitting)
					continue;

				CommandBase::Params params;
				params.push_back(msg.target);
				params.push_back(msg.message);

				stats->bypass = true;
				if (ServerInstance->Parser.CallHandler(msg.command, params, user) != CmdResult::SUCCESS)
					user->WriteNotice("A delayed message could not be delivered.");
				stats->bypass = false;
				released = true;
			}

			if (released && stats->queue.empty() && now >= stats->tarpit_until)
				stats->tarpit_until = now;
		}
	}

	void HandleDetection(LocalUser* user, MessageTarget& target, const std::string& normalized)
	{
		User* dest = target.Get<User>();
		const std::string targetname = dest ? dest->nick : "*";

		ServerInstance->Logs.Normal(MODNAME, "k-mer spam detected: {} -> {} text='{}'",
			user->GetRealHost(), targetname, normalized);

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
			case SpamAction::DELAY:
				// This path should not be reached; handled earlier.
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

	void UpdateCache(const std::vector<std::string>& kmers, time_t now)
	{
		for (const auto& kmer : kmers)
		{
			KmerData& entry = cache[kmer];
			entry.frequency++;
			entry.last_seen = now;
		}

		totalobservations += kmers.size();
		EnforceCacheLimit();
	}

	void CleanupCache(time_t now)
	{
		if (now == lastcachecleanup || now - lastcachecleanup < 30)
			return;
		lastcachecleanup = now;

		for (auto it = cache.begin(); it != cache.end(); )
		{
			if ((now - it->second.last_seen) > static_cast<time_t>(cachettl))
			{
				if (totalobservations >= it->second.frequency)
					totalobservations -= it->second.frequency;
				it = cache.erase(it);
			}
			else
			{
				++it;
			}
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
			if (totalobservations >= oldest->second.frequency)
				totalobservations -= oldest->second.frequency;
			cache.erase(oldest);
		}
	}

	void CleanupReputation(time_t now)
	{
		if (now == lastreputationcleanup || now - lastreputationcleanup < 60)
			return;
		lastreputationcleanup = now;

		for (auto it = reputation.begin(); it != reputation.end(); )
		{
			if ((now - it->second.last_seen) > static_cast<time_t>(reputationttl))
				it = reputation.erase(it);
			else
				++it;
		}
	}

	static bool HasListedMode(LocalUser* user, const std::string& modes)
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

	static bool IsAllowedChar(uint32_t cp)
	{
		return (cp >= 'a' && cp <= 'z') || (cp >= '0' && cp <= '9') || cp == '.' || cp == '-' || cp == '_';
	}
};

MODULE_INIT(ModuleKmerSpam)
