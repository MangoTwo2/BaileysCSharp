using System.Collections.Concurrent;
using BaileysCSharp.Core.Logging;
using BaileysCSharp.Core.NoSQL;
using BaileysCSharp.Core.Utils;
using static BaileysCSharp.Core.Utils.JidUtils;

namespace BaileysCSharp.Core.Signal
{
    /// <summary>
    /// Represents a LID ↔ PN (phone number) mapping pair.
    /// Ported from Baileys JS lid-mapping.ts.
    /// </summary>
    public class LIDMapping
    {
        public string LID { get; set; }
        public string PN { get; set; }
    }

    /// <summary>
    /// Bidirectional cache and persistent store for LID ↔ PN mappings.
    /// Ported from Baileys JS LIDMappingStore.
    ///
    /// This is the key component that enables WhatsApp's LID migration:
    /// - When a message arrives from a LID JID, we look up the corresponding PN JID
    ///   so we can find the existing Signal session
    /// - When sending to a PN JID, we look up if there's a LID mapping to use
    ///   for the actual wire protocol
    /// </summary>
    public class LIDMappingStore
    {
        // In-memory bidirectional cache: "pn:{user}" -> lidUser, "lid:{user}" -> pnUser
        private readonly ConcurrentDictionary<string, string> _cache = new();
        private readonly DefaultLogger _logger;

        public LIDMappingStore(DefaultLogger logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Store one or more LID ↔ PN mapping pairs.
        /// </summary>
        public void StoreLIDPNMappings(IEnumerable<LIDMapping> pairs)
        {
            foreach (var pair in pairs)
            {
                if (string.IsNullOrEmpty(pair.LID) || string.IsNullOrEmpty(pair.PN))
                    continue;

                // Validate: one must be LID, other must be PN
                string lidJid, pnJid;
                if ((IsLidUser(pair.LID) || IsHostedLidUser(pair.LID)) && (IsPnUser(pair.PN) || IsHostedPnUser(pair.PN)))
                {
                    lidJid = pair.LID;
                    pnJid = pair.PN;
                }
                else if ((IsPnUser(pair.LID) || IsHostedPnUser(pair.LID)) && (IsLidUser(pair.PN) || IsHostedLidUser(pair.PN)))
                {
                    lidJid = pair.PN;
                    pnJid = pair.LID;
                }
                else
                {
                    _logger.Warn($"Invalid LID-PN mapping: {pair.LID}, {pair.PN}");
                    continue;
                }

                var lidDecoded = JidDecode(lidJid);
                var pnDecoded = JidDecode(pnJid);
                if (lidDecoded == null || pnDecoded == null)
                    continue;

                var pnUser = pnDecoded.User;
                var lidUser = lidDecoded.User;

                _cache[$"pn:{pnUser}"] = lidUser;
                _cache[$"lid:{lidUser}"] = pnUser;

                _logger.Debug(new { pnUser, lidUser }, "Stored LID-PN mapping");
            }
        }

        /// <summary>
        /// Get the LID JID for a given PN JID.
        /// Returns the full LID JID with device, or null if not found.
        /// </summary>
        public string? GetLIDForPN(string pn)
        {
            if (string.IsNullOrEmpty(pn))
                return null;

            if (!IsPnUser(pn) && !IsHostedPnUser(pn))
                return null;

            var decoded = JidDecode(pn);
            if (decoded == null)
                return null;

            if (_cache.TryGetValue($"pn:{decoded.User}", out var lidUser) && !string.IsNullOrEmpty(lidUser))
            {
                var pnDevice = decoded.Device ?? 0;
                var server = decoded.Server == "hosted" ? "hosted.lid" : "lid";
                var deviceSpecificLid = pnDevice != 0
                    ? $"{lidUser}:{pnDevice}@{server}"
                    : $"{lidUser}@{server}";
                return deviceSpecificLid;
            }

            return null;
        }

        /// <summary>
        /// Get the PN JID for a given LID JID.
        /// Returns the full PN JID with device, or null if not found.
        /// </summary>
        public string? GetPNForLID(string lid)
        {
            if (string.IsNullOrEmpty(lid))
                return null;

            if (!IsLidUser(lid) && !IsHostedLidUser(lid))
                return null;

            var decoded = JidDecode(lid);
            if (decoded == null)
                return null;

            if (_cache.TryGetValue($"lid:{decoded.User}", out var pnUser) && !string.IsNullOrEmpty(pnUser))
            {
                var lidDevice = decoded.Device ?? 0;
                var server = decoded.DomainType == (int)WAJIDDomains.HOSTED_LID ? "hosted" : "s.whatsapp.net";
                var pnJid = lidDevice != 0
                    ? $"{pnUser}:{lidDevice}@{server}"
                    : $"{pnUser}@{server}";
                return pnJid;
            }

            return null;
        }

        /// <summary>
        /// Get LIDs for multiple PNs. Returns pairs where mapping was found.
        /// </summary>
        public List<LIDMapping>? GetLIDsForPNs(IEnumerable<string> pns)
        {
            var results = new List<LIDMapping>();
            foreach (var pn in pns)
            {
                var lid = GetLIDForPN(pn);
                if (lid != null)
                {
                    results.Add(new LIDMapping { LID = lid, PN = pn });
                }
            }
            return results.Count > 0 ? results : null;
        }

        /// <summary>
        /// Get PNs for multiple LIDs. Returns pairs where mapping was found.
        /// </summary>
        public List<LIDMapping>? GetPNsForLIDs(IEnumerable<string> lids)
        {
            var results = new List<LIDMapping>();
            foreach (var lid in lids)
            {
                var pn = GetPNForLID(lid);
                if (pn != null)
                {
                    results.Add(new LIDMapping { LID = lid, PN = pn });
                }
            }
            return results.Count > 0 ? results : null;
        }
    }
}
