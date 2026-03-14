using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using BaileysCSharp.Core.Helper;
using BaileysCSharp.Core.Models;
using BaileysCSharp.Core.Signal;
using BaileysCSharp.Core.Types;

namespace BaileysCSharp.Core.Utils
{
    /// <summary>
    /// WAJIDDomains enum matching Baileys JS WAJIDDomains.
    /// Used for Signal protocol address encoding to distinguish
    /// PN (phone number) vs LID (linked identity) sessions.
    /// </summary>
    public enum WAJIDDomains
    {
        WHATSAPP = 0,
        LID = 1,
        HOSTED = 128,
        HOSTED_LID = 129
    }

    public static class JidUtils
    {
        public static FullJid? JidDecode(string jid)
        {
            if (string.IsNullOrEmpty(jid))
                return null;

            var sepIndex = jid.IndexOf('@');
            if (sepIndex < 0)
                return null;

            FullJid result = new FullJid();

            result.Server = jid.Substring(sepIndex + 1);

            var userCombined = jid.Substring(0, sepIndex);

            var userAgentDevice = userCombined.Split(':');
            var userAgent = userAgentDevice[0];

            // Split user_agent (e.g. "user_1" for hosted domains)
            var userAgentParts = userAgent.Split('_');
            result.User = userAgentParts[0];

            if (userAgentDevice.Length > 1)
            {
                result.Device = Convert.ToUInt32(userAgentDevice[1]);
            }

            // Compute DomainType based on server, matching Baileys JS logic
            if (result.Server == "lid")
                result.DomainType = (int)WAJIDDomains.LID;
            else if (result.Server == "hosted")
                result.DomainType = (int)WAJIDDomains.HOSTED;
            else if (result.Server == "hosted.lid")
                result.DomainType = (int)WAJIDDomains.HOSTED_LID;
            else if (userAgentParts.Length > 1 && int.TryParse(userAgentParts[1], out var agentDomain))
                result.DomainType = agentDomain;
            else
                result.DomainType = (int)WAJIDDomains.WHATSAPP;

            return result;
        }


        public static string JidNormalizedUser(string jid)
        {
            var result = JidDecode(jid);
            if (result == null)
                return "";
            var server = result.Server == "c.us" ? "s.whatsapp.net" : result.Server;
            return JidEncode(result.User, server);
        }

        public static string JidEncode(string user, string server, uint? device = null, int? agent = null)
        {
            if (device == 0)
                device = null;
            return $"{user ?? ""}{(agent != null ? $"_{agent}" : "")}{(device != null ? $":{device}" : "")}@{server}";
        }

        /// <summary>
        /// Transfer device ID from one JID to another, matching Baileys JS transferDevice.
        /// </summary>
        public static string TransferDevice(string fromJid, string toJid)
        {
            var fromDecoded = JidDecode(fromJid);
            var deviceId = fromDecoded?.Device ?? 0;
            var toDecoded = JidDecode(toJid);
            return JidEncode(toDecoded.User, toDecoded.Server, deviceId);
        }

        /// <summary>
        /// Get the server string for a given domain type, matching Baileys JS getServerFromDomainType.
        /// </summary>
        public static string GetServerFromDomainType(string initialServer, int? domainType)
        {
            return domainType switch
            {
                (int)WAJIDDomains.LID => "lid",
                (int)WAJIDDomains.HOSTED => "hosted",
                (int)WAJIDDomains.HOSTED_LID => "hosted.lid",
                _ => initialServer
            };
        }

        public static string JidToSignalSenderKeyName(string group, string user)
        {
            var addr = new ProtocolAddress(JidDecode(user));
            return $"{group}::{addr}";
        }


        public static bool AreJidsSameUser(string? id1, string? id2)
        {
            return JidDecode(id1)?.User == JidDecode(id2)?.User;
        }

        /// <summary>Is the JID a phone number user (@s.whatsapp.net)?</summary>
        public static bool IsJidUser(string id)
        {
            return id?.EndsWith("@s.whatsapp.net") == true;
        }

        /// <summary>Is the JID a phone number user? Alias for IsJidUser.</summary>
        public static bool IsPnUser(string id)
        {
            return id?.EndsWith("@s.whatsapp.net") == true;
        }

        /// <summary>Is the JID a LID (linked identity)?</summary>
        public static bool IsLidUser(string id)
        {
            return id?.EndsWith("@lid") == true;
        }

        /// <summary>Is the JID a hosted PN?</summary>
        public static bool IsHostedPnUser(string id)
        {
            return id?.EndsWith("@hosted") == true;
        }

        /// <summary>Is the JID a hosted LID?</summary>
        public static bool IsHostedLidUser(string id)
        {
            return id?.EndsWith("@hosted.lid") == true;
        }

        public static bool IsBroadcast(string id)
        {
            return id?.EndsWith("@broadcast") == true;
        }

        public static bool IsJidStatusBroadcast(string id)
        {
            return id == "status@broadcast";
        }

        public static bool IsJidNewsletter(string id)
        {
            return id?.EndsWith("@newsletter") == true;
        }

        public static bool IsJidGroup(string id)
        {
            return id?.EndsWith("@g.us") == true;
        }

    }

}
