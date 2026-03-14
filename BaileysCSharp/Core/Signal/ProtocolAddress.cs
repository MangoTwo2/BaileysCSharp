using System.Text.Json.Serialization;
using static BaileysCSharp.Core.Utils.JidUtils;

namespace BaileysCSharp.Core.Signal
{
    public class ProtocolAddress
    {
        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("deviceId")]
        public long DeviceID { get; set; }

        public ProtocolAddress()
        {

        }
        public ProtocolAddress(string jid) : this(JidDecode(jid))
        {

        }

        public ProtocolAddress(FullJid jid)
        {
            // Match Baileys JS jidToSignalProtocolAddress:
            // For non-WHATSAPP domains, encode as "user_domainType"
            // This is critical for LID JIDs so they get separate Signal sessions
            var domainType = jid.DomainType ?? (int)Utils.WAJIDDomains.WHATSAPP;
            Name = domainType != (int)Utils.WAJIDDomains.WHATSAPP
                ? $"{jid.User}_{domainType}"
                : jid.User;
            DeviceID = jid.Device ?? 0;
        }

        public override string ToString()
        {
            return $"{Name}.{DeviceID}";
        }
    }

}
