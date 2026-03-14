using Google.Protobuf;
using BaileysCSharp.Core.Helper;
using BaileysCSharp.Core.Models;
using BaileysCSharp.Core.Models.SenderKeys;
using BaileysCSharp.Core.Models.Sessions;
using BaileysCSharp.Core.NoSQL;
using BaileysCSharp.LibSignal;
using static BaileysCSharp.Core.Helper.CryptoUtils;
using BaileysCSharp.Core.Utils;
using static BaileysCSharp.Core.Utils.JidUtils;
using BaileysCSharp.Core.Types;

namespace BaileysCSharp.Core.Signal
{
    public class SignalStorage
    {
        public SignalStorage(AuthenticationState auth)
        {
            Creds = auth.Creds;
            Keys = auth.Keys;
        }

        public AuthenticationCreds Creds { get; set; }
        public BaseKeyStore Keys { get; set; }

        /// <summary>
        /// The LID mapping store, set by SignalRepository.
        /// Used to resolve PN signal addresses to LID addresses when loading/storing sessions.
        /// Ported from Baileys JS signalStorage.resolveLIDSignalAddress.
        /// </summary>
        public LIDMappingStore? LIDMapping { get; set; }

        /// <summary>
        /// Resolve a signal protocol address ID to its LID equivalent if a mapping exists.
        /// This ensures that sessions keyed by PN addresses are transparently resolved
        /// to LID addresses once the LID mapping is known.
        ///
        /// Matches Baileys JS signalStorage.resolveLIDSignalAddress.
        /// </summary>
        private string ResolveLIDSignalAddress(string id)
        {
            if (LIDMapping == null)
                return id;

            if (id.Contains('.'))
            {
                var parts = id.Split('.');
                var userPart = parts[0];
                var device = parts.Length > 1 ? parts[1] : "0";

                // Parse user_domainType format
                var userDomainParts = userPart.Split('_');
                var user = userDomainParts[0];
                int domainType = userDomainParts.Length > 1 && int.TryParse(userDomainParts[1], out var dt) ? dt : 0;

                // If already LID domain, no resolution needed
                if (domainType == (int)WAJIDDomains.LID || domainType == (int)WAJIDDomains.HOSTED_LID)
                    return id;

                // Reconstruct PN JID and look up LID
                var server = domainType == (int)WAJIDDomains.HOSTED ? "hosted" : "s.whatsapp.net";
                var pnJid = device != "0"
                    ? $"{user}:{device}@{server}"
                    : $"{user}@{server}";

                var lidForPN = LIDMapping.GetLIDForPN(pnJid);
                if (lidForPN != null)
                {
                    var lidAddr = new ProtocolAddress(lidForPN);
                    return lidAddr.ToString();
                }
            }

            return id;
        }

        public bool IsTrustedIdentity(string fqAddr, ByteString identityKey)
        {
            return true;
        }


        internal KeyPair LoadSignedPreKey(uint signedPreKeyId)
        {
            return Creds.SignedPreKey;
        }

        internal KeyPair GetOurIdentity()
        {
            return new KeyPair()
            {
                Private = Creds.SignedIdentityKey.Private,
                Public = GenerateSignalPubKey(Creds.SignedIdentityKey.Public),
            };
        }

        internal KeyPair LoadPreKey(uint preKeyId)
        {
            var result = Keys.Get<PreKeyPair>(preKeyId.ToString());
            if (result == null)
                return null;
            return result;
        }

        internal void RemovePreKey(uint preKeyId)
        {
            Keys.Set<PreKeyPair>(preKeyId.ToString(), null);
        }

        internal void StoreSenderKey(string senderName, SenderKeyRecord senderMsg)
        {
            Keys.Set(senderName, senderMsg);
        }

        internal SenderKeyRecord LoadSenderKey(string senderName)
        {
            return Keys.Get<SenderKeyRecord>(senderName);
        }

        /// <summary>
        /// Load a Signal session, resolving PN addresses to LID if mapping exists.
        /// Ported from Baileys JS signalStorage.loadSession.
        /// </summary>
        internal SessionRecord? LoadSession(ProtocolAddress address)
        {
            var wireId = ResolveLIDSignalAddress(address.ToString());
            return Keys.Get<SessionRecord>(wireId);
        }

        /// <summary>
        /// Store a Signal session, resolving PN addresses to LID if mapping exists.
        /// Ported from Baileys JS signalStorage.storeSession.
        /// </summary>
        internal void StoreSession(ProtocolAddress address, SessionRecord record)
        {
            var wireId = ResolveLIDSignalAddress(address.ToString());
            Keys.Set(wireId, record);
        }

        internal uint GetOurRegistrationId()
        {
            return (uint)Creds.RegistrationId;
        }
    }
}
