using Google.Protobuf;
using Proto;
using BaileysCSharp.Core.Models.SenderKeys;
using BaileysCSharp.Core.Models.Sessions;
using BaileysCSharp.Core.NoSQL;
using BaileysCSharp.Core.Stores;
using BaileysCSharp.LibSignal;
using static BaileysCSharp.Core.Utils.JidUtils;
using BaileysCSharp.Core.Types;
using BaileysCSharp.Core.Logging;

namespace BaileysCSharp.Core.Signal
{
    public class SignalRepository : IDisposable
    {
        public void Dispose() {}
        public SignalStorage Storage { get; set; }

        /// <summary>
        /// LID ↔ PN mapping store. Shared with SignalStorage for session resolution.
        /// Ported from Baileys JS SignalRepositoryWithLIDStore.lidMapping.
        /// </summary>
        public LIDMappingStore LIDMapping { get; }

        private DefaultLogger _logger;

        public SignalRepository(AuthenticationState auth, DefaultLogger? logger = null)
        {
            Auth = auth;
            _logger = logger;
            LIDMapping = new LIDMappingStore(logger);
            Storage = new SignalStorage(Auth);
            // Connect LID mapping to storage so session lookups resolve PN→LID
            Storage.LIDMapping = LIDMapping;
        }
        public AuthenticationState Auth { get; }

        /// <summary>
        /// Get the JID to use for Signal session lookup during decryption.
        /// If the sender is a PN user and we have a LID mapping, use the LID.
        /// If the sender is already LID, use it directly.
        /// Ported from Baileys JS decode-wa-message.ts getDecryptionJid.
        /// </summary>
        public string GetDecryptionJid(string sender)
        {
            if (IsLidUser(sender) || IsHostedLidUser(sender))
                return sender;

            var mapped = LIDMapping.GetLIDForPN(sender);
            return mapped ?? sender;
        }

        /// <summary>
        /// Convert a JID to its Signal protocol address string representation.
        /// Matches Baileys JS jidToSignalProtocolAddress.
        /// </summary>
        public string JidToSignalProtocolAddress(string jid)
        {
            return new ProtocolAddress(jid).ToString();
        }

        public byte[] DecryptGroupMessage(string group, string authorJid, byte[] content)
        {
            var senderName = JidToSignalSenderKeyName(group, authorJid);
            var session = new GroupCipher(Storage, senderName);
            return session.Decrypt(content);
        }

        public CipherMessage EncryptMessage(string jid, byte[] data)
        {
            var address = new ProtocolAddress(jid);
            var cipher = new SessionCipher(Storage, address);

            var enc = cipher.Encrypt(data);
            return new CipherMessage(enc.Type == 3 ? "pkmsg" : "msg", enc.Data);
        }

        public byte[] DecryptMessage(string user, string type, byte[] ciphertext)
        {
            var addr = new ProtocolAddress(user);
            var session = new SessionCipher(Storage, addr);
            byte[] result;
            if (type == "pkmsg")
            {
                result = session.DecryptPreKeyWhisperMessage(ciphertext);
            }
            else
            {
                result = session.DecryptWhisperMessage(ciphertext);
            }
            return result;
        }

        public void ProcessSenderKeyDistributionMessage(string author, Message.Types.SenderKeyDistributionMessage senderKeyDistributionMessage)
        {
            var builder = new GroupSessionBuilder(Storage);
            var senderName = JidToSignalSenderKeyName(senderKeyDistributionMessage.GroupId, author);
            var senderMsg = Proto.SenderKeyDistributionMessage.Parser.ParseFrom(senderKeyDistributionMessage.AxolotlSenderKeyDistributionMessage.ToByteArray().Skip(1).ToArray());
            Auth.Keys.Set(senderName, new SenderKeyRecord());
            builder.Process(senderName, senderMsg);
        }

        internal void InjectE2ESession(string jid, E2ESession session)
        {
            var addr = new ProtocolAddress(jid);
            var sessionBuilder = new SessionBuilder(Storage, addr);
            sessionBuilder.InitOutGoing(session);
        }

        public GroupCipherMessage EncryptGroupMessage(string group, string meId, byte[] bytes)
        {
            var senderName = JidToSignalSenderKeyName(group, meId);
            var builder = new GroupSessionBuilder(Storage);

            var senderKey = Auth.Keys.Get<SenderKeyRecord>(senderName);
            if (senderKey == null)
            {
                Auth.Keys.Set(senderName, new SenderKeyRecord());
            }

            var senderKeyDistributionMessage = builder.Create(senderName);

            var session = new GroupCipher(Storage, senderName);
            var ciphertext = session.Encrypt(bytes);


            return new GroupCipherMessage()
            {
                CipherText = ciphertext,
                SenderKeyDistributionMessage = new byte[] { 51 }.Concat(senderKeyDistributionMessage.ToByteArray()).ToArray()
            };
        }

        /// <summary>
        /// Migrate Signal sessions from one JID (typically PN) to another (typically LID).
        /// Copies the session data from the source address to the destination address.
        /// Ported from Baileys JS signalRepository.migrateSession.
        /// </summary>
        public (int migrated, int skipped, int total) MigrateSession(string fromJid, string toJid)
        {
            if (string.IsNullOrEmpty(fromJid) || string.IsNullOrEmpty(toJid))
                return (0, 0, 0);

            // Only support PN→LID migration
            if (!IsPnUser(fromJid) && !IsHostedPnUser(fromJid))
                return (0, 0, 1);

            if (!IsLidUser(toJid) && !IsHostedLidUser(toJid))
                return (0, 0, 1);

            var fromAddr = new ProtocolAddress(fromJid);
            var toAddr = new ProtocolAddress(toJid);

            var fromAddrStr = fromAddr.ToString();
            var toAddrStr = toAddr.ToString();

            // Load existing PN session
            var session = Auth.Keys.Get<SessionRecord>(fromAddrStr);
            if (session == null)
            {
                _logger?.Debug(new { fromJid, toJid }, "No session to migrate");
                return (0, 1, 1);
            }

            // Copy session to LID address
            Auth.Keys.Set(toAddrStr, session);
            // Optionally delete the PN session (keep it for now for backward compat)
            // Auth.Keys.Set<SessionRecord>(fromAddrStr, null);

            _logger?.Debug(new { fromJid, toJid, fromAddr = fromAddrStr, toAddr = toAddrStr }, "Migrated Signal session PN→LID");

            return (1, 0, 1);
        }

        /// <summary>
        /// Validate whether a Signal session exists for a given JID.
        /// Ported from Baileys JS signalRepository.validateSession.
        /// </summary>
        public bool ValidateSession(string jid)
        {
            var addr = new ProtocolAddress(jid);
            var session = Storage.LoadSession(addr);
            return session != null;
        }
    }

    public class GroupCipherMessage
    {
        public byte[] CipherText { get; set; }
        public byte[] SenderKeyDistributionMessage { get; set; }
    }
}
