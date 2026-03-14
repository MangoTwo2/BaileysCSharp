using Proto;
using BaileysCSharp.Core.Helper;
using BaileysCSharp.Core.Models;
using static BaileysCSharp.Core.Utils.JidUtils;
using BaileysCSharp.Core.WABinary;
using System.Text;
using BaileysCSharp.Core.Extensions;

namespace BaileysCSharp.Core.Signal
{

    public class MessageDecryptor
    {
        public MessageDecryptor(SignalRepository repository)
        {
            Repository = repository;
        }

        public BinaryNode Stanza { get; set; }
        public WebMessageInfo Msg { get; set; }
        public string Category { get; set; }
        public string Author { get; set; }
        public string Sender { get; set; }
        public SignalRepository Repository { get; }

        /// <summary>
        /// Extract addressing context from stanza attributes.
        /// Ported from Baileys JS decode-wa-message.ts extractAddressingContext.
        ///
        /// When addressing_mode is "lid", the sender is a LID and the alt is the PN.
        /// When addressing_mode is "pn", the sender is a PN and the alt is the LID.
        /// </summary>
        private (string addressingMode, string? senderAlt, string? recipientAlt) ExtractAddressingContext()
        {
            var sender = Stanza.getattr("participant") ?? Stanza.getattr("from");
            var addressingMode = Stanza.getattr("addressing_mode")
                ?? (sender?.EndsWith("lid") == true ? "lid" : "pn");

            string? senderAlt = null;
            string? recipientAlt = null;

            if (addressingMode == "lid")
            {
                // Message is LID-addressed: sender is LID, extract corresponding PN
                senderAlt = Stanza.getattr("participant_pn")
                    ?? Stanza.getattr("sender_pn")
                    ?? Stanza.getattr("peer_recipient_pn");
                recipientAlt = Stanza.getattr("recipient_pn");
            }
            else
            {
                // Message is PN-addressed: sender is PN, extract corresponding LID
                senderAlt = Stanza.getattr("participant_lid")
                    ?? Stanza.getattr("sender_lid")
                    ?? Stanza.getattr("peer_recipient_lid");
                recipientAlt = Stanza.getattr("recipient_lid");
            }

            return (addressingMode, senderAlt, recipientAlt);
        }

        /// <summary>
        /// Store LID↔PN mapping from envelope attributes if available.
        /// Ported from Baileys JS decode-wa-message.ts storeMappingFromEnvelope.
        /// </summary>
        private void StoreMappingFromEnvelope(string sender, string decryptionJid)
        {
            var (_, senderAlt, _) = ExtractAddressingContext();

            if (!string.IsNullOrEmpty(senderAlt) && IsLidUser(senderAlt) && IsPnUser(sender) && decryptionJid == sender)
            {
                try
                {
                    Repository.LIDMapping.StoreLIDPNMappings(new[]
                    {
                        new LIDMapping { LID = senderAlt, PN = sender }
                    });
                    Repository.MigrateSession(sender, senderAlt);
                }
                catch { }
            }
        }

        public void Decrypt()
        {
            int decryptables = 0;
            try
            {
                if (Stanza.content is BinaryNode[] nodes)
                {
                    foreach (var node in nodes)
                    {
                        if (node.tag == "verified_name" && node.content is byte[] bytes)
                        {
                            var cert = VerifiedNameCertificate.Parser.ParseFrom(bytes);
                            var details = VerifiedNameCertificate.Types.Details.Parser.ParseFrom(cert.Details);
                            Msg.VerifiedBizName = details.VerifiedName;
                        }

                        if (node.tag != "enc" && node.tag != "plaintext")
                            continue;

                        if (node.content is byte[] buffer)
                        {
                            decryptables += 1;
                            byte[] msgBuffer = default;
                            var e2eType = node.getattr("type") ?? node.tag ?? "none";

                            // Get the JID to use for decryption, resolving PN→LID if mapped
                            // Ported from Baileys JS getDecryptionJid
                            var decryptionJid = Repository.GetDecryptionJid(Author);

                            switch (e2eType)
                            {
                                case "skmsg":
                                    msgBuffer = Repository.DecryptGroupMessage(Sender, Author, buffer);
                                    break;
                                case "pkmsg":
                                case "msg":
                                    // Store LID mapping from envelope attributes before decryption
                                    if (node.tag != "plaintext")
                                    {
                                        StoreMappingFromEnvelope(Author, decryptionJid);
                                    }

                                    msgBuffer = Repository.DecryptMessage(decryptionJid, e2eType, buffer);
                                    break;
                                default:
                                case "plaintext":
                                    msgBuffer = buffer;
                                    break;
                            }

                            var msg = Message.Parser.ParseFrom(node.tag == "plaintext" ? msgBuffer : msgBuffer.UnpadRandomMax16());
                            msg = msg.DeviceSentMessage?.Message ?? msg;
                            if (msg.SenderKeyDistributionMessage != null)
                            {
                                Repository.ProcessSenderKeyDistributionMessage(Author, msg.SenderKeyDistributionMessage);
                            }
                            Msg.MessageTimestamp = Stanza.getattr("t").ToUInt64();
                            Msg.Message = msg;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Msg.MessageStubType = WebMessageInfo.Types.StubType.Ciphertext;
                Msg.MessageStubParameters.Add($"{ex.GetType().Name} - {ex.Message}");

            }
            if (decryptables == 0)
            {
                Msg.MessageStubType = WebMessageInfo.Types.StubType.Ciphertext;
                Msg.MessageStubParameters.Add("Message absent from node");
            }
        }
    }
}
