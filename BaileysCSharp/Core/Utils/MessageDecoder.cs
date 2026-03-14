using Org.BouncyCastle.Cms;
using Proto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using BaileysCSharp.Core.Models;
using BaileysCSharp.Core.Models.Sessions;
using BaileysCSharp.Core.Signal;
using BaileysCSharp.Exceptions;
using static BaileysCSharp.Core.Utils.JidUtils;
using BaileysCSharp.Core.WABinary;
using BaileysCSharp.Core.Logging;

namespace BaileysCSharp.Core
{

    public class MessageDecoder
    {
        /// <summary>
        /// Extract addressing context from stanza attributes.
        /// Ported from Baileys JS decode-wa-message.ts extractAddressingContext.
        /// </summary>
        public static (string addressingMode, string? senderAlt, string? recipientAlt) ExtractAddressingContext(BinaryNode stanza)
        {
            var sender = stanza.getattr("participant") ?? stanza.getattr("from");
            var addressingMode = stanza.getattr("addressing_mode")
                ?? (sender?.EndsWith("lid") == true ? "lid" : "pn");

            string? senderAlt = null;
            string? recipientAlt = null;

            if (addressingMode == "lid")
            {
                senderAlt = stanza.getattr("participant_pn")
                    ?? stanza.getattr("sender_pn")
                    ?? stanza.getattr("peer_recipient_pn");
                recipientAlt = stanza.getattr("recipient_pn");
            }
            else
            {
                senderAlt = stanza.getattr("participant_lid")
                    ?? stanza.getattr("sender_lid")
                    ?? stanza.getattr("peer_recipient_lid");
                recipientAlt = stanza.getattr("recipient_lid");
            }

            return (addressingMode, senderAlt, recipientAlt);
        }

        public static MessageDecryptor DecryptMessageNode(BinaryNode stanza, string meId, string meLid, SignalRepository repository, DefaultLogger logger)
        {

            string chatId = "";
            string msgType = "";
            string author = "";

            var msgId = stanza.attrs["id"];
            var from = stanza.attrs["from"];
            var participant = stanza.getattr("participant");
            var recipient = stanza.getattr("recipient");

            // Extract addressing context for LID↔PN resolution
            var (addressingMode, senderAlt, recipientAlt) = ExtractAddressingContext(stanza);

            bool fromMe = false;

            // Unified JID check: handle both PN (@s.whatsapp.net) and LID (@lid) users
            // Also handle hosted variants (@hosted, @hosted.lid)
            // Ported from Baileys JS decode-wa-message.ts decodeMessageNode
            if (IsJidUser(from) || IsLidUser(from) || IsHostedPnUser(from) || IsHostedLidUser(from))
            {
                if (!string.IsNullOrWhiteSpace(recipient))
                {
                    if (!AreJidsSameUser(from, meId) && !AreJidsSameUser(from, meLid))
                    {
                        throw new Boom("receipient present, but msg not from me", Events.DisconnectReason.MissMatch);
                    }

                    if (AreJidsSameUser(from, meId) || AreJidsSameUser(from, meLid))
                    {
                        fromMe = true;
                    }

                    chatId = recipient;
                }
                else
                {
                    chatId = from;
                }
                msgType = "chat";
                author = from;
            }
            else if (IsJidGroup(from))
            {
                if (participant == null)
                {
                    throw new Boom("No participant in group message", Events.DisconnectReason.MissMatch);
                }
                else
                {
                    if (AreJidsSameUser(participant, meId) || AreJidsSameUser(participant, meLid))
                    {
                        fromMe = true;
                    }

                    msgType = "group";
                    author = participant;
                    chatId = from;
                }
            }
            else if (IsBroadcast(from))
            {
                if (participant == null)
                {
                    throw new Boom("No participant in group message", Events.DisconnectReason.MissMatch);
                }
                else
                {
                    var isParticipantMe = AreJidsSameUser(meId, participant);

                    if (IsJidStatusBroadcast(from))
                    {
                        msgType = isParticipantMe ? "direct_peer_status" : "other_status";
                    }
                    else
                    {
                        msgType = isParticipantMe ? "peer_broadcast" : "other_broadcast";
                    }

                    fromMe = isParticipantMe;
                    chatId = from;
                    author = participant;
                }
            }
            else if (IsJidNewsletter(from))
            {
                chatId = from;
                author = from;
                if (AreJidsSameUser(from, meId) || AreJidsSameUser(from, meLid))
                {
                    fromMe = true;
                }
            }

            var notify = stanza.getattr("notify");

            // For non-JID-type messages where fromMe wasn't set above,
            // compute it based on LID or PN comparison
            if (!fromMe && msgType == "chat")
            {
                if (IsLidUser(from))
                {
                    fromMe = AreJidsSameUser(meLid, !string.IsNullOrWhiteSpace(participant) ? participant : from);
                }
                else
                {
                    fromMe = AreJidsSameUser(meId, !string.IsNullOrWhiteSpace(participant) ? participant : from);
                }
            }

            var fullMessage = new WebMessageInfo()
            {
                Key = new MessageKey()
                {
                    RemoteJid = chatId,
                    Id = msgId,
                    FromMe = fromMe,
                    Participant = participant ?? "",
                },
                PushName = notify ?? "",
                Broadcast = IsBroadcast(from)

            };

            if (fromMe)
            {
                fullMessage.Status = WebMessageInfo.Types.Status.ServerAck;
            }


            return new MessageDecryptor(repository)
            {
                Stanza = stanza,
                Msg = fullMessage,
                Author = author,
                Category = stanza.getattr("category") ?? "",
                Sender = msgType == "chat" ? author : chatId
            };
        }

    }
}
