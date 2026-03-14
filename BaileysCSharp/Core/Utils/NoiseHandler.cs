using BaileysCSharp.Core.Helper;
using BaileysCSharp.Core.Logging;
using BaileysCSharp.Core.WABinary;
using BaileysCSharp.LibSignal;
using Google.Protobuf;
using Proto;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace BaileysCSharp.Core.Utils
{
    /// <summary>
    /// Separate read/write encryption state used after the Noise handshake completes.
    /// Port of Baileys JS TransportState class - resolves race condition where
    /// decodeFrame could run before finishInit completed, corrupting shared counters.
    /// </summary>
    internal sealed class TransportState
    {
        private uint _readCounter;
        private uint _writeCounter;
        private readonly byte[] _encKey;
        private readonly byte[] _decKey;
        private readonly byte[] _iv = new byte[12];
        // Lock to prevent concurrent encrypt/decrypt from corrupting counters
        private readonly object _lock = new();

        public TransportState(byte[] encKey, byte[] decKey)
        {
            _encKey = encKey;
            _decKey = decKey;
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            lock (_lock)
            {
                SetIV(_writeCounter++);
                return CryptoUtils.EncryptAESGCM(plaintext, _encKey, _iv, []);
            }
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            lock (_lock)
            {
                SetIV(_readCounter++);
                return CryptoUtils.DecryptAESGCM(ciphertext, _decKey, _iv, []);
            }
        }

        private void SetIV(uint counter)
        {
            _iv[8] = (byte)((counter >> 24) & 0xff);
            _iv[9] = (byte)((counter >> 16) & 0xff);
            _iv[10] = (byte)((counter >> 8) & 0xff);
            _iv[11] = (byte)(counter & 0xff);
        }
    }

    public class NoiseHandler : IDisposable
    {
        public void Dispose()
        {
            OnFrame = null;
        }

        public event EventHandler<BinaryNode> OnFrame;

        public NoiseHandler(KeyPair ephemeralKeyPair, DefaultLogger logger)
        {
            EphemeralKeyPair = ephemeralKeyPair;
            Logger = logger;
            Initialize();
        }

        public byte[] InBytes = new byte[0];
        public byte[] Hash { get; set; }
        public byte[] EncKey { get; set; }
        public byte[] DecKey { get; set; }
        public byte[] Salt { get; set; }

        uint counter;
        public bool SetIntro { get; set; }
        bool IsMobile { get; set; }
        public KeyPair EphemeralKeyPair { get; }
        public DefaultLogger Logger { get; }

        // Transport state - non-null after handshake completes (replaces IsFinished)
        private TransportState _transport;
        // Guard against frames arriving while finishInit is computing HKDF
        private volatile bool _isWaitingForTransport;
        private Action<BinaryNode> _pendingOnFrame;

        /// <summary>
        /// Whether the Noise handshake has completed and transport encryption is active.
        /// </summary>
        public bool IsFinished => _transport != null;

        private void Initialize()
        {
            byte[] data = Encoding.UTF8.GetBytes(Constants.NoiseMode);

            Hash = data.Length == 32 ? data : CryptoUtils.Sha256(data);
            Salt = Hash;
            EncKey = Hash;
            DecKey = Hash;
            counter = 0;
            _transport = null;
            _isWaitingForTransport = false;
            _pendingOnFrame = null;

            Authenticate(Constants.NOISE_WA_HEADER);
            Authenticate(EphemeralKeyPair.Public);
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            // After handshake, delegate to TransportState with separate counters
            if (_transport != null)
            {
                return _transport.Encrypt(plaintext);
            }

            // During handshake, use shared counter
            var result = CryptoUtils.EncryptAESGCM(plaintext, EncKey, GenerateIV(counter++), Hash);
            Authenticate(result);
            return result;
        }

        private void Authenticate(ByteString auth)
        {
            Authenticate(auth.ToByteArray());
        }

        private void Authenticate(byte[] buffer)
        {
            if (_transport == null)
            {
                Hash = CryptoUtils.Sha256(Hash.Concat(buffer));
            }
        }

        private byte[] Decrypt(ByteString ciphertext)
        {
            return Decrypt(ciphertext.ToByteArray());
        }

        private byte[] Decrypt(byte[] ciphertext)
        {
            // After handshake, delegate to TransportState
            if (_transport != null)
            {
                return _transport.Decrypt(ciphertext);
            }

            // During handshake, use shared counter
            var result = CryptoUtils.DecryptAESGCM(ciphertext, DecKey, GenerateIV(counter++), Hash);
            Authenticate(ciphertext);
            return result;
        }

        private void MixIntoKey(byte[] bytes)
        {
            var writeRead = LocalHKDF(bytes);
            Salt = writeRead.write;
            EncKey = writeRead.read;
            DecKey = writeRead.read;
            counter = 0;
        }

        public void FinishInit()
        {
            _isWaitingForTransport = true;
            var writeRead = LocalHKDF(new byte[0]);
            _transport = new TransportState(writeRead.write, writeRead.read);
            _isWaitingForTransport = false;

            Logger.Trace("Noise handler transitioned to Transport state");

            // Flush any frames that arrived while we were computing HKDF
            if (_pendingOnFrame != null)
            {
                Logger.Trace($"Flushing buffered frames after transport ready ({InBytes.Length} bytes)");
                ProcessData(_pendingOnFrame);
                _pendingOnFrame = null;
            }
        }

        public byte[] EncodeFrame(byte[] data)
        {
            if (_transport != null)
            {
                data = _transport.Encrypt(data);
            }

            var introSize = SetIntro ? 0 : Constants.NOISE_WA_HEADER.Length;
            byte[] buffer = new byte[introSize + 3 + data.Length];
            if (!SetIntro)
            {
                Constants.NOISE_WA_HEADER.CopyTo(buffer, 0);
                SetIntro = true;
            }

            // Write 3-byte big-endian length
            buffer[introSize] = (byte)((data.Length >> 16) & 0xff);
            buffer[introSize + 1] = (byte)((data.Length >> 8) & 0xff);
            buffer[introSize + 2] = (byte)(data.Length & 0xff);

            data.CopyTo(buffer, introSize + 3);

            return buffer;
        }

        public byte[] ProcessHandShake(HandshakeMessage result, KeyPair noiseKey)
        {
            Authenticate(result.ServerHello.Ephemeral);
            MixIntoKey(CryptoUtils.SharedKey(EphemeralKeyPair.Private, result.ServerHello.Ephemeral));

            var decStaticContent = Decrypt(result.ServerHello.Static);
            MixIntoKey(CryptoUtils.SharedKey(EphemeralKeyPair.Private, decStaticContent));

            var certDecoded = Decrypt(result.ServerHello.Payload);

            if (IsMobile)
            {
                // Mobile path not implemented
            }
            else
            {
                var certChain = CertChain.Parser.ParseFrom(certDecoded);

                // Validate leaf certificate (ported from Baileys JS "Verify leaf signature" commit)
                if (certChain.Leaf?.Details == null || certChain.Leaf?.Signature == null)
                {
                    throw new Exception("invalid noise leaf certificate");
                }

                if (certChain.Intermediate?.Details == null || certChain.Intermediate?.Signature == null)
                {
                    throw new Exception("invalid noise intermediate certificate");
                }

                var intermediateDetails = CertChain.Types.NoiseCertificate.Types.Details.Parser.ParseFrom(certChain.Intermediate.Details);

                // Verify leaf signature using intermediate key
                var leafVerified = CryptoUtils.Verify(
                    intermediateDetails.Key.ToByteArray(),
                    certChain.Leaf.Details.ToByteArray(),
                    certChain.Leaf.Signature.ToByteArray());

                // Verify intermediate signature using WA root public key
                var intermediateVerified = CryptoUtils.Verify(
                    Constants.WA_CERT_PUBLIC_KEY,
                    certChain.Intermediate.Details.ToByteArray(),
                    certChain.Intermediate.Signature.ToByteArray());

                if (!leafVerified)
                {
                    throw new Exception("noise certificate signature invalid");
                }

                if (!intermediateVerified)
                {
                    throw new Exception("noise intermediate certificate signature invalid");
                }

                if (intermediateDetails.IssuerSerial != Constants.WA_CERT_DETAILS_SERIAL)
                {
                    throw new Exception("certification match failed");
                }
            }

            var keyEnc = Encrypt(noiseKey.Public);
            MixIntoKey(CryptoUtils.SharedKey(noiseKey.Private.ToByteString(), result.ServerHello.Ephemeral));

            return keyEnc;
        }

        private byte[] GenerateIV(uint counter)
        {
            byte[] iv = new byte[12];
            iv[8] = (byte)((counter >> 24) & 0xff);
            iv[9] = (byte)((counter >> 16) & 0xff);
            iv[10] = (byte)((counter >> 8) & 0xff);
            iv[11] = (byte)(counter & 0xff);
            return iv;
        }

        public void DecodeFrameNew(byte[] newData, Action<BinaryNode> action)
        {
            var frame = newData.ToArray();

            var message = new BinaryNode()
            {
                tag = "handshake",
                attrs = new Dictionary<string, string>(),
                content = frame,
            };

            if (_transport != null)
            {
                try
                {
                    var decrypted = _transport.Decrypt(message.ToByteArray());
                    message = BufferReader.DecodeDecompressedBinaryNode(decrypted);
                }
                catch (AuthenticationTagMismatchException)
                {
                    return;
                }
            }

            if (message.attrs.TryGetValue("id", out var id))
            {
                Logger.Trace(new { msg = id }, "recv frame");
            }
            else
            {
                Logger.Trace("recv frame");
            }

            action(message);
        }

        public void DecodeFrame(byte[] newData, Action<BinaryNode> action)
        {
            // If we're waiting for FinishInit to complete, buffer the data
            if (_isWaitingForTransport)
            {
                InBytes = InBytes.Concat(newData).ToArray();
                _pendingOnFrame = action;
                return;
            }

            if (InBytes.Length == 0)
            {
                InBytes = newData.ToArray();
            }
            else
            {
                InBytes = InBytes.Concat(newData).ToArray();
            }

            Logger.Trace($"recv {newData.Length} bytes, total recv {InBytes.Length} bytes");

            ProcessData(action);
        }

        /// <summary>
        /// Extract and process complete frames from the internal buffer.
        /// Ported from Baileys JS processData function.
        /// </summary>
        private void ProcessData(Action<BinaryNode> action)
        {
            while (true)
            {
                if (InBytes.Length < 3) return;

                var size = (InBytes[0] << 16) | (InBytes[1] << 8) | InBytes[2];

                if (InBytes.Length < size + 3) return;

                var frame = InBytes.Skip(3).Take(size).ToArray();
                InBytes = InBytes.Skip(3 + size).ToArray();

                if (_transport != null)
                {
                    try
                    {
                        var decrypted = _transport.Decrypt(frame);
                        var message = BufferReader.DecodeDecompressedBinaryNode(decrypted);

                        if (Logger.Level == LogLevel.Trace)
                        {
                            Logger.Trace(new { msg = message?.attrs?.GetValueOrDefault("id") }, "recv frame");
                        }

                        action(message);
                    }
                    catch (AuthenticationTagMismatchException)
                    {
                        InBytes = [];
                        return;
                    }
                }
                else
                {
                    var message = new BinaryNode()
                    {
                        tag = "handshake",
                        attrs = new Dictionary<string, string>(),
                        content = frame,
                    };

                    if (message.attrs.TryGetValue("id", out var id))
                    {
                        Logger.Trace(new { msg = id }, "recv frame");
                    }
                    else
                    {
                        Logger.Trace("recv frame");
                    }

                    action(message);
                }
            }
        }

        public (byte[] write, byte[] read) LocalHKDF(byte[] bytes)
        {
            var hkdf = CryptoUtils.HKDF(bytes, 64, Salt, Encoding.UTF8.GetBytes(""));
            return (hkdf.Take(32).ToArray(), hkdf.Skip(32).ToArray());
        }
    }
}
