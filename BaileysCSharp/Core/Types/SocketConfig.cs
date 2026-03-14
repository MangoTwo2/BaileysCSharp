using Proto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using BaileysCSharp.Core.Events;
using BaileysCSharp.Core.Models.Sessions;
using BaileysCSharp.Core.NoSQL;
using BaileysCSharp.Core.Signal;
using BaileysCSharp.Core.Stores;
using BaileysCSharp.Core.Types;
using BaileysCSharp.Core.Logging;
using BaileysCSharp.Core.Utils;

namespace BaileysCSharp.Core.Models
{
    public class SocketConfig
    {
        public uint[] Version { get; set; }
        public string? SessionName { get; set; }
        public string[] Browser { get; set; }
        public SocketConfig()
        {
            Browser = Browsers.MacOS("Chrome");
            Version = [2, 3000, 1033846690];
            Logger = new DefaultLogger();
            Logger.Level = LogLevel.Trace;
            AppStateMacVerification = new AppStateMacVerification();
            ConnectTimeoutMs = 20000;
            KeepAliveIntervalMs = 30000;
            DefaultQueryTimeoutMs = 60000;
            MarkOnlineOnConnect = true;
            FireInitQueries = true;
        }

        public int ConnectTimeoutMs { get; set; }
        public int KeepAliveIntervalMs { get; set; }
        public int DefaultQueryTimeoutMs { get; set; }
        public int QrTimeout { get; set; }
        public bool MarkOnlineOnConnect { get; set; }
        public bool FireInitQueries { get; set; }
        public DefaultLogger Logger { get; set; }
        public bool Mobile => false;//For Now only multi device api
        public AuthenticationState Auth { get; set; }
        public bool SyncFullHistory { get; set; }

        public AppStateMacVerification AppStateMacVerification { get; set; }

        public bool ShouldSyncHistoryMessage()
        {
            return true;
        }

        public bool ShouldIgnoreJid(string jid = "")
        {
            return false;
        }

        private static string Root
        {
            get
            {
                var loc = typeof(BaseSocket).Assembly.Location;
                if (!string.IsNullOrEmpty(loc))
                    return Path.GetDirectoryName(loc)!;
                // Single-file publish: assembly location is empty, fall back to current directory
                return AppContext.BaseDirectory;
            }
        }

        /// <summary>
        /// Override the cache/auth directory. When set, CacheRoot returns this directly
        /// instead of computing from assembly location + SessionName.
        /// </summary>
        public string? CacheRootOverride { get; set; }
        public SignalRepository MakeSignalRepository(EventEmitter ev)
        {
            return new SignalRepository(Auth, Logger);
        }

        internal MemoryStore MakeStore(EventEmitter ev, DefaultLogger logger)
        {
            return new MemoryStore(CacheRoot, ev, logger);
        }

        internal Message PatchMessageBeforeSending(Message message, string[] jids)
        {
            return message;
        }

        public string CacheRoot
        {
            get
            {
                var path = CacheRootOverride ?? Path.Combine(Root, SessionName);
                if (!Directory.Exists(path))
                {
                    Directory.CreateDirectory(path);
                }
                return path;
            }
        }
    }
}
