using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OAuch.Protocols.Tls {
    public class TlsSniffer {
        public TlsSniffer() : this(SniffOptions.Default) { }
        public TlsSniffer(SniffOptions options) {
            _defaultOptions = options;
        }

        public Task<SniffResult> Sniff(string url, SniffOptions? options = null) {
            if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
                return Sniff(uri, options);
            throw new NotSupportedException("Unable to parse the specified URL.");
        }
        public Task<SniffResult> Sniff(Uri url, SniffOptions? options = null) {
            if (url.Port == -1)
                throw new NotSupportedException("No port specified and no default port available.");
            return Sniff(url.Host, url.Port, options);
        }
        public async Task<SniffResult> Sniff(string host, int port, SniffOptions? options = null) {
            if (options == null)
                options = _defaultOptions;

            var hellos = new List<ClientHelloMessage>();
            if (options.SniffProtocols) {
                foreach (var prot in options.Protocols) {
                    hellos.Add(new ClientHelloMessage(host, new SslProtocols[] { prot }, options.CipherSuites));
                }
            } else {
                hellos.Add(new ClientHelloMessage(host, options.Protocols, options.CipherSuites));
            }

            var recordLayer = new RecordLayer(options.Protocols.Min());
            var protocolList = new List<SslProtocols>();
            var cipherList = new List<CipherSuite>();

            // start sniffing protocols
            await StartSniffing(hellos, host, port, recordLayer, protocolList, cipherList);

            if (options.SniffAlgorithms && protocolList.Count > 0) {
                hellos.Clear();
                // add TLS 1.3 ciphers (if the protocol is supported)
                if (protocolList.Contains(SslProtocols.Tls13)) {
                    foreach (var cs in options.CipherSuites.Where(c => c.IsTls13Cipher)) {
                        hellos.Add(new ClientHelloMessage(host, new SslProtocols[] { SslProtocols.Tls13 }, new CipherSuite[] { cs }));
                    }
                }
                // add non-TLS 1.3 ciphers (if a non-TLS1.3-protocol is supported)
                var oldProtocols = protocolList.Where(c => c != SslProtocols.Tls13).OrderByDescending(c => c);
                if (oldProtocols.Count() > 0) {
                    var prot = oldProtocols.First();
                    foreach (var cs in options.CipherSuites.Where(c => !c.IsTls13Cipher)) {
                        hellos.Add(new ClientHelloMessage(host, new SslProtocols[] { prot }, new CipherSuite[] { cs }));
                    }
                }
                // start sniffing algorithms
                await StartSniffing(hellos, host, port, recordLayer, protocolList, cipherList);
            }

            return new SniffResult(protocolList, cipherList);
        }
        private Task StartSniffing(List<ClientHelloMessage> hellos, string host, int port, RecordLayer recordLayer, List<SslProtocols> protocolList, List<CipherSuite> cipherList) {
            var cancellationSource = new CancellationTokenSource();
            var tasks = new Task[hellos.Count];
            for (int i = 0; i < tasks.Length; i++) {
                var hello = hellos[i];
                tasks[i] = Task.Run(() => Sniff(host, port, recordLayer, hello, protocolList, cipherList, cancellationSource.Token));
            }
            return Task.Run(() => {
                if (!Task.WaitAll(tasks, 30000)) {
                    // not all tasks completed
                    cancellationSource.Cancel();
                }
            });
        }

        private async Task Sniff(string hostname, int port, RecordLayer rl, ClientHelloMessage hello, List<SslProtocols> protocols, List<CipherSuite> ciphers, CancellationToken cancellationToken) {
            try {
                using (var client = new TcpClient()) {
                    await client.ConnectAsync(hostname, port);
                    var stream = client.GetStream();

                    hello.SessionId = new byte[0];
                    var helloBytes = rl.Wrap(hello);
                    await stream.WriteAsync(helloBytes, 0, helloBytes.Length, cancellationToken);

                    var buffer = new byte[1024];
                    var ms = new MemoryStream();

                    var status = DecodeState.NeedMoreData;
                    ServerHelloMessage? serverHello = null;
                    while (status == DecodeState.NeedMoreData) {
                        int read = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                        if (read == 0)
                            return; // need more data, but the server doesn't send anything

                        ms.Position = ms.Length;
                        ms.Write(buffer, 0, read);
                        ms.Position = 0;
                        status = rl.Unwrap(ms, ref serverHello);
                        if (status == DecodeState.InvalidMessage)
                            return;
                    }
                    if (serverHello != null && hello.AllowedProtocols.Contains(serverHello.Protocol)) {
                        lock (_syncRoot) {
                            if (!protocols.Contains(serverHello.Protocol))
                                protocols.Add(serverHello.Protocol);
                            if (!ciphers.Contains(serverHello.CipherSuite))
                                ciphers.Add(serverHello.CipherSuite);
                        }
                    }                    
                }               
            } catch {
                // nothing to do
            }
        }

        private SniffOptions _defaultOptions;
        private object _syncRoot = new object();
    }

    public enum DecodeState { 
        Success,
        NeedMoreData,
        InvalidMessage
    }

    internal class RecordLayer {
        public RecordLayer(SslProtocols minProtocol) {
            this.MinProtocol = minProtocol;
        }
        public SslProtocols MinProtocol { get; }
        public byte[] Wrap(ClientHelloMessage message) {
            var ms = new MemoryStream();
            // handshake record
            ms.WriteByte(0x16);
            // protocol (lowest supported)
            ms.WriteProtocol(MinProtocol);
            // length
            ms.WriteInt(message.Length, 2);
            // contents
            message.WriteBytes(ms);
            return ms.ToArray();
        }

        public DecodeState Unwrap(MemoryStream ms, ref ServerHelloMessage? result) {
            if (ms.ReadByte() != 0x16) // handshake record
                return DecodeState.InvalidMessage;
            if (ms.ReadByte() != 0x03) // protocol version major
                return DecodeState.InvalidMessage;
            var minor = ms.ReadByte();
            if (minor > 0x3) // protocol version minor, must be between 0..3
                return DecodeState.InvalidMessage;
            var length = ms.ReadInt(2);
            if (ms.Length >= 5 + length)
                return ServerHelloMessage.Decode(ms, length, ref result);
            return DecodeState.NeedMoreData;
        }
    }
    internal class ServerHelloMessage {
        public static DecodeState Decode(MemoryStream bytes, int messageLength, ref ServerHelloMessage? result) {
            if (bytes.ReadByte() != 0x02) // server hello
                return DecodeState.InvalidMessage;
            int length = bytes.ReadInt(3);
            if (length + 9 > bytes.Length)
                return DecodeState.InvalidMessage; // message is not complete

            var protocol = bytes.ReadProtocol();

            var serverRandom = new byte[32];
            bytes.Read(serverRandom, 0, serverRandom.Length);

            int sessionIdLength = bytes.ReadByte();
            var sessionId = new byte[sessionIdLength];
            bytes.Read(sessionId, 0, sessionId.Length);

            int cipherId = bytes.ReadInt(2);
            CipherSuite? cs = CipherSuite.All.FirstOrDefault(c => c.Id == cipherId);
            if (cs == null)
                cs = CipherSuite.UNKNOWN;

            bytes.Position++; //compression algorithm

            if (protocol == SslProtocols.Tls12 && messageLength > 1 + 3 + 2 + 32 + 1 + sessionIdLength + 2 + 1) {
                // there are extensions in the hello message
                int extensionsLength = bytes.ReadInt(2);
                int processed = 0;
                while(processed < extensionsLength) {
                    int size = 0;
                    var ext = TlsExtension.Create(bytes, ref size);
                    processed += size;

                    var sve = ext as SupportedVersionsExtension;
                    if (sve != null) { // TLS 1.3 is supported
                        protocol = sve.Protocols[0];
                        break;
                    }
                }
            }
            result = new ServerHelloMessage(protocol, serverRandom, sessionId, cs);
            return DecodeState.Success;
        }
        private ServerHelloMessage(SslProtocols prot, byte[] random, byte[] session, CipherSuite cipher) {
            this.Protocol = prot;
            this.ServerRandom = random;
            this.SessionId = session;
            this.CipherSuite = cipher;
        }
        public SslProtocols Protocol { get; }
        public byte[] ServerRandom { get; }
        public byte[] SessionId { get; }
        public CipherSuite CipherSuite { get; }
    }
    internal class ClientHelloMessage {
        public ClientHelloMessage(string host, IEnumerable<SslProtocols> protocols, IEnumerable<CipherSuite> availableCiphers) {
            var rnd = new Random();
            this.AllowedProtocols = protocols;
            this.MaxProtocol = protocols.Max();
            this.SupportedCipherSuites = availableCiphers;
            this.ClientRandom = new byte[32];
            rnd.NextBytes(this.ClientRandom);
            this.SessionId = new byte[32];
            rnd.NextBytes(this.SessionId);

            var extensions = new List<TlsExtension>();
            extensions.Add(new ServerNameExtension(host));
            extensions.Add(new SignatureAlgorithmsExtension());
            extensions.Add(new SupportedGroupsExtension());
            extensions.Add(new KeyShareExtension());

            if (this.MaxProtocol == SslProtocols.Tls13) {
                extensions.Add(new SupportedVersionsExtension(protocols));
            }
            this.Extensions = extensions;
        }

        public IEnumerable<CipherSuite> SupportedCipherSuites { get; }
        public SslProtocols MaxProtocol { get; }
        public IEnumerable<SslProtocols> AllowedProtocols { get; }
        public byte[] ClientRandom { get; }
        public byte[] SessionId { get; set; }
        public IEnumerable<TlsExtension> Extensions { get; }
        public int CipherSuitesLength => SupportedCipherSuites.Count() * 2;
        public int ExtensionsLength => Extensions.Sum(e => e.Length);
        public int Length => 
                1 /* message type */
                + 3 /* message length */
                + 2 /* client version */
                + ClientRandom.Length /* client random */
                + SessionId.Length + 1 /* session id vector */
                + CipherSuitesLength + 2 /* cipher suites vector */
                + 2 /* compression methods - only none */
                + ExtensionsLength + (Extensions.Any() ? 2 : 0) /* extensions vector */;

        public void WriteBytes(MemoryStream ms) {
            //handshake record
            ms.WriteByte(0x01); // client hello
            ms.WriteInt(Length - 4, 3);
            // version
            ms.WriteProtocol(MaxProtocol);
            // client random
            ms.Write(this.ClientRandom, 0, this.ClientRandom.Length);
            // session id
            ms.WriteInt(this.SessionId.Length, 1);
            ms.Write(this.SessionId, 0, this.SessionId.Length);
            // cipher suites
            ms.WriteInt(CipherSuitesLength, 2);
            foreach (var cs in this.SupportedCipherSuites) {
                ms.WriteInt(cs.Id, 2);
            }
            // compression methods
            ms.WriteByte(0x01);
            ms.WriteByte(0x00); // no compression
            // extensions length
            if (Extensions.Any()) {
                ms.WriteInt(ExtensionsLength, 2);
                foreach (var ext in Extensions) {
                    ext.WriteBytes(ms);
                }
            }
        }
    }
    internal abstract class TlsExtension {
        public abstract int Length { get; }
        public abstract void WriteBytes(MemoryStream ms);

        public static TlsExtension? Create(MemoryStream ms, ref int size) {
            long startPos = ms.Position;
            int id = ms.ReadInt(2);
            int length = ms.ReadInt(2);
            TlsExtension? ext = null;
            switch (id) {
                case SupportedVersionsExtension.ExtensionId:
                    ext = new SupportedVersionsExtension(ms, length);
                    break;
                case SupportedGroupsExtension.ExtensionId:
                    ext = new SupportedGroupsExtension(ms, length);
                    break;
                case KeyShareExtension.ExtensionId:
                    ext = new KeyShareExtension(ms, length);
                    break;
                case SignatureAlgorithmsExtension.ExtensionId:
                    ext = new SignatureAlgorithmsExtension(ms, length);
                    break;
                case ServerNameExtension.ExtensionId:
                    ext = new ServerNameExtension(ms, length);
                    break;
            }
            size = length + 4;
            if (size <= 0)
                throw new ArgumentException(); // weird stuff
            ms.Position = startPos + size;
            return ext;
        }
    }
    internal class SupportedVersionsExtension : TlsExtension {
        public SupportedVersionsExtension(SslProtocols protocol) {
            this.Protocols = new List<SslProtocols>() { protocol };
        }
        public SupportedVersionsExtension(IEnumerable<SslProtocols> protocols) {
            var p = new List<SslProtocols>();
            p.AddRange(protocols);
            this.Protocols = p;
        }
        public SupportedVersionsExtension(MemoryStream contents, int length) {
            // if we receive this extension from the server, the contents is not a vector, so we do not need to read that single byte anymore
            var p = new List<SslProtocols>();
            //for (int i = 0; i < length; i += 2) {
                p.Add(contents.ReadProtocol());
            //}
            this.Protocols = p;
        }
        public const int ExtensionId = 0x2b;
        public IReadOnlyList<SslProtocols> Protocols { get; }
        public override int Length => Protocols.Count * 2 + 5;
        public override void WriteBytes(MemoryStream ms) {
            ms.WriteInt(ExtensionId, 2);
            ms.WriteInt(Protocols.Count * 2 + 1, 2);
            ms.WriteInt(Protocols.Count * 2, 1);
            foreach (var p in Protocols) {
                ms.WriteProtocol(p, true);
            }
        }
    }
    internal class SupportedGroupsExtension : TlsExtension {
        public SupportedGroupsExtension(MemoryStream contents, int totalLength) {
            var p = new List<int>();
            int length = contents.ReadInt(2);
            for (int i = 0; i < length; i += 2) {
                p.Add(contents.ReadInt(2));
            }
            this.GroupIds = p;
        }
        public SupportedGroupsExtension() {
            this.GroupIds = new List<int>() { 
                0x0017, 0x0018, 0x0019, 0x001d, 0x001e, /* Elliptic Curve Groups (ECDHE) */
                0x0100, 0x0101, 0x0102, 0x0103, 0x0104 /* Finite Field Groups (DHE) */
            };
        }
        public const int ExtensionId = 0x0a;
        public IReadOnlyList<int> GroupIds;
        public override int Length => GroupIds.Count * 2 + 6;
        public override void WriteBytes(MemoryStream ms) {
            ms.WriteInt(ExtensionId, 2);
            ms.WriteInt(GroupIds.Count * 2 + 2, 2);
            ms.WriteInt(GroupIds.Count * 2, 2);
            foreach (var p in GroupIds) {
                ms.WriteInt(p, 2);
            }
        }
    }
    internal class KeyShareExtension : TlsExtension {
        public KeyShareExtension(MemoryStream contents, int length) {
            contents.Position += length; // we do not process key share messages
            this.Length = length + 4;
        }
        public KeyShareExtension() {
            this.Length = 6;
        }
        public const int ExtensionId = 0x33;
        public override int Length { get; }
        public override void WriteBytes(MemoryStream ms) {
            ms.WriteInt(ExtensionId, 2);
            ms.WriteInt(2, 2);
            ms.WriteInt(0, 2);
        }
    }
    internal class SignatureAlgorithmsExtension : TlsExtension {
        public SignatureAlgorithmsExtension(MemoryStream contents, int totalLength) {
            var p = new List<int>();
            int length = contents.ReadInt(2);
            for (int i = 0; i < length; i += 2) {
                p.Add(contents.ReadInt(2));
            }
            this.SignatureIds = p;
        }
        public SignatureAlgorithmsExtension() {
            this.SignatureIds = new List<int>() {
                0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603, 
                0x0804, 0x0805, 0x0806, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 
                0x0201, 0x0203
            };
        }
        public const int ExtensionId = 0x0d;
        public IReadOnlyList<int> SignatureIds;
        public override int Length => SignatureIds.Count * 2 + 6;
        public override void WriteBytes(MemoryStream ms) {
            ms.WriteInt(ExtensionId, 2);
            ms.WriteInt(SignatureIds.Count * 2 + 2, 2);
            ms.WriteInt(SignatureIds.Count * 2, 2);
            foreach (var p in SignatureIds) {
                ms.WriteInt(p, 2);
            }
        }
    }
    internal class ServerNameExtension : TlsExtension {
        public ServerNameExtension(MemoryStream contents, int totalLength) {
            if (totalLength < 5)
                return;
            int length = contents.ReadInt(2);
            int type = contents.ReadByte();
            int hostLength = contents.ReadInt(2);
            var buffer = new byte[hostLength];
            contents.Read(buffer, 0, buffer.Length);
            this.Hostname = Encoding.ASCII.GetString(buffer);
        }
        public ServerNameExtension(string host) {
            this.Hostname = host;
        }
        public const int ExtensionId = 0x0;
        public string? Hostname { get; }
        public override int Length => Hostname.Length + 9;
        public override void WriteBytes(MemoryStream ms) {
            var hostBytes = Encoding.ASCII.GetBytes(Hostname);
            ms.WriteInt(ExtensionId, 2);
            ms.WriteInt(hostBytes.Length + 5, 2);
            ms.WriteInt(hostBytes.Length + 3, 2);
            ms.WriteByte(0); // type 'hostname'
            ms.WriteInt(hostBytes.Length, 2);
            ms.Write(hostBytes, 0, hostBytes.Length);
        }
    }
   

}
