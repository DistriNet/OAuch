using System.Net;
using System.Net.Sockets;

namespace OAuch.Compliance.Tests.Concurrency {
    public static class ConnectionPing {
        public static int Ping(IPAddress ip, int port) {
            try {
                using var client = new TcpClient();
                var start = PreciseTime.Now;
                client.Connect(ip, port);
                var stop = PreciseTime.Now;
                return (int)stop.Subtract(start).TotalMilliseconds / 2;
            } catch {
                return -1;
            }
        }
    }
}
