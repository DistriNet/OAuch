using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace OAuch.Compliance.Tests.Concurrency {
    public static class ConnectionPing {
        public static int Ping(IPAddress ip, int port) {
            try {
                using var client = new TcpClient();                
                var start = Stopwatch.GetTimestamp();
                client.Connect(ip, port);
                var stop = Stopwatch.GetTimestamp();
                var elapsed = Stopwatch.GetElapsedTime(start, stop);
                return (int)(elapsed.TotalMilliseconds / 2);
            } catch {
                return -1;
            }
        }
    }
}
