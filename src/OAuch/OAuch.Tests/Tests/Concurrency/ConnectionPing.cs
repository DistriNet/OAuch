using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.Concurrency {
    public class ConnectionPing {
        public int Ping(IPAddress ip, int port) {
            try {
                using (var client = new TcpClient()) {
                    var start = PreciseTime.Now;
                    client.Connect(ip, port);
                    var stop = PreciseTime.Now;
                    return (int)stop.Subtract(start).TotalMilliseconds / 2;
                }
            } catch (Exception e) {
                return -1;
            }
        }
    }
}
