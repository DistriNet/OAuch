using System;
using System.IO;
using System.Security.Authentication;

namespace OAuch.Protocols.Tls {
    public static class ByteSerializer {
        public static void WriteInt(this MemoryStream ms, int value, int byteCount) {
            switch (byteCount) {
                case 1:
                    ms.WriteByte((byte)(value & 0xFF));
                    break;
                case 2:
                    ms.WriteByte((byte)((value >> 8) & 0xFF));
                    ms.WriteByte((byte)(value & 0xFF));
                    break;
                case 3:
                    ms.WriteByte((byte)((value >> 16) & 0xFF));
                    ms.WriteByte((byte)((value >> 8) & 0xFF));
                    ms.WriteByte((byte)(value & 0xFF));
                    break;
                case 4:
                    ms.WriteByte((byte)((value >> 24) & 0xFF));
                    ms.WriteByte((byte)((value >> 16) & 0xFF));
                    ms.WriteByte((byte)((value >> 8) & 0xFF));
                    ms.WriteByte((byte)(value & 0xFF));
                    break;
                default:
                    throw new ArgumentException("Value must be between 1 and 4", nameof(byteCount));
            }
        }
        public static int ReadInt(this MemoryStream ms, int byteCount) {
            int ret = 0;
            for (int i = 0; i < byteCount; i++) {
                ret <<= 8;
                ret |= ms.ReadByte();
            }
            return ret;
        }

        public static void WriteProtocol(this MemoryStream ms, SslProtocols protocol, bool isExtension = false) {
            ms.WriteByte(0x03);
            if (isExtension && protocol == SslProtocols.Tls13) {
                ms.WriteByte(0x04);
            } else {
                switch (protocol) {
                    case SslProtocols.Tls12:
                    case SslProtocols.Tls13:
                        ms.WriteByte(0x03);
                        break;
                    case SslProtocols.Tls11:
                        ms.WriteByte(0x02);
                        break;
                    case SslProtocols.Tls:
                        ms.WriteByte(0x01);
                        break;
                    case SslProtocols.Ssl3:
                        ms.WriteByte(0x00);
                        break;
                    default:
                        throw new NotSupportedException("Unsupported protocol version.");
                }
            }
        }
        public static SslProtocols ReadProtocol(this MemoryStream ms) {
            if (ms.ReadByte() != 0x03)
                throw new NotSupportedException();
            var minor = ms.ReadByte();
            return minor switch {
                0 => SslProtocols.Ssl3,
                1 => SslProtocols.Tls,
                2 => SslProtocols.Tls11,
                3 => SslProtocols.Tls12,
                4 => SslProtocols.Tls13,
                _ => throw new NotSupportedException(),
            };
        }
    }
}
