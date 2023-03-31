using System;
using System.Collections.Generic;
using System.Text;
using OAuch.Shared;

namespace OAuch.Protocols.Http {
    public class HttpMethods : Enumeration {
        public static HttpMethods Get = new HttpMethods(1, "GET");
        public static HttpMethods Post = new HttpMethods(2, "POST");

        private HttpMethods(int id, string name) : base(id, name) { }
    }
}
