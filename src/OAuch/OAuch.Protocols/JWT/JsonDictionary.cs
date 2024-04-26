using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json.Linq;

namespace OAuch.Protocols.JWT {
    public class JsonDictionary : Dictionary<string, object?> {
        public T? Read<T>(string key) {
            if (!this.ContainsKey(key))
                return default;
            var value = this[key];
            if (value == null)
                return default;
            if (value is JToken jvalue) {
                return jvalue.ToObject<T>();
            } else {
                return (T)value;
            }
        }
    }
}
