using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace OAuch.Protocols {
    public class SafeStringConverter : JsonConverter {
        public SafeStringConverter(bool splitOnSpace = true) {
            this.SplitOnSpace = splitOnSpace;
        }
        public bool SplitOnSpace { get; }
        public override bool CanConvert(Type objectType) {
            return /*(objectType == typeof(string)) ||*/ (objectType == typeof(List<string>));
        }

        public override object? ReadJson(JsonReader reader, Type objectType, object? existingValue, JsonSerializer serializer) {
            if (reader.TokenType == JsonToken.StartArray) {
                var l = new List<string>();
                reader.Read();
                while (reader.TokenType != JsonToken.EndArray) {
                    if (reader.Value is string s)
                        l.Add(s);

                    reader.Read();
                }
                return l;
            } else {
                var ret = new List<string>();
                if (reader.Value is string s) {
                    if (SplitOnSpace) {
                        var sp = s.Split(' ');
                        foreach (var spe in sp) {
                            if (!string.IsNullOrEmpty(spe))
                                ret.Add(spe);
                        }
                    } else {
                        ret.Add(s);
                    }
                }
                return ret;
            }
        }
        public override void WriteJson(JsonWriter writer, object? value, JsonSerializer serializer) {
            
        }
    }
}
