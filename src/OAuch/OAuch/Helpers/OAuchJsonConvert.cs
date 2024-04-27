using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using OAuch.Compliance.Tests;
using System;

namespace OAuch.Helpers {
    public static class OAuchJsonConvert {
        public static T? Deserialize<T>(string json) {
            return JsonConvert.DeserializeObject<T>(json, new JsonSerializerSettings {
                TypeNameHandling = TypeNameHandling.Auto,
                SerializationBinder = new ForgivingSerializationBinder() // add new ISerializationBuilder to catch serialization errors (because test cases are renamed or removed)
            });
        }

        public static string Serialize(object o, Formatting formatting = Formatting.None) {
            return JsonConvert.SerializeObject(o, formatting, new JsonSerializerSettings {
                TypeNameHandling = TypeNameHandling.Auto
            });
        }
    }
    public class ForgivingSerializationBinder : ISerializationBinder {
        private readonly DefaultSerializationBinder defaultBinder = new();

        void ISerializationBinder.BindToName(Type serializedType, out string? assemblyName, out string? typeName) {
            defaultBinder.BindToName(serializedType, out assemblyName, out typeName);
        }

        Type ISerializationBinder.BindToType(string? assemblyName, string typeName) {
            try {
                return defaultBinder.BindToType(assemblyName, typeName);
            } catch (JsonSerializationException) {
                if (typeName.StartsWith("OAuch.Compliance.Tests") && typeName.EndsWith("TestResult")) {
                    // test case got renamed or removed; simply replace it with a dummy test result
                    return typeof(DummyTestResult);
                }
                throw;
            }
        }
    }
}
