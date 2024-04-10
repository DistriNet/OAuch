using AngleSharp.Dom;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using OAuch.Compliance.Tests;
using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.Helpers {
    public static class OAuchJsonConvert {
        // TODO: add new ISerializationBuilder to catch serialization errors (because test cases are renamed or removed)
        // https://stackoverflow.com/questions/60972554/getting-error-resolving-type-specified-in-json
        public static T Deserialize<T>(string json) {
            return JsonConvert.DeserializeObject<T>(json, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Auto,
                SerializationBinder = new ForgivingSerializationBinder()
            });
        }

        public static string Serialize(object o, Formatting formatting = Formatting.None) {
            return JsonConvert.SerializeObject(o, formatting, new JsonSerializerSettings { 
                 TypeNameHandling = TypeNameHandling.Auto
            });
        }
    }
    public class ForgivingSerializationBinder : ISerializationBinder {
        DefaultSerializationBinder defaultBinder = new DefaultSerializationBinder();

        void ISerializationBinder.BindToName(Type serializedType, out string? assemblyName, out string? typeName) {
            //if (serializedType == typeof(CharacterData)) {
            //    assemblyName = "Global";
            //    typeName = serializedType.Name;
            //} else {
                defaultBinder.BindToName(serializedType, out assemblyName, out typeName);
            //}
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
