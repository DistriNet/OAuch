namespace OAuch.Shared.Logging {
    //public class LoggedItemJsonConverter : JsonConverter {
    //    public override bool CanConvert(Type objectType) {
    //        return (objectType == typeof(LoggedItem));
    //    }

    //    public override object? ReadJson(JsonReader reader, Type objectType, object? existingValue, JsonSerializer serializer) {
    //        var jo = JObject.Load(reader);
    //        var className = jo["Type"]?.Value<string>();
    //        if (className != null && className.StartsWith("OAuch.Shared.Logging.")) {
    //            var type = Type.GetType(className);
    //            if (type != null)
    //                return jo.ToObject(type, serializer);
    //        }
    //        return null;
    //    }

    //    public override bool CanWrite {
    //        get { return false; }
    //    }

    //    public override void WriteJson(JsonWriter writer, object? value, JsonSerializer serializer) {
    //        throw new NotImplementedException();
    //    }
    //}
}
