using System;

namespace Certify.Plugin.CertificateManagers.Utils
{
    internal class JsonUtils
    {

        public static string Serialize<T>(T obj)
        {
            return System.Text.Json.JsonSerializer.Serialize(obj);
        }

        public static T Deserialize<T>(string json)
        {
            return System.Text.Json.JsonSerializer.Deserialize<T>(json) ?? throw new InvalidOperationException("Deserialization failed");
        }
    }
}
