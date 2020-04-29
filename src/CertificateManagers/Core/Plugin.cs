using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using Certify.Models.Config;
using Certify.Models.Plugins;
using Certify.Providers.CertificateManagers;
using Certify.Providers.DeploymentTasks;

namespace Plugin.CertificateManagers
{
    public static class TypeLoaderExtensions
    {
        // https://stackoverflow.com/questions/26733/getting-all-types-that-implement-an-interface
        public static IEnumerable<Type> GetLoadableTypes(this Assembly assembly)
        {
            if (assembly == null)
            {
                throw new ArgumentNullException("assembly");
            }

            try
            {
                return assembly.GetTypes();
            }
            catch (ReflectionTypeLoadException e)
            {
                return e.Types.Where(t => t != null);
            }
        }
    }

    public class Plugin : ICertificateManagerProviderPlugin
    {

        public ICertificateManager GetProvider(string id)
        {

            id = id?.ToLower();

            var baseAssembly = typeof(Plugin).Assembly;

            // we filter the defined classes according to the interfaces they implement
            var typeList = baseAssembly.GetTypes().Where(type => type.GetInterfaces().Any(inter => inter == typeof(ICertificateManager))).ToList();

            foreach (var t in typeList)
            {
                ProviderDefinition def = (ProviderDefinition)t.GetProperty("Definition").GetValue(null);
                if (def.Id.ToLower() == id)
                {
                    return (ICertificateManager)Activator.CreateInstance(t);
                }
            }

            throw new ArgumentException("Type Unknown:" + (id ?? "<none>"));
        }

        public List<ProviderDefinition> GetProviders()
        {
            var list = new List<ProviderDefinition>();

            var baseAssembly = typeof(Plugin).Assembly;

            var typeList = baseAssembly.GetTypes().Where(type => type.GetInterfaces().Any(inter => inter == typeof(ICertificateManager))).ToList();

            foreach (var t in typeList)
            {
                try
                {
                    var def = (ProviderDefinition)t.GetProperty("Definition").GetValue(null);
                    list.Add(def);
                }
                catch (Exception exp)
                {
                    System.Diagnostics.Debug.WriteLine($"Failed to load provider Definition: {t.FullName}");
                }
            }

            return list;
        }
    }
}
