using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using Certify.Models.Config;
using Certify.Models.Plugins;
using Certify.Providers.DeploymentTasks;

namespace Plugin.DeploymentTasks
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

    public class Plugin : IDeploymentTaskProviderPlugin
    {

        
        public IDeploymentTaskProvider GetProvider(string id)
        {

            id = id?.ToLower();

            var baseAssembly = typeof(Plugin).Assembly;

            // we filter the defined classes according to the interfaces they implement
            var typeList = baseAssembly.GetTypes().Where(type => type.GetInterfaces().Any(inter => inter == typeof(IDeploymentTaskProvider))).ToList();
            
            foreach(var t in typeList)
            {
                DeploymentProviderDefinition def = (DeploymentProviderDefinition)t.GetProperty("Definition").GetValue(null);
                if (def.Id.ToLower() == id)
                {
                    return (IDeploymentTaskProvider)Activator.CreateInstance(t);
                }
            }
  
            throw new ArgumentException("Deploy Task Type Unknown:" + (id ?? "<none>"));
        }

        public List<DeploymentProviderDefinition> GetProviders()
        {
            var list = new List<DeploymentProviderDefinition>();

            var baseAssembly = typeof(Plugin).Assembly;

            // we filter the defined classes according to the interfaces they implement
            var typeList = baseAssembly.GetTypes().Where(type => type.GetInterfaces().Any(inter => inter == typeof(IDeploymentTaskProvider))).ToList();

            foreach (var t in typeList)
            {
                var def = (DeploymentProviderDefinition)t.GetProperty("Definition").GetValue(null);
                list.Add(def);  
            }

            return list;
        }
    }
}
