using System;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Plugin.CertificateManagers;

namespace Plugin.Tests
{
    [TestClass]
    public class CertificateManagerTests
    {
        [TestMethod]
        public async Task WinAcme()
        {
            var manager = new WinAcme();
            var isPresent = await manager.IsPresent();

            Assert.IsTrue(isPresent, "win-acme config should be present");

            var certs = await manager.GetManagedCertificates();

            Assert.IsTrue(certs.Count > 0, "win-acme renewals should be present");


        }
    }
}
