using Microsoft.VisualStudio.TestTools.UnitTesting;
using Plugin.CertificateManagers;
using System.Threading.Tasks;

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

        [TestMethod]
        public async Task Certbot()
        {
            var manager = new Certbot();
            var isPresent = await manager.IsPresent();

            Assert.IsTrue(isPresent, "Certbot config should be present");

            var certs = await manager.GetManagedCertificates();

            Assert.IsTrue(certs.Count > 0, "Certbot renewals should be present");


        }
    }
}
