using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using Ws_Trust.Service;
using RequestSecurityTokenResponse = System.IdentityModel.Protocols.WSTrust.RequestSecurityTokenResponse;

namespace Ws_TrustTests
{
    [TestFixture]
    public class WsTrustLocalTests
    {
        private WSTrustServiceHost _host;
        private const string hostAddress = "https://localhost:19311/StsLocal";

        [SetUp]
        public void PrepareTest()
        {
            var configuration = new StsConfiguration();
            _host = new WSTrustServiceHost(configuration, new Uri(hostAddress));
            //host.AddDefaultEndpoints();
            _host.AddServiceEndpoint(typeof(IWSTrust13SyncContract), GetBinding(), "");
            _host.Credentials.ServiceCertificate.Certificate = StsHelper.GetCertificate();
            _host.Description.Behaviors.Find<ServiceDebugBehavior>().IncludeExceptionDetailInFaults = true;
            _host.Description.Behaviors.Find<ServiceBehaviorAttribute>().AddressFilterMode = AddressFilterMode.Any;
            _host.Open();
            Console.WriteLine("host started " + hostAddress);
        }

        [Test]
        public void Test()
        {
            var WsBinding = GetBinding();
            var rst = new RequestSecurityToken()
            {

                RequestType = RequestTypes.Issue,
                AppliesTo = new EndpointReference("http://myDestinationServer/Service")
            };
            var factory = new WSTrustChannelFactory(WsBinding,
                                                    new EndpointAddress(hostAddress));

            factory.Credentials.ClientCertificate.SetCertificate(StoreLocation.LocalMachine, StoreName.My, X509FindType.FindBySubjectName,
                                   "localhost");
            factory.Credentials.SupportInteractive = false;

            var channel = factory.CreateChannel(new EndpointAddress(hostAddress));
            RequestSecurityTokenResponse rstr = null;
            channel.Issue(new RequestSecurityToken()
            {

                RequestType = RequestTypes.Issue,
                AppliesTo = new EndpointReference("http://myDestinationServer/Service"),
            }, out rstr);

            Assert.That(rstr.RequestedSecurityToken, Is.Not.Null);
        }

        private static Binding GetBinding()
        {
            var result = new WS2007HttpBinding();
            result.Security.Mode = SecurityMode.TransportWithMessageCredential;
            result.Security.Message.ClientCredentialType = MessageCredentialType.Certificate;
            result.Security.Message.EstablishSecurityContext = false;
            result.Security.Message.NegotiateServiceCredential = false;
            return result;
        }
    }
}
