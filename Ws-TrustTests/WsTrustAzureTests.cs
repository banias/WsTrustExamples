using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Ws_TrustTests
{
    [TestFixture]
    public class WsTrustAzureTests 
    {
        private const string Address = "https://127.0.0.1:8888/Ws-trust.svc";

        [SetUp]
        public void PrepareTest()
        {
            
        }

        [Test]
        public void TestSingleLogin()
        {
            var channelFactpry = new WSTrustChannelFactory(GetBinding());
            channelFactpry.Credentials.UserName.UserName = "admin";
            channelFactpry.Credentials.UserName.Password = "passwd";

            var channel = channelFactpry.CreateChannel(new EndpointAddress(Address));
            RequestSecurityTokenResponse rstr = null;
            channel.Issue(new RequestSecurityToken()
            {

                RequestType = RequestTypes.Issue,
                AppliesTo = new EndpointReference("http://myDestinationServer/Service"),
            }, out rstr);

            Assert.That(rstr.RequestedSecurityToken, Is.Not.Null);
        }

        [Test]
        public void TestLoginInParallelLoop()
        {
            Assert.That(() =>
                Parallel.For(0, 100, i => { TestSingleLogin(); }), Throws.Nothing);
        }

        private static Binding GetBinding()
        {
            var result = new WS2007HttpBinding();
            result.Security.Mode = SecurityMode.TransportWithMessageCredential;
            result.Security.Message.ClientCredentialType = MessageCredentialType.UserName;
            result.Security.Message.EstablishSecurityContext = false;
            result.Security.Message.NegotiateServiceCredential = false;
            //result.UseDefaultWebProxy = false;
            //result.BypassProxyOnLocal = false;
            //result.ProxyAddress = new Uri("https://127.0.0.1:8888");
            return result;

            var sbe = SecurityBindingElement.CreateUserNameForSslBindingElement(false);
            sbe.MessageSecurityVersion =
                MessageSecurityVersion
                    .WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
            var sct = SecurityBindingElement.CreateSecureConversationBindingElement(sbe, false);
           // sbe.EndpointSupportingTokenParameters.Endorsing.Add(new UserNameSecurityTokenParameters());
            sct.MessageSecurityVersion =
                MessageSecurityVersion
                    .WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
            var bindingElementCollection = new BindingElementCollection
                                               {
                                                    sbe,

                                                   new TextMessageEncodingBindingElement(),

                                                   new HttpTransportBindingElement
                                                       {
                                                            AllowCookies = true
                                                       },
                                               };

            var customBinding = new CustomBinding(bindingElementCollection);

            return customBinding;
            var basicBinding = new BasicHttpBinding();
            basicBinding.Security.Mode = BasicHttpSecurityMode.None;
            //result.Security.Message.ClientCredentialType = MessageCredentialType.UserName;
            return basicBinding;
        }
    }
}
