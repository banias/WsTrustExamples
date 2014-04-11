using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Ws_TrustTests
{
    [TestFixture]
    public class WsTrustTests 
    {
        private const string Address = "http://localhost:8888/Ws-trust.svc";

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
            var token = channel.Issue(new RequestSecurityToken()
            {
                RequestType = RequestTypes.Issue,
                AppliesTo = new EndpointReference("http://myDestinationServer/Service"),
            });

            Assert.That(token, Is.Not.Null);
        }

        [Test]
        public void TestLoginInParallelLoop()
        {
            Assert.That(
                Parallel.For(0, 100, i => { TestSingleLogin(); }), Throws.Nothing);
        }

        private static Binding GetBinding()
        {
            var result = new WS2007HttpBinding();
            result.Security.Mode = SecurityMode.Message;
            result.Security.Message.ClientCredentialType = MessageCredentialType.UserName;
            //return result;

            var sbe = SecurityBindingElement.CreateUserNameForSslBindingElement(false);
            sbe.MessageSecurityVersion =
                MessageSecurityVersion
                    .WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
            var sct = SecurityBindingElement.CreateSecureConversationBindingElement(sbe, false);
            //sbe.EndpointSupportingTokenParameters.Signed.Add(new UserNameSecurityTokenParameters());
            sct.MessageSecurityVersion =
                MessageSecurityVersion
                    .WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
            var bindingElementCollection = new BindingElementCollection
                                               {
                                                    sct,

                                                   new TextMessageEncodingBindingElement(),

                                                   new HttpTransportBindingElement
                                                       {
                                                            AllowCookies = true
                                                       },
                                               };

            var customBinding = new CustomBinding(bindingElementCollection);

            return customBinding;
        }
    }
}
