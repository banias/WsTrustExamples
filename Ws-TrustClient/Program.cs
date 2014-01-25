using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Text;
using System.Threading.Tasks;

namespace Ws_TrustClient
{
    class Program
    {
        private const string Address = "http://localhost:8080/Sts";
        static void Main(string[] args)
        {
            Console.WriteLine("Press q to quit the program, press any key to send request");
            while (true)
            {
                var key = Console.ReadKey();
                if(key.KeyChar == 'q')
                    break;


                var channelFactpry = new WSTrustChannelFactory(GetBinding());
                channelFactpry.Credentials.UserName.UserName = "admin";
                channelFactpry.Credentials.UserName.Password = "passwd";

                var channel = channelFactpry.CreateChannel(new EndpointAddress(Address));
                var token = channel.Issue(new RequestSecurityToken()
                {
                    RequestType = RequestTypes.Issue,
                    AppliesTo = new EndpointReference("http://myDestinationServer/Service"),
                });
                if (token != null)
                {
                    Console.WriteLine("token received");
                }
            }


            Console.ReadKey();

        }

        private static Binding GetBinding()
        {
            var result = new WS2007HttpBinding();
            result.Security.Mode = SecurityMode.Message;
            result.Security.Message.ClientCredentialType = MessageCredentialType.UserName;
            return result;
        }
    }
}
