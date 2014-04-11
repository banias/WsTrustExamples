using System;
using System.Collections.Generic;
using System.IdentityModel.Configuration;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;
using System.Threading.Tasks;
using Ws_Trust.Service;

namespace Ws_Trust
{
    class Program
    {
        private const string hostAddress = "http://localhost:80/Sts";

        static void Main(string[] args)
        {
            var configuration = new StsConfiguration();
            var host = new WSTrustServiceHost(configuration, new Uri(hostAddress));
            //host.AddDefaultEndpoints();
            host.AddServiceEndpoint(typeof(IWSTrust13SyncContract), GetBinding(), "");
            host.Credentials.ServiceCertificate.Certificate = StsHelper.GetCertificate();
            host.Description.Behaviors.Find<ServiceDebugBehavior>().IncludeExceptionDetailInFaults = true;
            host.Description.Behaviors.Find<ServiceBehaviorAttribute>().AddressFilterMode = AddressFilterMode.Any;          
            host.Open();
            Console.WriteLine("host started " + hostAddress);
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
