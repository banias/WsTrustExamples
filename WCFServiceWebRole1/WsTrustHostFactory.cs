using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Activation;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Web;
using Ws_Trust.Service;

namespace WCFServiceWebRole1
{
    public class WsTrustHostFactory : ServiceHostFactory
    {
         public override ServiceHostBase CreateServiceHost(string constructorString, Uri[] baseAddresses)
         {
             var configuration = new StsConfiguration();
             var host = new WSTrustServiceHost(configuration, baseAddresses);
             var serviceBehavior = host.Description.Behaviors.Find<ServiceBehaviorAttribute>();
             serviceBehavior.AddressFilterMode = AddressFilterMode.Any;
             host.Credentials.ServiceCertificate.Certificate = StsHelper.GetCertificate();
             host.Description.Behaviors.Find<ServiceDebugBehavior>().IncludeExceptionDetailInFaults = true;

             host.AddServiceEndpoint(
                    typeof(IWSTrust13SyncContract),
                    GetBinding(),
                    "");
             return host;
         }

         private static Binding GetBinding()
         {
             var result = new WS2007HttpBinding();
             result.Security.Mode = SecurityMode.TransportWithMessageCredential;
             result.Security.Message.ClientCredentialType = MessageCredentialType.UserName;
             result.Security.Message.EstablishSecurityContext = false;
             result.Security.Message.NegotiateServiceCredential = false;
             return result;
             
             var sbe = SecurityBindingElement.CreateUserNameForSslBindingElement(false);
             sbe.MessageSecurityVersion =
                 MessageSecurityVersion
                     .WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
             var sct = SecurityBindingElement.CreateSecureConversationBindingElement(sbe, false);
           //  sbe.EndpointSupportingTokenParameters.Endorsing[0] = new UserNameSecurityTokenParameters();
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
             //basicBinding.Security.Mode = BasicHttpSecurityMode.TransportWithMessageCredential;
             //result.Security.Message.ClientCredentialType = MessageCredentialType.UserName;

             return basicBinding;
         }
    }
}