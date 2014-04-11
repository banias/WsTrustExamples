using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Activation;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
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