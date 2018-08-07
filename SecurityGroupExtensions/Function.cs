using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Amazon.Lambda.Core;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace SecurityGroupExtensions
{
    public class Function
    {
        
        /// <summary>
        /// A simple function that takes a string and does a ToUpper
        /// </summary>
        /// <param name="input"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        public void FunctionHandler(ILambdaContext context)
        {
            Amazon.EC2.AmazonEC2Client ec2 = new Amazon.EC2.AmazonEC2Client();
            var securityGroups = ec2.DescribeSecurityGroupsAsync().Result.SecurityGroups;
            foreach (var securityGroup in securityGroups)
            {
                var dict = securityGroup.IpPermissions.ToList();
                foreach (var rule in dict)
                {
                    if (rule.Ipv4Ranges != null)
                    {
                        foreach (var ipv4rule in rule.Ipv4Ranges)
                        {
                            var extensions = ipv4rule.Description.Split('|')
                                .Select(x => x.Split('='))
                                .ToDictionary(x => x[0], x => x[1]);

                            foreach (var extension in extensions)
                            {
                                if (extension.Key == "fqdn")
                                {
                                    ipv4rule.CidrIp = Dns.GetHostEntry(extension.Value).AddressList.FirstOrDefault().ToString() + "/32";
                                }
                            }
                            ec2.AuthorizeSecurityGroupIngressAsync(new Amazon.EC2.Model.AuthorizeSecurityGroupIngressRequest { GroupId = securityGroup.GroupId, IpPermissions = dict });
                        }
                    }
                }
            }
            
            


        }


    }
}
