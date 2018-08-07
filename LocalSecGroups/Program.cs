using Amazon;
using Amazon.EC2.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace LocalSecGroups
{
    class Program
    {
        static void Main(string[] args)
        {
            Amazon.EC2.AmazonEC2Client ec2 = new Amazon.EC2.AmazonEC2Client(RegionEndpoint.APSoutheast2);
            var securityGroups = ec2.DescribeSecurityGroupsAsync().Result.SecurityGroups;
            foreach (var securityGroup in securityGroups)
            {
                var dict = securityGroup.IpPermissions.ToList();
                var newDict = dict.ToList();

                foreach (var rule in dict)
                {
                    if (rule.Ipv4Ranges != null)
                    {
                        foreach (var ipv4rule in rule.Ipv4Ranges.ToList())
                        {


                            var rulesRegex = new Regex(@"\[(?:\[[^\[\]]*\]|[^\[\]])*\]", RegexOptions.None);

                            if (ipv4rule.Description == null) continue;

                            var m = rulesRegex.Matches(ipv4rule.Description).ToList();

                            if (m == null) continue;

                            foreach (Group g in m)
                            {
                                var extension = g.Value.Split(new[] { '[', ']' }, StringSplitOptions.RemoveEmptyEntries).ToDictionary(s => s.Split('=')[0], s => s.Split('=')[1]).FirstOrDefault();

                                if (extension.Key == "fqdn")
                                {
                                    //get ip from DNS
                                    var newIP = Dns.GetHostEntry(extension.Value).AddressList.FirstOrDefault().ToString() + "/32";

                                    if (ipv4rule.CidrIp == newIP)
                                    {
                                        Console.WriteLine("Didn't update security group. Cidr Still matches");
                                    }
                                    else
                                    {

                                        IpPermission oldPermission = new IpPermission
                                        {
                                            FromPort = rule.FromPort,
                                            IpProtocol = rule.IpProtocol,
                                            ToPort = rule.ToPort
                                        };
                                        oldPermission.Ipv4Ranges.Add(ipv4rule);
                                        var oldlistofpermissions = new List<IpPermission>();
                                        oldlistofpermissions.Add(oldPermission);
                                        //revoke that one rule.
                                        ec2.RevokeSecurityGroupIngressAsync(new Amazon.EC2.Model.RevokeSecurityGroupIngressRequest { GroupId = securityGroup.GroupId, IpPermissions = oldlistofpermissions }).Wait();

                                        //add the new one.

                                        IpPermission newPermission = new IpPermission
                                        {
                                            FromPort = rule.FromPort,
                                            IpProtocol = rule.IpProtocol,
                                            ToPort = rule.ToPort
                                        };
                                        var newiprange = new IpRange();
                                        newiprange.CidrIp = newIP;
                                        newiprange.Description = ipv4rule.Description;
                                        newPermission.Ipv4Ranges.Add(newiprange);
                                        var newlistofpermissions = new List<IpPermission>();
                                        newlistofpermissions.Add(newPermission);

                                        //ipv4rule.CidrIp = Dns.GetHostEntry(extension.Value).AddressList.FirstOrDefault().ToString() + "/32";
                                        ec2.AuthorizeSecurityGroupIngressAsync(new Amazon.EC2.Model.AuthorizeSecurityGroupIngressRequest { GroupId = securityGroup.GroupId, IpPermissions = newlistofpermissions }).Wait();
                                    }
                                }

                                if (extension.Key == "expiry")
                                {
                                    var isDate = DateTime.TryParse(extension.Value, out DateTime expiry);

                                    if (!isDate)
                                    {
                                        var chronic = new Chronic.Parser();
                                        expiry = chronic.Parse(extension.Value, new Chronic.Options { EndianPrecedence = Chronic.EndianPrecedence.Little }).ToTime();
                                        ipv4rule.Description = ipv4rule.Description.Replace(g.Value, $"[expiry={expiry.ToString("yyyy-MM-dd HH:mm")}]");

                                        IpPermission newPermission = new IpPermission
                                        {
                                            FromPort = rule.FromPort,
                                            IpProtocol = rule.IpProtocol,
                                            ToPort = rule.ToPort
                                        };
                                        var newiprange = new IpRange();
                                        newiprange.Description = ipv4rule.Description;
                                        newiprange.CidrIp = ipv4rule.CidrIp;
                                        newPermission.Ipv4Ranges.Add(newiprange);
                                        var newlistofpermissions = new List<IpPermission>();
                                        newlistofpermissions.Add(newPermission);


                                        ec2.UpdateSecurityGroupRuleDescriptionsIngressAsync(new Amazon.EC2.Model.UpdateSecurityGroupRuleDescriptionsIngressRequest { GroupId = securityGroup.GroupId, IpPermissions = newlistofpermissions }).Wait();
                                        //ec2.RevokeSecurityGroupIngressAsync(new Amazon.EC2.Model.RevokeSecurityGroupIngressRequest { GroupId = securityGroup.GroupId, IpPermissions = listofpermissions }).Wait();

                                    }
                                    else
                                    {
                                        if (expiry < DateTime.Now)
                                        {
                                            IpPermission permission = new IpPermission
                                            {
                                                FromPort = rule.FromPort,
                                                IpProtocol = rule.IpProtocol,
                                                ToPort = rule.ToPort
                                            };
                                            permission.Ipv4Ranges.Add(ipv4rule);
                                            var listofpermissions = new List<IpPermission>();
                                            listofpermissions.Add(permission);

                                            ec2.RevokeSecurityGroupIngressAsync(new Amazon.EC2.Model.RevokeSecurityGroupIngressRequest { GroupId = securityGroup.GroupId, IpPermissions = listofpermissions }).Wait();
                                            //newDict.Where(x => x == rule).Where(y => y.Ipv4Ranges == rule.Ipv4Ranges).First().Ipv4Ranges.Add()
                                        }
                                    }
                                }
                            }
                            
                        }
                    }
                }
            }
        }
    }
}