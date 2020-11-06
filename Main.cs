using System;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Collections;
using PacketDotNet;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace ReadingCaptureFile
{
    class MainClass
    {
        static int counter=0;
        struct Servername {
            public string querry;
            public int index;
        };
        struct ConnectionRecord {
            public long timeval;
            public long lastupdatetime;
            public long IPSource;
            public long IPSourceNetw;
            public long IPDst;
            public long IPDstNetw;
            public ushort SrcPort;
            public ushort DstPort;
            public int connStatus;
            public int vpnscore;
            public string servername;
            public int synfound;
            public Dictionary<int, byte[]> sslhandshakemsgs;
        };
        struct DnsRecord {
            public List<string> hostname { get; set; }
            public List<string> authoritativeNames { get; set; }
            public List<int> IplistI { get; set; }
            public List<string> IplistS { get; set; }
            public int vpns;
            public int dnss;
        };
        static List<string> authNZenM;
        static List<string> dodgyhost;
        static List<string> VPNsDNS;
        static Dictionary<int, DnsRecord> IPHashTable;
        static Dictionary<long, ConnectionRecord> ConnectionTable;
        struct Answername
        {
            public string hostname;
            public int answercount;
            public List<int> Answertype { get; set; }
            public List<int> IplistI { get; set; }
            public List<string> IplistS { get; set; }
            public int index;
        };
        struct Authoritativename
        {
            public string hostname;
            public int authoritativecount;
            public List<int> Answertype { get; set; }
            public List<string> ServerName { get; set; }
            public int index;
        };
        enum HandshakeType
        {
            hello_request = 0, client_hello = 1, server_hello = 2,
            new_session_ticket =4,
            certificate = 11, server_key_exchange = 12,
            certificate_request = 13, server_hello_done = 14,
            certificate_verify = 15, client_key_exchange = 16,
            finished = 20
        };
        enum ContentType
        {
            change_cipher_spec = 20, alert = 21, handshake = 22,
            application_data = 23
        };
    
        public static string logfile = "";
        public static void Main (string[] args)
        {
            string ver = SharpPcap.Version.VersionString;
            IPHashTable = new Dictionary<int, DnsRecord>();
            ConnectionTable = new Dictionary<long, ConnectionRecord>();
            authNZenM = new List<string>(new string[] { "jill.ns.cloudflare.com", "rick.ns.cloudflare.com", "jill", "rick" });
            dodgyhost = new List<string>(new string[] { "godaddy", "torproject" });
            VPNsDNS = new List<string>(new string[] { "trlone", "tcdn", "young-purple", "owens-willis-teal", "clark-aqua", "cooper-martin-white", "flags.zeus.pm","api.zcdn" });

            /* Print SharpPcap version */
            Console.WriteLine("SharpPcap {0}, ReadingCaptureFile", ver);
            Console.WriteLine();
            logfile = @"D:\logs0101.txt";
            
                Console.WriteLine();
            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }
            
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            int i = 0;

            // Print out the available devices
            foreach (var dev in devices)
            {
                Console.WriteLine("{0}) {1}", i, dev.Description);
                i++;
            }
            Console.WriteLine("{0}) {1}", i, "Read packets from offline pcap file");

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            var choice = int.Parse(Console.ReadLine());

            ICaptureDevice device = null;
            // read the file from stdin or from the command line arguments
            
            // use the first argument as the filename
            

            // ICaptureDevice device;
            if (choice == i)
            {
                Console.Write("-- Please enter an input capture file name: ");
                string capFile = Console.ReadLine();
                device = new CaptureFileReaderDevice(capFile);
            }
            else
            {
                device = devices[choice];
            }
            
            Thread thread = new Thread(new ThreadStart(RemoveConnections));
            thread.Start();
            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival +=
                new PacketArrivalEventHandler( device_OnPacketArrival );
            device.Open();
            Console.WriteLine();
            Console.WriteLine
                ("-- Capturing from '{0}', hit 'Ctrl-C' to exit...",
                device);

            // Start capture 'INFINTE' number of packets
            // This method will return when EOF reached.
            device.Capture();

            // Close the pcap device
            device.Close();
            thread.Abort();
            Console.WriteLine("-- End of file reached.");
            Console.Write("Hit 'Enter' to exit...");
            Console.ReadLine();
        }

        private static void RemoveConnections()
        {
            while (true)
            {
                long currentticks = DateTime.Now.Ticks;
                try
                {
                    List<long> connectionDel = new List<long>();
                    foreach (KeyValuePair<long, ConnectionRecord> entry in ConnectionTable)
                    {
                        if (currentticks - entry.Value.lastupdatetime > 100000000)
                        {
                            //connectionDel.Add(entry.Key);
                        }
                        /*if (currentticks - entry.Value.timeval > 600000000)
                        {
                            if (entry.Value.synfound == 0)
                            {
                                if (IPHashTable.ContainsKey((int)entry.Value.IPDstNetw))
                                {
                                    if (IPHashTable[(int)entry.Value.IPDstNetw].vpns > 0)
                                    {
                                        ConnectionRecord obj = entry.Value;
                                        obj.vpnscore = IPHashTable[(int)entry.Value.IPDstNetw].vpns;
                                        ConnectionTable[entry.Key] = obj;

                                    }
                                }
                            }
                        }*/

                    }
                    foreach (long k in connectionDel)
                    {
                        ConnectionTable.Remove(k);
                    }
                }
                catch (Exception ee)
                {

                }
                Thread.Sleep(5000);
            }
        }

        private static int packetIndex = 0;

        /// <summary>
        /// Prints the source and dest MAC addresses of each received Ethernet frame
        /// </summary>
        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            counter++;
             var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
             if (packet is PacketDotNet.EthernetPacket)
             {
                 var ip = PacketDotNet.IpPacket.GetEncapsulated(packet);
                 if (ip != null)
                 {
                     var tcp = PacketDotNet.TcpPacket.GetEncapsulated(packet);
                     if (tcp != null)
                     {
                        try
                        {
                            handleTCPData(packet);
                        }
                        catch (Exception ee)
                        {
                            Console.WriteLine(ee.ToString());
                        }
                        
                    }
                    else
                     {
                         var udp = PacketDotNet.UdpPacket.GetEncapsulated(packet);
                         if (udp != null)
                         {
                             byte[] payload = udp.Bytes;
                            if (udp.SourcePort == 53)
                            {
                                DNSHandlePacket(payload);
                            }
                        }
                     }
                 }
             }
        }
        private static long NetworkToHostOrder(byte[] array, int index, int length)
        {
            long answer = 0;
            int iter = 0;
            for (iter = 0; iter < length; iter++)
            {
                answer = answer << 8;
                answer += array[index + iter];
            }
            return answer;
        }
        private static void handleTCPData(Packet packet)
        {
            var ip = PacketDotNet.IpPacket.GetEncapsulated(packet);
            var tcp = PacketDotNet.TcpPacket.GetEncapsulated(packet);
            var index = tcp.DataOffset * 4;
            byte[] payload = tcp.Bytes;
            if (tcp.AllFlags == 0x02)
            {
                //syn recieved

                long key = 0;
                byte[] ipdst = ip.DestinationAddress.GetAddressBytes();
                key += NetworkToHostOrder(ipdst, 0, 4) << 32;
                key += tcp.SourcePort << 16;
                key += tcp.DestinationPort;
                ConnectionRecord obj = new ConnectionRecord();
                obj.connStatus = 1;
                obj.IPDst = ip.DestinationAddress.Address;
                obj.IPDstNetw = NetworkToHostOrder(ip.DestinationAddress.GetAddressBytes(), 0, 4);
                obj.IPSource = ip.SourceAddress.Address;
                obj.IPSourceNetw = NetworkToHostOrder(ip.SourceAddress.GetAddressBytes(), 0, 4);
                obj.SrcPort = tcp.SourcePort;
                obj.DstPort = tcp.DestinationPort;
                obj.vpnscore = 0;
                obj.timeval = DateTime.Now.Ticks;
                obj.lastupdatetime = DateTime.Now.Ticks;
                obj.synfound = 1;
                if (!ConnectionTable.ContainsKey(key))
                {
                    ConnectionTable.Add(key, obj);
                }
                else
                {
                    //Console.WriteLine("Key already present " + key+" updating Object");
                    ConnectionTable[key] = obj;
                }
            }
            else if (tcp.AllFlags == 0x12)
            {
                long key = 0;
                byte[] ipdst = ip.SourceAddress.GetAddressBytes();
                key += NetworkToHostOrder(ipdst, 0, 4) << 32;
                key += tcp.DestinationPort << 16;
                key += tcp.SourcePort;
                if (!ConnectionTable.ContainsKey(key))
                {
                    ConnectionRecord obj = new ConnectionRecord();
                    obj.connStatus = 2;
                    obj.IPDst = ip.SourceAddress.Address;
                    obj.IPDstNetw = NetworkToHostOrder(ip.SourceAddress.GetAddressBytes(), 0, 4);
                    obj.IPSource = ip.DestinationAddress.Address;
                    obj.IPSourceNetw = NetworkToHostOrder(ip.DestinationAddress.GetAddressBytes(), 0, 4);
                    obj.SrcPort = tcp.DestinationPort;
                    obj.DstPort = tcp.SourcePort;
                    obj.vpnscore = 0;
                    obj.timeval = DateTime.Now.Ticks;
                    obj.lastupdatetime = DateTime.Now.Ticks;
                    obj.synfound = 1;
                    ConnectionTable.Add(key, obj);
                }
                else
                {
                    ConnectionRecord obj = ConnectionTable[key];
                    obj.connStatus = 2;
                    obj.lastupdatetime = DateTime.Now.Ticks;
                    ConnectionTable[key] = obj;
                }

            }
            else if (tcp.AllFlags == 0x004)
            {
                long key = 0;
                byte[] ipdst = ip.SourceAddress.GetAddressBytes();
                key += NetworkToHostOrder(ipdst, 0, 4) << 32;
                key += tcp.DestinationPort << 16;
                key += tcp.SourcePort;
                if (ConnectionTable.ContainsKey(key))
                {
                    ConnectionTable.Remove(key);
                }
                else
                {
                    ipdst = ip.DestinationAddress.GetAddressBytes();
                    key = 0;
                    key += NetworkToHostOrder(ipdst, 0, 4) << 32;
                    key += tcp.SourcePort << 16;
                    key += tcp.DestinationPort;
                    if (ConnectionTable.ContainsKey(key))
                    {
                        ConnectionTable.Remove(key);
                    }
                }

            }
            else
            {
                //client
                long keyc = 0;
                byte[] ipdst = ip.DestinationAddress.GetAddressBytes();
                keyc += NetworkToHostOrder(ipdst, 0, 4) << 32;
                keyc += tcp.SourcePort << 16;
                keyc += tcp.DestinationPort;
                if (ConnectionTable.ContainsKey(keyc))
                {
                    ConnectionRecord obj = ConnectionTable[keyc];
                    if (obj.synfound == 1 && obj.connStatus == 2)
                    {
                        obj.connStatus = 3;
                        obj.lastupdatetime = DateTime.Now.Ticks;
                        ConnectionTable[keyc] = obj;
                    }
                    else if (obj.synfound == 1 && obj.connStatus == 3)
                    {
                        obj.connStatus = 4;
                        obj.lastupdatetime = DateTime.Now.Ticks;
                        ConnectionTable[keyc] = obj;
                        if (payload.Length > index)
                        {
                            if (SSLCertHandle(payload, index, keyc) == true)
                            {
                                obj = ConnectionTable[keyc];
                                //check vpn score
                                int dnss = 0;
                                int vpns = checkvpnscore(obj,out dnss);
                                if (vpns == 1)
                                {
                                    Console.WriteLine("Valid Stream No DNS found Hotspot/TOR/VPN"+ Environment.NewLine+ip.SourceAddress.ToString() + ":" + tcp.SourcePort + "->" + ip.DestinationAddress.ToString() + ":" + tcp.DestinationPort + " Server Name: " + obj.servername);
                                    using (StreamWriter writer = new StreamWriter(logfile, true))
                                    {

                                        writer.WriteLine("Valid Stream No DNS found Hotspot/TOR/VPN" + Environment.NewLine + ip.SourceAddress.ToString() + ":" + tcp.SourcePort + "->" + ip.DestinationAddress.ToString() + ":" + tcp.DestinationPort + " Server Name: " + obj.servername);
                                    }
                                }
                                else if (vpns == 3)
                                {
                                    Console.WriteLine("Valid Stream ZenMate Detected" + Environment.NewLine + ip.SourceAddress.ToString() + ":" + tcp.SourcePort + "->" + ip.DestinationAddress.ToString() + ":" + tcp.DestinationPort + " Server Name: " + obj.servername);
                                    using (StreamWriter writer = new StreamWriter(logfile, true))
                                    {

                                        writer.WriteLine("Valid Stream ZenMate Detected" + Environment.NewLine + ip.SourceAddress.ToString() + ":" + tcp.SourcePort + "->" + ip.DestinationAddress.ToString() + ":" + tcp.DestinationPort + " Server Name: " + obj.servername);
                                    }
                                }
                                else
                                {
                                    
                                    Console.WriteLine("Valid Stream SSL" + Environment.NewLine + ip.SourceAddress.ToString() + ":" + tcp.SourcePort + "->" + ip.DestinationAddress.ToString() + ":" + tcp.DestinationPort + " Server Name: " + obj.servername);
                                    if (dnss == 1)
                                    {
                                        Console.WriteLine("This HostName is Dodgy, Beware!!");
                                    }
                                    else if (dnss == 2)
                                    {
                                        Console.WriteLine("VPN DNS Detected");
                                    }
                                    using (StreamWriter writer = new StreamWriter(logfile, true))
                                    {
                                       
                                        writer.WriteLine("Valid Stream SSL" + Environment.NewLine + ip.SourceAddress.ToString() + ":" + tcp.SourcePort + "->" + ip.DestinationAddress.ToString() + ":" + tcp.DestinationPort + " Server Name: " + obj.servername);
                                        if (dnss ==1)
                                        {
                                            writer.WriteLine("This HostName is Dodgy, Beware!!");
                                        }
                                        else if (dnss == 2)
                                        {
                                            writer.WriteLine("VPN DNS Detected");
                                        }
                                       
                                    }
                                }
                                obj.vpnscore = vpns;
                                ConnectionTable[keyc] = obj;
                            }
                            else
                            {
                                Console.WriteLine("Valid TCP Stream" + Environment.NewLine + ip.SourceAddress.ToString() + ":" + tcp.SourcePort + "->" + ip.DestinationAddress.ToString() + ":" + tcp.DestinationPort + " Server Name: " + hostnamevsip((int)NetworkToHostOrder(ipdst, 0, 4)));
                                using (StreamWriter writer = new StreamWriter(logfile, true))
                                {

                                    writer.WriteLine("Valid TCP Stream" + Environment.NewLine + ip.SourceAddress.ToString() + ":" + tcp.SourcePort + "->" + ip.DestinationAddress.ToString() + ":" + tcp.DestinationPort + " Server Name: " + hostnamevsip((int)NetworkToHostOrder(ipdst, 0, 4)));
                                }
                            }
                        }
                        


                    }
                    else
                    {
                        SSLCertHandle(payload, index, keyc);
                        obj.lastupdatetime = DateTime.Now.Ticks;
                        ConnectionTable[keyc] = obj;
                    }
                }
                else
                {
                    //server
                    ipdst = ip.SourceAddress.GetAddressBytes();
                    keyc = 0;
                    keyc += NetworkToHostOrder(ipdst, 0, 4) << 32;
                    keyc += tcp.DestinationPort << 16;
                    keyc += tcp.SourcePort;
                    if (ConnectionTable.ContainsKey(keyc))
                    {
                        ConnectionRecord obj = ConnectionTable[keyc];
                        if (obj.synfound == 1 && obj.connStatus == 4)
                        {
                            obj.connStatus = 5;
                            SSLCertHandle(payload, index, keyc);
                            obj.lastupdatetime = DateTime.Now.Ticks;
                            ConnectionTable[keyc] = obj;
                        }
                        else
                        {
                            SSLCertHandle(payload, index, keyc);
                            obj.lastupdatetime = DateTime.Now.Ticks;
                            ConnectionTable[keyc] = obj;
                        }
                    }
                    else
                    {
                        if (tcp.SourcePort < tcp.DestinationPort)
                        {
                            ConnectionRecord obj = new ConnectionRecord();
                            obj.connStatus = 10;
                            obj.IPDst = ip.SourceAddress.Address;
                            obj.IPSource = ip.DestinationAddress.Address;
                            obj.IPDstNetw = NetworkToHostOrder(ip.SourceAddress.GetAddressBytes(), 0, 4);
                            obj.IPSourceNetw = NetworkToHostOrder(ip.DestinationAddress.GetAddressBytes(), 0, 4);
                            obj.SrcPort = tcp.DestinationPort;
                            obj.DstPort = tcp.SourcePort;
                            obj.vpnscore = 10;
                            obj.timeval = DateTime.Now.Ticks;
                            obj.lastupdatetime = DateTime.Now.Ticks;
                            obj.synfound = 0;
                            ConnectionTable.Add(keyc, obj);

                        }
                        else
                        {
                            ipdst = ip.DestinationAddress.GetAddressBytes();
                            keyc = 0;
                            keyc += NetworkToHostOrder(ipdst, 0, 4) << 32;
                            keyc += tcp.SourcePort << 16;
                            keyc += tcp.DestinationPort;
                            ConnectionRecord obj = new ConnectionRecord();
                            obj.connStatus = 10;
                            obj.IPDst = ip.DestinationAddress.Address;
                            obj.IPSource = ip.SourceAddress.Address;
                            obj.IPDstNetw = NetworkToHostOrder(ip.DestinationAddress.GetAddressBytes(), 0, 4);
                            obj.IPSourceNetw = NetworkToHostOrder(ip.SourceAddress.GetAddressBytes(), 0, 4);
                            obj.SrcPort = tcp.SourcePort;
                            obj.DstPort = tcp.DestinationPort;
                            obj.vpnscore = 10;
                            obj.timeval = DateTime.Now.Ticks;
                            obj.lastupdatetime = DateTime.Now.Ticks;
                            obj.synfound = 0;
                            ConnectionTable.Add(keyc, obj);
                        }
                    
                    }
                }
            }
            

        }
        private static string hostnamevsip(int ipserver)
        {
            if (IPHashTable.ContainsKey(ipserver))
            {
                return IPHashTable[ipserver].hostname[0];
            }
            return "";
        }
        private static int checkvpnscore(ConnectionRecord obj, out int dnss)
        {
            dnss = 0;
            if (IPHashTable.ContainsKey((int)obj.IPDstNetw))
            {
                DnsRecord entry = IPHashTable[(int)obj.IPDstNetw];
                dnss = entry.dnss;
                if (entry.authoritativeNames.Count > authNZenM.Count)
                {
                    foreach (string s in authNZenM)
                    {
                        if (entry.authoritativeNames.Contains(s))
                        {
                            entry.vpns = 3;
                            IPHashTable[(int)obj.IPDstNetw] = entry;
                            return 3;
                        }
                    }
                }
                else
                {
                    foreach (string s in entry.authoritativeNames)
                    {
                        if (authNZenM.Contains(s))
                        {
                            entry.vpns = 3;
                            IPHashTable[(int)obj.IPDstNetw] = entry;
                            return 3;
                        }
                    }
                }

                if (entry.hostname.Contains(obj.servername))
                {
                   // return getdnsscore(new List<string>(new string[] {obj.servername }));
                    return 0;
                }
                else
                {
                    return 2;
                }
            }
            else
            {
                return 1;
            }

            
        }

        private static bool SSLCertHandle(byte[] payload, int index, long key)
        {
            #region SSLCertificateRegion
            if (payload.Length > index)
            {
                int ind_iter = index;
                do
                {
                    if (payload[ind_iter] == (byte)ContentType.handshake)
                    {
                        //handshake msg
                        if (payload[ind_iter + 1] == 0x03 && (payload[ind_iter + 2] == 0x03 || payload[ind_iter + 2] == 0x01 || payload[ind_iter + 2] == 0x02))
                        {

                            int t_len = ((int)payload[ind_iter + 3] << 8) + payload[ind_iter + 4];
                            if (t_len <= payload.Length - ind_iter - 5)
                            {
                                int certtype = payload[ind_iter + 5];
                                Console.WriteLine("Message is " + (HandshakeType)certtype);
                            }
                            ind_iter += t_len + 5;
                        }
                        else
                            break;
                    }
                    else if (payload[ind_iter] == (byte)ContentType.change_cipher_spec)
                    {
                        if (payload[ind_iter + 1] == 0x03 && (payload[ind_iter + 2] == 0x03 || payload[ind_iter + 2] == 0x01 || payload[ind_iter + 2] == 0x02))
                        {
                            int t_len = ((int)payload[ind_iter + 3] << 8) + payload[ind_iter + 4];
                            ind_iter += t_len;
                            Console.WriteLine("Message is Change Cipher Spec");
                        }
                        else
                            break;
                    }
                    else if (payload[ind_iter] == (byte)ContentType.application_data)
                    {
                        if (payload[ind_iter + 1] == 0x03 && (payload[ind_iter + 2] == 0x03 || payload[ind_iter + 2] == 0x01 || payload[ind_iter + 2] == 0x02))
                        {
                            int t_len = ((int)payload[ind_iter + 3] << 8) + payload[ind_iter + 4];
                            ind_iter += t_len + 5;
                         //   Console.WriteLine("Message is Change Application Data");
                        }
                        else
                            break;
                    }
                    else
                        break;
                } while (ind_iter < payload.Length);
                //client hello
                if (payload[index] == 0x16 && payload[index + 1] == 0x03 && (payload[index + 2] == 0x03 || payload[index + 2] == 0x01 || payload[index + 2] == 0x02) && payload[index + 5] == 0x01)
                {


                    int cert_len = ((int)payload[index + 3] << 8) + payload[index + 4];
                    index = index + 6;
                    int handsklen = ((int)payload[index] << 16) + ((int)payload[index + 1] << 8) + payload[index + 2];
                    index += 34 + 3;
                    int sessionlength = payload[index];
                    index += sessionlength + 1;
                    int cipherSLength = ((int)payload[index] << 8) + payload[index + 1];
                    index += cipherSLength + 2;
                    int compressionMlength = payload[index];
                    index += compressionMlength + 1;
                    int extensionLength = ((int)payload[index] << 8) + payload[index + 1];
                    index += 2;
                    int ct_iter = 0;
                    while (ct_iter < extensionLength)
                    {
                        int tag = 0, length = 0;
                        tag = ((int)payload[index + ct_iter] << 8) + payload[index + ct_iter + 1];
                        length = ((int)payload[index + ct_iter + 2] << 8) + payload[index + ct_iter + 2 + 1];
                        if (tag == 0x0000)//server_name
                        {
                            //tlv iter here also
                            int current_ident = index + ct_iter + 4;
                            if (payload[current_ident + 2] == 0x00)//host_name
                            {
                                int loop_iter = ((int)payload[current_ident + 3] << 8) + payload[current_ident + 4];
                                string hostname = "";
                                for (int tmp = 0; tmp < loop_iter; tmp++)
                                {
                                    hostname += ((char)payload[current_ident + 5 + tmp]).ToString();

                                }
                                // Console.WriteLine("Host Name: " + hostname);
                                // using (StreamWriter writer = new StreamWriter("D:\\log.txt", true))
                                // {
                                //     writer.WriteLine("Host Name: " + hostname);
                                //
                                // }

                                if (key != 0)
                                {
                                    ConnectionRecord obj = ConnectionTable[key];
                                    obj.servername = hostname;
                                    ConnectionTable[key] = obj;
                                    return true;
                                }
                                else
                                    return false;

                            }
                        }
                        ct_iter += length + 4;

                    }
                }
            }
            return false;
            #endregion
        }

        private static void DNSHandlePacket(byte[] payload)
        {
            #region DNSRESponseHandle
            int index = 8;
            int transactionrecord = ((int)payload[index] << 8) + payload[index + 1];
            index += 2;
            int flags = ((int)payload[index] << 8) + payload[index + 1];
            index += 2;
            int questions = ((int)payload[index] << 8) + payload[index + 1];
            index += 2;
            int answers = ((int)payload[index] << 8) + payload[index + 1];
            index += 2;
            int authoritative = ((int)payload[index] << 8) + payload[index + 1];
            index += 2;
            int additional = ((int)payload[index] << 8) + payload[index + 1];
            index += 2;
            Servername querry_response;
            Answername answer_response;
            Authoritativename auth_response;
            if (questions == 1)
            {
                querry_response = getquerryname(payload, index);
                index = querry_response.index;
                index += 4;
                if (answers > 0)
                {
                    answer_response = getanswerresponse(payload, index, querry_response.querry, answers);
                    index = answer_response.index;
                }
                else
                {
                    answer_response = new Answername();
                }
                if (authoritative > 0)
                {
                    auth_response = getauthoritativeresponse(payload, index, querry_response.querry, authoritative);
                    index = auth_response.index;
                }
                else
                {
                    auth_response = new Authoritativename();
                }
                if (answers > 0)
                {
                    if (answer_response.Answertype.Contains(0x01))
                    {
                        foreach (int UniqueIP in answer_response.IplistI)
                        {
                            if (UniqueIP != 0 && !IPHashTable.ContainsKey(UniqueIP))
                            {
                                DnsRecord obj = new DnsRecord();
                                obj.IplistI = answer_response.IplistI;
                                obj.IplistS = answer_response.IplistS;
                               
                                obj.authoritativeNames = auth_response.ServerName;
                                obj.hostname = new List<string>();
                                obj.hostname.Add(querry_response.querry);
                                obj.dnss = getdnsscore(obj.hostname);
                                IPHashTable.Add(UniqueIP, obj);
                                
                            }
                            else if (IPHashTable.ContainsKey(UniqueIP))
                            {
                                DnsRecord obj;
                                

                                if (IPHashTable.TryGetValue(UniqueIP, out obj) == true)
                                {
                                    if (answer_response.IplistI != null)
                                    {
                                        foreach (int dnstmpI in answer_response.IplistI)
                                        {
                                            if (!obj.IplistI.Contains(dnstmpI))
                                            {
                                                obj.IplistI.Add(dnstmpI);
                                            }
                                        }
                                    }
                                    if (answer_response.IplistS != null)
                                    {
                                        foreach (string dnstmpI in answer_response.IplistS)
                                        {
                                            if (!obj.IplistS.Contains(dnstmpI))
                                            {
                                                obj.IplistS.Add(dnstmpI);
                                            }
                                        }
                                    }
                                  /*  if (auth_response.ServerName != null)
                                    {
                                        foreach (string dnstmpI in auth_response.ServerName)
                                        {
                                            if (!obj.authoritativeNames.Contains(dnstmpI))
                                            {
                                                obj.authoritativeNames.Add(dnstmpI);
                                            }
                                        }
                                    }*/
                                    if (querry_response.querry != null)
                                    {
                                        if (!obj.hostname.Contains(querry_response.querry))
                                        {
                                            obj.hostname.Add(querry_response.querry);
                                        }
                                    }
                                }
                                obj.dnss=getdnsscore(obj.hostname);
                                IPHashTable[UniqueIP] = obj;
                            }
                        }
                    }
                }
            }
            #endregion
        }

        private static int getdnsscore(List<string> hostname)
        {
            foreach (string s in hostname)
            {
                
                foreach (string ds in dodgyhost)
                {
                    if (s.Contains(ds))
                    {
                        return 1;
                    }
                }
                foreach (string ds in VPNsDNS)
                {
                    if (s.Contains(ds))
                    {
                        return 2;
                    }
                }
            }
            return 0;
        }

        private static Authoritativename getauthoritativeresponse(byte[] payload, int index, string querryS, int authoritative)
        {
            Authoritativename obj = new Authoritativename();
            obj.ServerName = new List<string>();
            obj.Answertype = new List<int>();
            obj.hostname = querryS;
            int ident = 0;
            int auth_iter = 0;
            while (auth_iter < authoritative)
            {
                ident = ((int)payload[index] << 8) + payload[index + 1];
                index += 2;
                int atype = ((int)payload[index] << 8) + payload[index + 1];
                index += 8;
                int lengthans = ((int)payload[index] << 8) + payload[index + 1];
                index += 2;
                if (atype == 0x02)
                {
                    string querry = "";
                    int auth_iter_tmp = 0;
                    int ind_tmp = index;
                    while (auth_iter_tmp<lengthans)
                    {
                        int iter = 1;
                        while (iter <= payload[ind_tmp])
                        {
                            if (payload.Length <= ind_tmp + iter)
                            {
                                break;
                            }
                            querry += ((char)payload[ind_tmp + iter]).ToString();
                            iter++;

                        }
                        auth_iter_tmp += iter;
                        ind_tmp += iter;
                        if (ind_tmp == payload.Length)
                            break;
                        if (payload[ind_tmp] != 0&& (payload[ind_tmp]&0xc0) != 0xc0)
                            querry += ".";
                        else
                            break;
                       

                    }
                    obj.Answertype.Add(atype);
                    obj.ServerName.Add(querry);
                    obj.authoritativecount += 1;
                }
                index += lengthans;
                auth_iter++;
            }
            
            obj.index = index;
            return obj;
        }

        private static Answername getanswerresponse(byte[] payload, int index, string querry, int answers)
        {
            Answername obj = new Answername();
            obj.IplistI = new List<int>();
            obj.IplistS = new List<string>();
            obj.Answertype = new List<int>();
            obj.hostname = querry;
            int ident = 0;
            int answer_iter = 0;
            while (answer_iter<answers)
            {
                ident = ((int)payload[index] << 8) + payload[index + 1];
                index += 2;
                int atype= ((int)payload[index] << 8) + payload[index + 1];
                index += 8;
                int lengthans = ((int)payload[index] << 8) + payload[index + 1];
                index += 2;
                if (atype==0x01)
                {
                    //hostname
                    if (lengthans == 0x04)
                    {
                        int iter = 0;
                        int ipint = 0;
                        string ips = "";
                        while (iter < lengthans)
                        {
                            ipint = ipint << 8;
                            ipint += payload[iter + index];
                            ips += payload[iter + index].ToString();
                            if (iter != lengthans - 1)
                                ips += ".";
                            iter++; 
                         
                        }
                        obj.IplistI.Add(ipint);
                        obj.IplistS.Add(ips);
                        obj.answercount++;
                        obj.Answertype.Add(atype);
                        
                        
                    }
                }
                index += lengthans;
                answer_iter++;
            }
            obj.index = index;
            return obj;
        }

        private static Servername getquerryname(byte[] payload, int index)
        {
            Servername obj = new Servername();   
            string querry="";
            while (payload[index] != 0)
            {
                int iter = 1;
                while (iter <= payload[index])
                {
                    querry += ((char)payload[index+iter]).ToString();
                    iter++;
                }
                index += iter;
                if (payload[index] != 0)
                    querry += ".";
                else
                    break;
              
            }
            obj.querry = querry;
            index += 1;
            obj.index = index;
            return obj;
        }
    }
}

