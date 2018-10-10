package translator;

/* Author:		Aaron Parks
 * Course:		CSS 519 - Incident Response and Recovery
 * Date/Time:	31 May 2014 @ 14:30
 * Version:		v3.1
 * 
 * Description:
 * Will capture packets from a selected network device and parse the packet headers into various
 * "containers" to be output to an ARFF file and later directly to a Weka handler class for a
 * *.model file.
 * 
 * The output to the ARFF file and the output to the Weka handler class will follow this format:
 *   0 Record Number
 *   1 Average Packet Time (within the context of the capture window)
 *   2 Number of instances of the most common source
 *   3 Number of instances of the second most common source
 *   4 Number of instances of the third most common source
 *   5 ARP packet count
 *   6 DNS packet count*
 *   7 DHCP packet count*
 *   8 HTML packet count
 *   9 ICMP packet count
 *  10 TCP packet count
 *  11 UDP packet count
 *  (*No class for this packet type in 'jNetPcap' library)
 */

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.application.Html;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class Translator {
	
	public static void main(String[] args) {
		final int DURATION = 15*1000;			//length of capture time (currently 15 seconds)
		
		//list to store network devices on this system
		List<PcapIf> deviceList = new ArrayList<PcapIf>();
		//buffer for error messages
		StringBuilder errorBuffer = new StringBuilder();
		
		//get list of devices on this system
		int r = Pcap.findAllDevs(deviceList, errorBuffer);
		if (r == Pcap.NOT_OK || deviceList.isEmpty()) {
			System.err.printf("Can't read device list!\nError: %s", errorBuffer.toString());
			return;
		}
		
		//device search successful!
		System.out.println("Network devices found:");
		
		//display all devices on system and their descriptions
		for (int i = 0; i < deviceList.size(); i++) {
			String description = (deviceList.get(i).getDescription() != null) ? deviceList.get(i).getDescription() : "No description available";
			System.out.printf("Device #%d: %s [%s]\n",i, deviceList.get(i).getName(), description);
		}
		
		//select device to perform capture //device 2 on 'YUZUKI'is the wireless adaptor
		PcapIf device  = deviceList.get(2);
		System.out.printf("\nDevice #%s '%s' selected by default:\n", 2, device.getDescription());
		
		int snaplen = 64 * 1024;				//capture all packets; no truncation
		int mode = Pcap.MODE_PROMISCUOUS;		//capture all the packets on the interface
		int timeout = 5*1000;					//length of capture (currently 5 seconds)
		
		//open chosen device
		//Note: replace 'device.getName()' with 'NULL' to capture on all devices (!! does NOT work in promiscuous mode)
		final Pcap pcap = Pcap.openLive(device.getName(), snaplen, mode, timeout, errorBuffer);
		
		if (pcap == null) {
			System.err.printf("Error opening '%s' for capture\nError: %s",device.getName(), errorBuffer.toString());
		}

		/*** JPacketHandler (pcap.loop) ****
		 * 
		 * 
		 ************************************************************************************************************/
		PcapPacketHandler<String> jPacketHandler = new PcapPacketHandler<String>() {
			//constant variables
			final int W_SIZE = 500;			//capture window size (in milliseconds)
			final int S_SIZE = 10;			//elements in source arrays
			final int S_TOP = 3;			//used to sort three most common sources
			
			//create and instantiate protocol objects
			final Arp arp = new Arp();
			final Html html = new Html();
			final Icmp icmp = new Icmp();
			final Tcp tcp = new Tcp();
			final Udp udp = new Udp();
			final Ip4 ip4 = new Ip4();
			final Ip6 ip6 = new Ip6();
			
			//packet counters
			int arp_count = 0;				//counter for ARP packets
			int html_count = 0;				//counter for HTML packets (possibly HTML/XML packets)
			int icmp_count = 0;				//counter for ICMP packets //needs to implement ICMPv6, IGMP, IGMPv2
			int tcp_count = 0;				//counter for TCP packets
			int udp_count = 0;				//counter for UDP packets //need to implement MDNS (if possible)
			int unk_count = 0;				//counter for all other packet types
			int packetsByProtocol = 0;		//packet counter in packet type 'if/else' statement
			int packetsByIp = 0;			//packet counter in IP type 'if/else' statement
			
			int record = 0;					//number of records generated //this variable will not be cleared at loop exit
			long captureStart = 0;			//loop start time (will be equal to the timestamp of the first packet captured in the loop
			long packetTime = 0;			//timestamp of packet
			
			//variables for handling packet source
			String s_name[] = new String[S_SIZE];
			int s_count[] = new int[S_SIZE];
			
			//parse packet headers
			public void nextPacket(PcapPacket packet, String user) {
				//set loop start time
				if (captureStart == 0) {
					//loop start time (captureStart) is set as the timestamp of the first packet
					//this is because packetTime is already recorded before captureStart time can be set resulting in a negative value
					//   when loop time is calculated
					captureStart = packetTime = packet.getCaptureHeader().timestampInMillis();
				}
				else {
					packetTime = packet.getCaptureHeader().timestampInMillis();	
				}

				//CHECK FOR PCAP.LOOP EXIT CONDITION
				if ((packetTime - captureStart) >= W_SIZE) {
					//prepare collected data to be written as record to ARFF file
					//sort source arrays
					for (int i = 0; i <= S_TOP; i++) {
						for (int j = i+1; j < S_SIZE; j++) {
							if (s_count[i] < s_count[j]) {
								//swap strings
								String temps = s_name[i];
								s_name[i] = s_name[j];
								s_name[j] = temps;
								//swap integers
								int tempi = s_count[i];
								s_count[i] = s_count[j];
								s_count[j] = tempi;
							}
						}
					}
					//display capture summary //!! to be replace by output to ARFF file.
					//this is the data that will appear in the ARFF file
					double timeHolder = (double)(System.currentTimeMillis()-captureStart)/1000;
					System.out.printf("\nRECORD #%s\n", ++record);
					System.out.printf("TIME ELAPSED=  %s\n", timeHolder);
					System.out.printf("TOTAL PACKETS= %s\n", packetsByProtocol);
					System.out.printf("AVG TIME=      %s\n", BigDecimal.valueOf(timeHolder/packetsByProtocol).setScale(3, RoundingMode.HALF_UP));
					System.out.println("SOURCE SUMMARY\n---------------");
					for (int i = 0; i < S_TOP; i++) {
						System.out.printf("  %s  Count= %s\n", s_name[i], s_count[i]);
					}
					System.out.printf("PACKET SUMMARY\n---------------\n  ARP=  %s\n  HTML= %s\n  ICMP= %s\n  TCP=  %s\n  UDP=  %s\n  UNK=  %s\n", arp_count, html_count, icmp_count, tcp_count, udp_count, unk_count);
					System.out.printf("========= \n  Protocol Count= %s\n  IP Count=       %s\n",packetsByProtocol, packetsByIp);
					System.out.printf("**** END CAPTURE WINDOW @ TIME %s ****\n\n",new Date(System.currentTimeMillis()));
					//clear arrays and variables
					//necessary because 'pcap.loop' method retains the values even when loop is broken
					Arrays.fill(s_name, null);
					Arrays.fill(s_count, 0);
					captureStart = arp_count = html_count = icmp_count = tcp_count = udp_count = unk_count = packetsByProtocol = packetsByIp = 0;
					pcap.breakloop();
				}
				else {
					//HANDLE PACKET SOURCE
					if (packet.hasHeader(ip4)) {
						//get byte array of source
						System.out.println("-> IPv4");
						//read 'source' string then add to array or increment counter if already exists
						for (int i = 0; i < S_SIZE; i++) {
							if (s_name[i] == null) {
								s_name[i] = org.jnetpcap.packet.format.FormatUtils.ip(ip4.source());
								s_count[i]++;
								break;
							}
							if (s_name[i].equalsIgnoreCase(org.jnetpcap.packet.format.FormatUtils.ip(ip4.source()))) {
								s_count[i]++;
								break;
							}
						}
						packetsByIp++;
					}
					//!! causes an "OutOfMemory" exception (out of heap space)
					else if (packet.hasHeader(ip6)) {
						System.out.println("-> IPv6");
						String ip6source = org.jnetpcap.packet.format.FormatUtils.ip(ip6.source());
						System.out.printf("-> Source= %s\n", ip6source);
						packetsByIp++;
					}
					
					//HANDLE PACKET PROTOCOL
					if (packet.hasHeader(arp)) {
						//System.out.printf("  PROTOCOL: ARP   Time=  %s\n", (double)(packetTime - captureStart)/1000);
						arp_count++;
						packetsByProtocol++;
					}
					else if (packet.hasHeader(html)) {
						//System.out.printf("  PROTOCOL: HTML   Time= %s\n", (double)(packetTime - captureStart)/1000);
						html_count++;
						packetsByProtocol++;
					}
					else if (packet.hasHeader(icmp)) {
						//System.out.printf("  PROTOCOL: ICMP   Time= %s\n",(double)(packetTime - captureStart)/1000);
						icmp_count++;
						packetsByProtocol++;
					}
					else if (packet.hasHeader(tcp)) {
						//System.out.printf("  PROTOCOL: TCP   Time=  %s\n",(double)(packetTime - captureStart)/1000);
						tcp_count++;
						packetsByProtocol++;
					}
					else if (packet.hasHeader(udp)) {
						//System.out.printf("  PROTOCOL: UDP   Time=  %s\n",(double)(packetTime - captureStart)/1000);
						udp_count++;
						packetsByProtocol++;
					}
					else { //packet has unknown header
						//System.out.printf("  PROTOCOL: UNK   Time=  %s\n", (double)(packetTime - captureStart)/1000);
						unk_count++;
						packetsByProtocol++;
					}
				}
				
			}
		}; //*** END 'PcapPacketHandler<String>'
		
		/**** PACKET CAPTURE LOOP *****
		 * Will continuously loop through the while loop until a pre-defined duration of time has expired. The pcap
		 * 'loop' method acts as a pseudo-timer that will exit once a pre-defined duration of time has expired.
		 ************************************************************************************************************/
		long currentTime = System.currentTimeMillis();
		while ((System.currentTimeMillis() - currentTime) < DURATION) {
			System.out.printf("**** BEGIN CAPTURE WINDOW @ TIME %s ****\n", new Date(System.currentTimeMillis()));
			pcap.loop(Pcap.LOOP_INFINITE, jPacketHandler, "THISISATEST");
			System.gc();
		}
		System.out.println("********************\n* Capture Complete *\n********************");
		
		//close pcap handle
		pcap.close();
	}
}