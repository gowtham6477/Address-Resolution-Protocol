import java.net.InetAddress;
import java.io.*;
import java.net.*;
import java.lang.*;
import java.net.NetworkInterface;
 import java.net.SocketException; 
 import java.util.Scanner;
import java.net.UnknownHostException; 
public class Arps
{
public static void main(String args[])
{
try
{
Scanner console=new Scanner(System.in); System.out.println("enter system name"); String
ipaddr=console.nextLine();
InetAddress address=InetAddress.getByName(ipaddr); System.out.println("address="+address);
NetworkInterface ni=NetworkInterface.getByInetAddress(address); if(ni!=null)
{
byte[] mac=ni.getHardwareAddress(); if(mac!=null)
{
System.out.println("MAC address:"); for(int i=0;i<mac.length;i++)
{
System.out.format("%02x%s", mac[i],(i<mac.length-1)?"-":"");
}
}
else
{
System.out.println("address doesn't exist or is not accessible/");
}
}
else
{
System.out.println("Network Interface for the specified address is not found");
}
}
catch(Exception e)
{
}
}
}