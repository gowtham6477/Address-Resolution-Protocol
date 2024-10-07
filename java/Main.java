import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.*;
import java.text.SimpleDateFormat;
// ARP Table to store IP-MAC mappings with size limit and cache expiry
class ARPTable {
    private Map<InetAddress, ARPEntry> table;
    private static final long CACHE_TIMEOUT = 30000; // 30 seconds
    private static final int MAX_ENTRIES = 100; // Maximum entries in the ARP cache

    public ARPTable() {
        // LinkedHashMap with access-order to keep track of the oldest entry for eviction
        table = new LinkedHashMap<InetAddress, ARPEntry>(MAX_ENTRIES, 0.75f, true) {
            protected boolean removeEldestEntry(Map.Entry<InetAddress, ARPEntry> eldest) {
                return size() > MAX_ENTRIES; // Evict the oldest entry if table exceeds max size
            }
        };
    }

    public void addEntry(InetAddress ip, String mac) {
        ARPEntry entry = new ARPEntry(mac, System.currentTimeMillis());
        table.put(ip, entry);
        Logger.log("Added entry to ARP table: " + ip + " -> " + mac);
    }

    public String getMAC(InetAddress ip) {
        ARPEntry entry = table.get(ip);
        if (entry != null && !isEntryExpired(entry)) {
            return entry.getMac();
        }
        return null; // Entry not found or expired
    }

    private boolean isEntryExpired(ARPEntry entry) {
        return (System.currentTimeMillis() - entry.getTimestamp()) > CACHE_TIMEOUT;
    }

    // Remove expired entries from the ARP table
    public void removeExpiredEntries() {
        Iterator<Map.Entry<InetAddress, ARPEntry>> iterator = table.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<InetAddress, ARPEntry> entry = iterator.next();
            if (isEntryExpired(entry.getValue())) {
                Logger.log("Removed expired ARP entry for IP: " + entry.getKey());
                iterator.remove();
            }
        }
    }

    public Map<InetAddress, ARPEntry> getTable() {
        return table;
    }

    // ARPEntry class to store the MAC and timestamp of each entry
    static class ARPEntry {
        private String mac;
        private long timestamp;

        public ARPEntry(String mac, long timestamp) {
            this.mac = mac;
            this.timestamp = timestamp;
        }

        public String getMac() {
            return mac;
        }

        public long getTimestamp() {
            return timestamp;
        }
    }
}

// ARP Packet representing ARP requests and responses
class ARPPacket {
    private InetAddress senderIP;
    private String senderMAC;
    private InetAddress targetIP;
    private String targetMAC;
    private int opcode;

    public ARPPacket(InetAddress senderIP, String senderMAC, InetAddress targetIP, String targetMAC, int opcode) {
        this.senderIP = senderIP;
        this.senderMAC = senderMAC;
        this.targetIP = targetIP;
        this.targetMAC = targetMAC;
        this.opcode = opcode;
    }

    public InetAddress getSenderIP() {
        return senderIP;
    }

    public String getSenderMAC() {
        return senderMAC;
    }

    public InetAddress getTargetIP() {
        return targetIP;
    }

    public String getTargetMAC() {
        return targetMAC;
    }

    public int getOpcode() {
        return opcode;
    }
}

// ARP Simulator class handling ARP traffic and cache expiry
class ARPSimulator {
    private ARPTable arpTable;
    private ScheduledExecutorService executor;

    public ARPSimulator() {
        arpTable = new ARPTable();
        executor = Executors.newScheduledThreadPool(2);

        // Schedule ARP cache expiry check every 10 seconds
        executor.scheduleAtFixedRate(() -> arpTable.removeExpiredEntries(), 10, 10, TimeUnit.SECONDS);
    }

    public void sendARPRequest(InetAddress senderIP, String senderMAC, InetAddress targetIP) {
        ARPPacket packet = new ARPPacket(senderIP, senderMAC, targetIP, null, 1); // Opcode 1: ARP Request
        executor.execute(() -> processPacket(packet));
    }

    public void sendARPResponse(InetAddress senderIP, String senderMAC, InetAddress targetIP, String targetMAC) {
        ARPPacket packet = new ARPPacket(senderIP, senderMAC, targetIP, targetMAC, 2); // Opcode 2: ARP Response
        executor.execute(() -> processPacket(packet));
    }

    private void processPacket(ARPPacket packet) {
        simulateRandomDelay(); // Simulate network delay

        if (packet.getOpcode() == 1) { // ARP Request
            Logger.log("Received ARP request from " + packet.getSenderIP() + " for IP " + packet.getTargetIP());
            String targetMAC = arpTable.getMAC(packet.getTargetIP());
            if (targetMAC != null) {
                Logger.log("Sending ARP response for IP " + packet.getTargetIP());
                sendARPResponse(packet.getTargetIP(), targetMAC, packet.getSenderIP(), packet.getSenderMAC());
            } else {
                Logger.log("No ARP response sent for IP " + packet.getTargetIP() + " (not found in ARP table)");
            }
        } else if (packet.getOpcode() == 2) { // ARP Response
            Logger.log("Received ARP response from " + packet.getSenderIP() + " (" + packet.getSenderMAC() + ")");
            arpTable.addEntry(packet.getSenderIP(), packet.getSenderMAC());
        } else {
            Logger.log("Invalid opcode: " + packet.getOpcode());
        }
    }

    // Simulate random network delay between 100ms to 2 seconds
    private void simulateRandomDelay() {
        int delay = ThreadLocalRandom.current().nextInt(100, 2000); // Random delay
        try {
            Thread.sleep(delay);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        Logger.log("Simulated network delay of " + delay + " ms");
    }

    public ARPTable getArpTable() {
        return arpTable;
    }

    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(1, TimeUnit.MINUTES)) {
                executor.shutdownNow();
                if (!executor.awaitTermination(1, TimeUnit.MINUTES)) {
                    Logger.log("Executor did not terminate");
                }
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}

class Logger {
    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

    public static void log(String message) {
        System.out.println("[" + sdf.format(new Date()) + "] " + message);
    }
}

public class Main {
    public static void main(String[] args) throws UnknownHostException, InterruptedException {
        ARPSimulator simulator = new ARPSimulator();

        InetAddress senderIP = InetAddress.getByName("192.168.1.100");
        String senderMAC = "00:11:22:33:44:55";

        InetAddress targetIP = InetAddress.getByName("192.168.1.200");
        String targetMAC = "66:77:88:99:AA:BB";

        simulator.getArpTable().addEntry(targetIP, targetMAC);

        simulator.sendARPRequest(senderIP, senderMAC, targetIP);

        Thread.sleep(2000); 

        simulator.sendARPResponse(targetIP, targetMAC, senderIP, senderMAC);

        Thread.sleep(2000); 

  
        Logger.log("ARP table:");
        for (Map.Entry<InetAddress, ARPTable.ARPEntry> entry : simulator.getArpTable().getTable().entrySet()) {
            Logger.log(entry.getKey() + " -> " + entry.getValue().getMac());
        }

        simulator.sendARPRequest(senderIP, senderMAC, targetIP);
        Thread.sleep(1000); 
        Logger.log("ARP request lost");

        simulator.sendARPResponse(targetIP, targetMAC, senderIP, senderMAC);
        Thread.sleep(3000); 
        Logger.log("ARP response delayed");

        Thread.sleep(30000); 
        Logger.log("ARP cache timed out");

        simulator.sendARPRequest(senderIP, senderMAC, targetIP);

        Thread.sleep(2000); 

        Logger.log("ARP table after timeout:");
        for (Map.Entry<InetAddress, ARPTable.ARPEntry> entry : simulator.getArpTable().getTable().entrySet()) {
            Logger.log(entry.getKey() + " -> " + entry.getValue().getMac());
        }

        simulator.shutdown();
    }
}
