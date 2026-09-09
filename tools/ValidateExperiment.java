import core.*;
import applications.*;
import java.util.*;

/** Read-only audit of the actual Settings parser and instantiated network. */
public class ValidateExperiment {
    static void require(boolean ok, String why) {
        if (!ok) throw new AssertionError(why);
    }
    public static void main(String[] args) throws Exception {
        Settings.init(args[0]);
        Set<String> tuples = new HashSet<String>();
        Set<String> names = new HashSet<String>();
        int[] intervals = {1800,1200,600};
        long[] buffers = {5000,10000,20000,40000,80000};
        int[] counts = {80,6,4,6,4};
        boolean attack = args[0].contains("Malicious");
        for (int i=0;i<150;i++) {
            Settings.setRunIndex(i);
            Settings group = new Settings("Group");
            long buffer = group.getLong("bufferSize");
            int ttl = group.getInt("msgTtl");
            int interval = new Settings("SinkCCN").getInt("interval");
            int seed = new Settings("MovementModel").getInt("rngSeed");
            require(interval==intervals[i/50], "Interval ordering");
            require(buffer==buffers[(i/10)%5], "Buffer ordering");
            require(ttl==60*((i/2)%5+1), "TTL ordering");
            require(seed==i%2+1, "Seed ordering");
            String tuple = interval+","+buffer+","+ttl+","+seed;
            require(tuples.add(tuple), "Duplicate run "+i);
            Settings scenario = new Settings("Scenario");
            String name = scenario.valueFillString(scenario.getSetting("name"));
            require(names.add(name), "Filename collision");
            require(name.contains("_24h_") && scenario.getInt("endTime")==86400, "Duration/name");
            for (int j=1;j<=5;j++) {
                Settings g = new Settings("Group"+j);
                g.setSecondaryNamespace("Group");
                require(g.getInt("nrofHosts")==counts[j-1], "Group count");
                require(g.getLong("bufferSize")==buffer, "Inherited buffer override at group "+j);
                require(g.getInt("msgTtl")==ttl, "TTL mismatch");
                require(g.getSetting("router").equals(attack && j==5?"EpidemicRouter":"FirstContactRouter"), "Router mismatch");
                require(g.getSetting("movementModel").equals("ShortestPathMapBasedMovement"), "Movement override");
                require(Arrays.equals(g.getCsvDoubles("speed",2),new double[]{2.7,13.9}), "Speed override");
                require(Arrays.equals(g.getCsvDoubles("waitTime",2),new double[]{0,30}), "Wait override");
                require(g.getInt("nrofInterfaces")==1, "Interface override");
            }
            System.out.println((i+1)+" "+tuple+" "+name);
        }
        Settings.setRunIndex(0);
        Settings special = new Settings("Group5");
        require(special.getSetting("groupID").equals(attack ? "mS" : "nS"), "Group 5 prefix");
        require(special.contains("router")==attack, "Normal must inherit FirstContact; Attack must override router");
        SimScenario scenario = SimScenario.getInstance();
        List<DTNHost> hosts = scenario.getHosts();
        require(hosts.size()==100, "Runtime total");
        for (int i=0;i<100;i++) {
            DTNHost host = hosts.get(i);
            require(host.getAddress()==i, "Address allocation");
            require(host.getRouter().getClass().getSimpleName().equals(attack && i>=96?"EpidemicRouter":"FirstContactRouter"), "Runtime router");
            require(host.getRouter().getBufferSize()==5000, "Runtime buffer");
            if(i>=96) System.out.println("GROUP5_RUNTIME "+host+" address="+i+" router="+host.getRouter().getClass().getSimpleName());
            Collection<Application> apps = host.getRouter().getApplications(CCN_application.APP_ID);
            require(apps.size()==(i<80?0:1), "Runtime application count");
            if(i>=80) {
                Application app = apps.iterator().next();
                int mode = app instanceof CCN_application ? ((CCN_application)app).getMode() : ((MaliciousCCN_application)app).getMode();
                require(mode==(i<86?1:i<90?3:2), "Runtime mode");
                require((app instanceof MaliciousCCN_application)==(attack && i>=96), "Treatment allocation");
            }
        }
        CCN_application consumer = (CCN_application)hosts.get(80).getRouter().getApplications(CCN_application.APP_ID).iterator().next();
        java.lang.reflect.Method random = CCN_application.class.getDeclaredMethod("randomHost",DTNHost.class);
        random.setAccessible(true);
        Set<Integer> destinations = new TreeSet<Integer>();
        for (int i=0;i<1000;i++) {
            int address = ((DTNHost)random.invoke(consumer,hosts.get(80))).getAddress();
            require(address>=90 && address<100, "Destination out of range");
            destinations.add(address);
        }
        require(destinations.size()==10, "Destination coverage");
        System.out.println("PASS: 150 unique tuples, 150 unique report names; runtime 100 nodes, correct groups, routers, applications and buffers; destinations "+destinations);
    }
}
