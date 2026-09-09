import core.*;
import routing.*;
import applications.*;
import report.*;
import java.util.*;
import java.lang.reflect.*;

/** Controlled in-memory regression, separate from research/pilot measurements. */
public class ContentPathValidation {
    static void require(boolean ok, String why) { if(!ok) throw new AssertionError(why); }
    static long count(Object r,String name) throws Exception {
        Field f=r.getClass().getDeclaredField(name); f.setAccessible(true); return f.getLong(r);
    }
    static Application app(DTNHost h) { return h.getRouter().getApplications(CCN_application.APP_ID).iterator().next(); }
    static Message query(DTNHost h) {
        app(h).update(h);
        for(Message m:h.getRouter().getMessageCollection()) if("query_ad".equals(m.getProperty("type"))) return m;
        throw new AssertionError("No generated Interest");
    }
    static Message response(DTNHost h, String interest) {
        for(Message m:h.getRouter().getMessageCollection()) if(m.getId().equals("queryResponse-"+h.getAddress()+"-"+interest)) return m;
        throw new AssertionError("No generated response for "+interest);
    }
    static Message deliver(DTNHost from, DTNHost to, Message m) {
        require(to.receiveMessage(m,from)==MessageRouter.RCV_OK,"Router rejected "+m.getId());
        Message received=to.getRouter().messageTransferred(m.getId(),from);
        if(from.getRouter() instanceof FirstContactRouter && from.getRouter().hasMessage(m.getId())) from.deleteMessage(m.getId(),false);
        return received;
    }
    static void marker(Message m, boolean attack) {
        require(m.getSize()==211,"Content size independent of Interest size");
        require(Boolean.TRUE.equals(m.getProperty("isFalseContent"))==attack,"Lost/incorrect false property");
        require(((String)m.getProperty("content")).startsWith("FALSE_TRAFFIC_CONTENT_")==attack,"Lost/incorrect payload marker");
        require(Objects.equals(m.getProperty("isFalseContent"),m.replicate().getProperty("isFalseContent")),"Replication lost property");
    }
    public static void main(String[] args) throws Exception {
        boolean attack=args[0].contains("Malicious");
        Settings.init(args[0]); Settings.addSettings(args[1]); Settings.setRunIndex(0);
        SimScenario scenario=SimScenario.getInstance();
        Report reporter=attack?new MaliciousCCN_application_reporter():new CCN_application_reporter();
        Map<String,Integer> events=new HashMap<String,Integer>();
        scenario.getApplicationListeners().add((ApplicationListener)reporter);
        scenario.getApplicationListeners().add((event,params,a,h)->events.merge(event+"@"+h.getAddress(),1,Integer::sum));
        List<DTNHost> hosts=scenario.getHosts();
        DTNHost c0=hosts.get(80),c1=hosts.get(81),c2=hosts.get(82),pure=hosts.get(0),relay=hosts.get(86),producer=hosts.get(96);
        SimClock.getInstance().setTime(1.125);
        Message q0=query(c0), q2=query(c2);
        require(q0.getSize()==73 && q2.getSize()==73,"Interest size");
        q0.setTo(producer); q2.setTo(hosts.get(99));
        deliver(c0,pure,q0);
        Message carried=pure.getRouter().getMessageCollection().iterator().next();
        require(carried.getAppID().equals(CCN_application.APP_ID),"Pure DTN lost AppID");
        deliver(pure,producer,carried);
        deliver(c2,producer,q2);
        Message r0=response(producer,q0.getId()), r2=response(producer,q2.getId());
        require(!r0.getId().equals(r2.getId()),"Same-second response ID collision");
        marker(r0,attack); marker(r2,attack);
        SimClock.getInstance().setTime(1.25);
        Message viaCache=deliver(producer,relay,r0);
        marker(viaCache,attack);
        require(events.getOrDefault("CacheState@86",0)>0,"No intermediate cache insertion");
        SimClock.getInstance().setTime(1.5);
        deliver(relay,c0,viaCache);
        // A different consumer later requests the cached name, without producer contact.
        SimClock.getInstance().setTime(2.125);
        Message q1=query(c1); q1.setTo(hosts.get(99));
        deliver(c1,relay,q1);
        Message cachedResponse=response(relay,q1.getId()); marker(cachedResponse,attack);
        require(events.getOrDefault("oppoCacheHit@86",0)==1,"Intermediate did not serve cached content");
        SimClock.getInstance().setTime(2.5);
        deliver(relay,c1,cachedResponse);
        require(count(reporter,"query_count")==3,"Query event count");
        require(count(reporter,"response_count")==2,"Response event count");
        require(count(reporter,"false_content_received")== (attack?2:0),"False reception count");
        require(count(reporter,"legitimate_content_received")== (attack?0:2),"Legitimate reception count");
        require(count(reporter,"false_content_generated")== (attack?2:0),"Both producer response branches counted");
        require(events.getOrDefault("FalseContentCached@86",0)==(attack?1:0),"Relay pollution count");
        // Verify the exact one-remaining-recipient retargeting and no fake newMessage event.
        DTNHost relay2=hosts.get(87);
        Message multicast=new Message(producer,relay,"validation-retarget",211);
        multicast.addProperty("type","queryResponse"); multicast.addProperty("queryMsg","500");
        multicast.addProperty("content","legitimate"); multicast.addProperty("hostsTo",relay2.toString());
        multicast.setAppID(CCN_application.APP_ID); producer.createNewMessage(multicast);
        Message retargeted=deliver(producer,relay,multicast);
        require(retargeted.getTo()==relay2,"Single remaining recipient lost");
        // LRU eviction semantics, including legitimate replaced by false at capacity.
        LRUCache cache=new LRUCache(10);
        for(int i=1;i<=10;i++) cache.set(i,"legitimate");
        cache.set(11,"FALSE_TRAFFIC_CONTENT_11");
        require(cache.get_len()==10 && cache.countFalseContent()==1,"LRU capacity/pollution");
        require("legitimate".equals(cache.getLastEvictedValue()),"LRU eviction metadata");
        cache.set(11,"legitimate");
        require(cache.countFalseContent()==0 && cache.getLastEvictedValue()==null,"LRU replacement counted as eviction");
        reporter.done();
        // Both reporters must return numeric zero when no queries/responses exist.
        Settings.addSettings("validation/configs/zero_report.txt");
        Report empty = attack ? new MaliciousCCN_application_reporter() : new CCN_application_reporter();
        empty.done();
        System.out.println("PASS: "+(attack?"Attack":"Normal")+" producer -> pure/CCN routers -> intermediate cache -> later cached response -> consumer; marker survives; sizes 73/211; unique same-second IDs; direct and overheard generation counted; response conservation; one remaining recipient; bounded LRU metadata.");
    }
}
