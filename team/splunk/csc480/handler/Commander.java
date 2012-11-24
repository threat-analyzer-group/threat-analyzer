package team.splunk.csc480.handler;

import team.splunk.csc480.data.DataItem;
import team.splunk.csc480.data.DataItem.*;
import team.splunk.csc480.data.DataSource;
import team.splunk.csc480.data.FileDataSource;
import team.splunk.csc480.researcher.ErrorResearcher;
import team.splunk.csc480.researcher.FrequentAccessResearcher;
import team.splunk.csc480.researcher.GrumpyResearcher;
import team.splunk.csc480.researcher.Researcher;

import java.io.FileNotFoundException;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Starts all available Researchers in a new thread and gives them a callback
 * to use when reporting security threats.
 *
 * @author Team Splunk
 * @version 3.14
 * @date Nov. 13, 2012
 */
public class Commander implements ThreatHandler, Broadcaster {
   private List<DataSource> sources = new ArrayList<DataSource>();
   private List<Researcher> researchers = new ArrayList<Researcher>();

   private Map<IPAddress, Integer> levels = new HashMap<IPAddress, Integer>();
   private static final int DEFAULT_OFFENDERS = 10;

   private static final String QUIT_PATTERN = "(?i)(q$|quit$)";
   private static final String VIEW_PATTERN = "(?i)(v$|view$)";

   /**
    * Initializes the list of sources and researchers, then sets itself to be
    * the ThreatHandler for each Researcher.
    *
    * @param researchers the list of Researchers to run on the data
    * @param sources the list of sources to receive events and forward them to
    *                each researcher
    */
   public Commander(List<Researcher> researchers, List<DataSource> sources) {
      this.researchers = researchers;
      this.sources = sources;

      for (Researcher r : researchers) {
         r.setThreatHandler(this);
      }

      for (DataSource ds : sources) {
         ds.setBroadcaster(this);
      }
   }

   /**
    * Start/resume all of the DataSources and run for 30 secs.
    */
   public void start() {
      for (DataSource source : sources) {
         source.startThread();
      }
   }

   /**
    * Stop all DataSource.
    */
   public void stop() {
      for (DataSource source : sources) {
         source.stopNow();
      }
   }

   /**
    * Receives threats from Researchers and does any required processing or
    * reporting on them.
    *
    * @param t a threat from a Researcher
    */
   public synchronized void reportThreat(Threat t) {
      Integer threat = levels.get(t.addr);
      levels.put(t.addr, ((threat != null) ? threat : 0) + t.level.severity);

      System.out.println(t.toString());
   }

   /**
    * Receives events from DataSources and broadcasts them to all Researchers.
    *
    * @param item the DataItem to broadcast
    */
   @Override
   public synchronized void broadcastEvent(DataItem item) {
      for (Researcher r : researchers)
         r.reportEvent(item);
   }

   /**
    * Returns a list of the n worst offenders, where n = DEFAULT_OFFENDERS,
    * and their scores
    *
    * @return a list of ThreatResults
    */
   public List<ThreatResult> getWorstOffenders() {
      return getWorstOffenders(DEFAULT_OFFENDERS);
   }

   /**
    * Returns a list of the `num` worst offenders and their scores
    *
    * @param num the number of offenders to return
    * @return a list of ThreatResults
    */
   public synchronized List<ThreatResult> getWorstOffenders(int num) {
      List<ThreatResult> offenders = new ArrayList<ThreatResult>(num);

      for (IPAddress addr : levels.keySet()) {
         offenders.add(new ThreatResult(addr, levels.get(addr)));
      }

      Collections.sort(offenders, new Comparator<ThreatResult>() {
         @Override
         public int compare(ThreatResult o1, ThreatResult o2) {
            return o1.result - o2.result;
         }
      });

      return offenders.subList(0,
        (num < offenders.size()) ? num : offenders.size());
   }

   /**
    * Main method
    */
   public static void main(String[] args) {
      List<Researcher> researchers = new ArrayList<Researcher>();
      List<DataSource> sources = new ArrayList<DataSource>();

      try {
         researchers.add(new ErrorResearcher());
         researchers.add(new FrequentAccessResearcher());
         sources.add(new FileDataSource("error_log"));
         sources.add(new FileDataSource("access_log"));
      }
      catch (FileNotFoundException e) {
         e.printStackTrace();
      }

      Commander shepard = new Commander(researchers, sources);

      try {
         String input;
         Scanner sysIn = new Scanner(System.in);
         shepard.start();

         Pattern quit = Pattern.compile(QUIT_PATTERN);
         Pattern view = Pattern.compile(VIEW_PATTERN);

         while ((input = sysIn.nextLine()) != null) {
            if (quit.matcher(input).find())
               break;
            else if (view.matcher(input).find()) {
               List<ThreatResult> results = shepard.getWorstOffenders();
               System.out.println("CURRENT STATS:");

               for (ThreatResult res : results) {
                  System.out.println(res.toString());
               }
            }
         }
      }
      catch (Exception e) {
         System.err.println("ERROR!!");
         e.printStackTrace();
      }
      finally {
         shepard.stop();
      }
   }
}
