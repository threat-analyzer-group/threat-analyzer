package team.splunk.csc480.handler;

import team.splunk.csc480.data.DataItem;
import team.splunk.csc480.data.DataSource;
import team.splunk.csc480.data.HelloDataSource;
import team.splunk.csc480.researcher.GrumpyResearcher;
import team.splunk.csc480.researcher.Researcher;

import java.util.ArrayList;
import java.util.List;

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

   /**
    * Initializes the list of sources and researchers, then sets itself to be
    * the ThreatHandler for each Researcher.
    *
    * @param researchers the list of Researchers to run on the data
    * @param sources the list of sources to receive events and forward them to each researcher
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
    * Stop all DataSources.
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
   public void reportThreat(Threat t) {
      System.out.println(t.toString());
   }

   /**
    * Receives events from DataSources and broadcasts them to all Researchers.
    *
    * @param item the DataItem to broadcast
    */
   @Override
   public void broadcastEvent(DataItem item) {
      for (Researcher r : researchers)
         r.reportEvent(item);
   }

   /**
    * Main method
    */
   public static void main(String[] args) {
      List<Researcher> researchers = new ArrayList<Researcher>();
      List<DataSource> sources = new ArrayList<DataSource>();

      researchers.add(new GrumpyResearcher());

      sources.add(new HelloDataSource());

      try {
         Commander shepard = new Commander(researchers, sources);
         shepard.start();
         Thread.sleep(10000);
         shepard.stop();
      }
      catch (Exception e) {
         System.err.println("ERROR!!");
         e.printStackTrace();
      }
   }
}
