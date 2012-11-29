package team.splunk.csc480.handler;

import team.splunk.csc480.data.DataItem;
import team.splunk.csc480.data.DataItem.*;
import team.splunk.csc480.researcher.Researcher;

/**
 * An interface for a class that handles threats. For an example, see the
 * Commander class.
 *
 * @see Commander
 * @author Team Splunk
 * @version 3.14
 * @date Nov. 13, 2012
 */
public interface ThreatHandler {

   /**
    * Threat level.
    */
   public static enum ThreatLevel {
      RED(10000), ORANGE(1000), YELLOW(100), GREEN(10), BLUE(1);

      public long severity;
      ThreatLevel(long severity) { this.severity = severity; }

      /**
       * Return the highest threat level less than or equal to score.
       *
       * @param score the score an IP address has attained
       * @return a threat level lte to score
       */
      public static ThreatLevel get(long score) {
         ThreatLevel curLevel = BLUE;

         for (ThreatLevel lev : ThreatLevel.values()) {
            if (score >= lev.severity && lev.severity > curLevel.severity)
               curLevel = lev;
         }

         return curLevel;
      }
   }

   /**
    * Stores an IP address and the threat level of that IP address, as well
    * as the total score it has attained.
    */
   public static class ThreatResult {
      public final IPAddress address;
      public final ThreatLevel level;
      public final long result;

      ThreatResult(IPAddress a, long r) {
         this.address = a;
         this.result = r;
         this.level = ThreatLevel.get(r);
      }

      @Override
      public String toString() {
         StringBuilder sb = new StringBuilder();

         sb.append("IP: ").append(address.toString());
         sb.append("; Level: ");
         sb.append(level).append("/").append(result);

         return sb.toString();
      }
   }

   /**
    * A threat. Has an IP Address and a threat level.
    */
   public static class Threat {
      public final IPAddress addr;
      public final long timeMillis;
      public final ThreatLevel level;
      public final DataItem item;

      /**
       * Create a new threat with a DataItem, threat level, and IP address.
       *
       * @param addr an IP address
       * @param d a DataItem
       * @param l the threat level
       */
      public Threat(String addr, long millis, DataItem d, ThreatLevel l) {
         this.addr = new IPAddress(addr);
         this.level = l;
         this.item = d;
         this.timeMillis = millis;
      }

      @Override
      public String toString() {
         StringBuilder sb = new StringBuilder();

         sb.append("IP: ").append(addr.toString());
         sb.append("; ").append(level.toString());
         sb.append("; ").append(item.toString());

         return sb.toString();
      }
   }

   /**
    * Receives threats from Researchers and does any required processing or
    * reporting on them.
    *
    * @param t the threat object to report to the ThreatHandler
    * @param key the key which identifies the Researcher, given at startup
    */
   public void reportThreat(Threat t, String key);
}
