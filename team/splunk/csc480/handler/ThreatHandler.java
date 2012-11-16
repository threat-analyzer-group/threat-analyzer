package team.splunk.csc480.handler;

import team.splunk.csc480.data.DataItem;
import team.splunk.csc480.data.DataItem.*;

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

      public int severity;
      ThreatLevel(int severity) { this.severity = severity; }
   }

   /**
    * A threat. Has an IP Address and a threat level.
    */
   public static class Threat {
      public final IPAddress addr;
      public final ThreatLevel level;
      public final DataItem item;

      /**
       * Create a new threat with a DataItem, threat level, and IP address.
       *
       * @param addr an IP address
       * @param d a DataItem
       * @param l the threat level
       */
      public Threat(String addr, DataItem d, ThreatLevel l) {
         this.addr = new IPAddress(addr);
         this.level = l;
         this.item = d;
      }
   }

   /**
    * Receives threats from Researchers and does any required processing or
    * reporting on them.
    *
    * @param t
    */
   public void reportThreat(Threat t);
}
