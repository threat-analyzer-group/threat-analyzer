package team.splunk.csc480.researcher;

import team.splunk.csc480.data.DataItem;
import team.splunk.csc480.handler.ThreatHandler;

/**
 * A class that receives (possibly) asynchronous events as DataItems and
 * analyzes them accordingly.
 *
 * @author Team Splunk
 * @version 3.14
 * @date Nov. 13, 2012
 */
public abstract class Researcher {
   protected ThreatHandler handler;
   protected String key;

   protected Researcher(String key) { this.key = key; }

   /**
    * Sets the ThreatHandler for this Researcher to handler. This method must
    * be called (presumably by the ThreatHandler) before any reporting can be
    * done.
    *
    * @param handler the ThreatHandler to use when reporting threats
    */
   public void setThreatHandler(ThreatHandler handler) {
      this.handler = handler;
   }

   /**
    * Any class can call this method and pass a DataItem that can be
    * analyzed by this researcher. This method will be available to a
    * multithreaded environment, so you should synchronize this method if you
    * are editing any instance variables.
    *
    * @param item a DataItem to analyze
    */
   public abstract void reportEvent(DataItem item);

   /**
    * Calls the reportThreat(...) function in this Researcher's ThreatHandler
    * with the key given by the ThreatHandler
    *
    * @param threat the Threat to send
    */
   public void reportThreat(ThreatHandler.Threat threat) {
      handler.reportThreat(threat, key);
   }
}
