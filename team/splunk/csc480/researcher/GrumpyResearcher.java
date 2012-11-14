package team.splunk.csc480.researcher;

import team.splunk.csc480.data.DataItem;
import team.splunk.csc480.handler.ThreatHandler;
import team.splunk.csc480.handler.ThreatHandler.*;

/**
 * A test Researcher that simply takes every log event and reports a Level
 * Red threat to the ThreatHandler.
 *
 * @author Team Splunk
 * @version 3.14
 * @date Nov. 13, 2012
 */
public class GrumpyResearcher implements Researcher {
   private ThreatHandler handler;

   public GrumpyResearcher() { }

   @Override
   public void setThreatHandler(ThreatHandler handler) { this.handler = handler; }

   @Override
   public void reportEvent(DataItem item) {
      Threat t = new Threat("0.0.0.0", item, ThreatLevel.RED);
      handler.reportThreat(t);
   }
}