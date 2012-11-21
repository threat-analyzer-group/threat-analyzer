package team.splunk.csc480.researcher;

import team.splunk.csc480.data.DataItem;
import team.splunk.csc480.handler.ThreatHandler;
import team.splunk.csc480.handler.ThreatHandler.*;


import java.util.HashMap;

/**
 * Analyzes DataItems, looking for "warn", "error", etc.
 */
public class ErrorResearcher implements Researcher{
   private ThreatHandler handler;

   private static final HashMap<String, ThreatHandler.ThreatLevel> APACHEMAPPINGS = new HashMap<String, ThreatHandler.ThreatLevel>(){
      {
         put("warn", ThreatLevel.YELLOW);
         put("error", ThreatLevel.ORANGE);
         put("alert", ThreatLevel.RED);
      }
   };

   public ErrorResearcher() {

   }

   @Override
   public void setThreatHandler(ThreatHandler handler) {
      this.handler = handler;
   }

   @Override
   public void reportEvent(DataItem item) {
      Threat t = null;

      //The below is just a place holder. I need to determine the layout of the DataItem data before
      //I can actually make something useful. 
      for (String error : APACHEMAPPINGS.keySet()){
         if (item.data.containsKey(error)){
            t = new Threat("0.0.0.0", item, APACHEMAPPINGS.get(error));
         }
      }
      if (t != null){
         handler.reportThreat(t);
      }
   }
}
