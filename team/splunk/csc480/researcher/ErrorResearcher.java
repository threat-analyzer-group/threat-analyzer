package team.splunk.csc480.researcher;

import team.splunk.csc480.data.DataItem;
import team.splunk.csc480.handler.ThreatHandler;
import team.splunk.csc480.handler.ThreatHandler.*;


import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyzes DataItems, looking for "warn", "error", etc.
 * @author Team Splunk (Austin Dworaczyk Wiltshire)
 * @version 1.0
 * @date November 20th, 2012
 */
public class ErrorResearcher extends Researcher {

   public ErrorResearcher() { }

   @Override
   public void reportEvent(DataItem item) {
      Threat t = null;
      Pattern pat = Pattern.compile("\\[(warn|error|alert)\\]");
      Matcher match = pat.matcher(item.data);

      if (match.find() && match.groupCount() > 0) {
         Pattern ipPat = Pattern.compile("client (\\d+\\.\\d+\\.\\d+.\\d+)");
         Matcher ipMatch = ipPat.matcher(item.data);

         String ipAddress = ipMatch.find() ? ipMatch.group(1) : "";

         String message = match.group(1);
         ThreatLevel threatLevel = ThreatLevel.BLUE;

         if (message.equals("alert")) {
           threatLevel = ThreatLevel.YELLOW;
         }
         else if (message.equals("warn")) {
            threatLevel = ThreatLevel.ORANGE;
         }
         else if (message.equals("error")) {
            threatLevel = ThreatLevel.RED;
         }

         t = new Threat(ipAddress, item, threatLevel);
         handler.reportThreat(t);
      }
   }
}
