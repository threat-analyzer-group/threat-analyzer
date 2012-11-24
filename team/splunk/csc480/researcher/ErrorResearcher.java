package team.splunk.csc480.researcher;

import team.splunk.csc480.data.DataItem;
import team.splunk.csc480.handler.ThreatHandler;
import team.splunk.csc480.handler.ThreatHandler.*;


import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
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
   private static DateFormat dateFormat = new SimpleDateFormat("EEE MMM dd HH:mm:ss yyyy");

   public ErrorResearcher() { }

   @Override
   public void reportEvent(DataItem item) {
      Threat t = null;
      Pattern pat = Pattern.compile("\\[(warn|error|alert)\\]");
      Matcher match = pat.matcher(item.data);

      if (match.find() && match.groupCount() > 0) {
         Pattern ipPat = Pattern.compile("client (\\d+\\.\\d+\\.\\d+.\\d+)");
         Pattern datePat = Pattern.compile("[(\\w{3} \\w{3} \\d{2} \\d{2}:\\d{2}:\\d{2} \\d{4})]");
         Matcher ipMatch = ipPat.matcher(item.data);
         Matcher dateMatch = datePat.matcher(item.data);

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

         String date = (dateMatch.find() ? dateMatch.group(0) : "");
         long millis;

         try {
            millis = dateFormat.parse(date).getTime();
         }
         catch (ParseException e) {
            millis = 0L;
         }

         t = new Threat(ipAddress, millis, item, threatLevel);
         handler.reportThreat(t);
      }
   }
}
