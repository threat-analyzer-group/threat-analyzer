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
      Pattern errorMessagePattern = Pattern.compile("\\[(warn|error|alert)\\]");
      Matcher errorMessageMatch = errorMessagePattern.matcher(item.data);

      Pattern errorCodePattern = Pattern.compile("([4|5]\\d{2}) -|\\d+$");
      Matcher errorCodeMatch = errorCodePattern.matcher(item.data);

      //Handle [warn] | [error] | [alert] in the error_log
      if (errorMessageMatch.find() && errorMessageMatch.groupCount() > 0) {
         Pattern ipPat = Pattern.compile("client (\\d+\\.\\d+\\.\\d+.\\d+)");
         Matcher ipMatch = ipPat.matcher(item.data);

         String ipAddress = ipMatch.find() ? ipMatch.group(1) : "";

         String message = errorMessageMatch.group(1);
         ThreatLevel threatLevel = null;

         if (message.equals("alert")) {
           threatLevel = ThreatLevel.YELLOW;
         }
         else if (message.equals("warn")) {
            threatLevel = ThreatLevel.ORANGE;
         }
         else if (message.equals("error")) {
            threatLevel = ThreatLevel.RED;
         }

         if (threatLevel != null) {
            t = new Threat(ipAddress, getTime(item), item, threatLevel);
            handler.reportThreat(t);
         }
      }
      //Handle error codes at the end of the access_log.
      else if (errorCodeMatch.find() && errorCodeMatch.groupCount() > 0) {
         Pattern ipPat = Pattern.compile("^\\d+.\\d+.\\d+.\\d+");
         Matcher ipMatch = ipPat.matcher(item.data);

         String ipAddress = ipMatch.groupCount() > 0 ? ipMatch.group(1) : "";

         String errorCode = errorCodeMatch.group(1);

         t = new Threat(ipAddress, getTime(item), item, ThreatLevel.ORANGE);
         handler.reportThreat(t);
      }
   }

   private long getTime(DataItem item) {
      Pattern datePat = Pattern.compile("[(\\w{3} \\w{3} \\d{2} \\d{2}:\\d{2}:\\d{2} \\d{4})]");
      Matcher dateMatch = datePat.matcher(item.data);

      String date = (dateMatch.find() ? dateMatch.group(0) : "");
      long millis;

      try {
         millis = dateFormat.parse(date).getTime();
      }
      catch (ParseException e) {
         millis = 0L;
      }

      return millis;
   }
}
