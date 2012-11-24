package team.splunk.csc480.researcher;

import team.splunk.csc480.data.DataItem;
import team.splunk.csc480.handler.ThreatHandler;
import team.splunk.csc480.handler.ThreatHandler.*;


import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

/**
 * Analyzes DataItems, looking for "warn", "error", etc.
 * @author Team Splunk (Halli Meth, Daniel Crawford)
 * @version 1.0
 * @date November 23th, 2012
 */
public class FrequentAccessResearcher extends Researcher {
   private HashMap<String, ArrayList<Date>> accesses;
   
   private static final int kRange = 30000;
   private static final int kYellow = 5;
   private static final int kOrange = 10;
   private static final int kRed = 15;
   
   public FrequentAccessResearcher() {
      accesses = new HashMap<String, ArrayList<Date>>();
   }

   @Override
   public void reportEvent(DataItem item) {
	  Threat t = null;
	  String ipAddress = "";
	  String time = "";
	  DateFormat df = null;
	  
      if (item.fromFile.equals("access_log")) {
         Pattern ipPat = Pattern.compile("\\d+\\.\\d+\\.\\d+.\\d");
         Matcher ipMatch = ipPat.matcher(item.data);

         ipAddress = ipMatch.find() ? ipMatch.group(0) : "";

         Pattern timePat = Pattern.compile("\\d+/[A-Z][a-z][a-z]/\\d+:\\d+:\\d+:\\d+");
         Matcher timeMatch = timePat.matcher(item.data);

         time = timeMatch.find() ? timeMatch.group(0) : "";
         df = new SimpleDateFormat("dd/MMM/yyyy:hh:mm:ss");
      }
      else if (item.fromFile.equals("error_log")) {
    	  Pattern ipPat = Pattern.compile("client (\\d+\\.\\d+\\.\\d+.\\d+)");
          Matcher ipMatch = ipPat.matcher(item.data);

          ipAddress = ipMatch.find() ? ipMatch.group(1) : "";

          Pattern timePat = Pattern.compile("[A-Z][a-z][a-z] [A-Z][a-z][a-z] \\d+ \\d+:\\d+:\\d+ \\d+");
          Matcher timeMatch = timePat.matcher(item.data);

          time = timeMatch.find() ? timeMatch.group(0) : "";
          if (time.length() >= 4)
             time = time.substring(4);
          df = new SimpleDateFormat("MMM dd hh:mm:ss yyyy");
      }
      
      try {
          Date curTime = df.parse(time);
          if (accesses.containsKey(ipAddress)) {
             accesses.get(ipAddress).add(curTime);
          }
          else {
             ArrayList<Date> timeList = new ArrayList<Date>();
             timeList.add(curTime);
             accesses.put(ipAddress, timeList);
          }
       } catch (Exception e) {
          return;
      }
         
      ThreatLevel threatLevel = ThreatLevel.BLUE;
         
      long first = accesses.get(ipAddress).get(0).getTime();
      long last = accesses.get(ipAddress).get(accesses.get(ipAddress).size()-1).getTime();
         
      if ((last - first) < kRange) {
      	 int numThreats = accesses.get(ipAddress).size();
       	 if (numThreats >= kRed) {
            threatLevel = ThreatLevel.RED;
        	 accesses.remove(ipAddress);
         }
         else if (numThreats >= kOrange) {
            threatLevel = ThreatLevel.ORANGE;
         }
         else if (numThreats >= kYellow) {
        	threatLevel = ThreatLevel.YELLOW; 
         }
       }

       if (threatLevel != ThreatLevel.BLUE) {
         t = new Threat(ipAddress, last, item, threatLevel);
         handler.reportThreat(t);
       }
   }
}
