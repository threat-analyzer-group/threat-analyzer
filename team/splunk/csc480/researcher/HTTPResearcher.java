package team.splunk.csc480.researcher;

import team.splunk.csc480.data.DataItem;
import team.splunk.csc480.handler.ThreatHandler.*;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class HTTPResearcher extends Researcher {
  /**
   * The Knowledge Base contains signatures of known HTTP attacks
   */
  protected static KnowledgeBase kb;

  protected HTTPResearcher(String key) {
     super(key);
     kb = KnowledgeBase.getKnowledgeBase();
  }

  public void addKnowledge(String newKnowledge) {
     kb.learn(newKnowledge);
  }

  /**
   *  Determines whether or the current item in the log file matches a pattern
   *  for an existing threat.
   *
   *  @param item the DataItem currently being analyzed
   *  @param regex the rule to match
   */
   public boolean inferThreat(DataItem item, String regex) {
      Pattern attack = Pattern.compile(regex);
      Matcher itemMatch = attack.matcher(item.data);
      
      String match = itemMatch.find() ? itemMatch.group(0) : "";
      if (match.equals(""))
         return false;

      return kb.remember(regex);
   }

   /**
   *  Concrete HTTPResearchers will handle their own event reporting.
   */  
   public abstract void reportEvent(DataItem item);
}
