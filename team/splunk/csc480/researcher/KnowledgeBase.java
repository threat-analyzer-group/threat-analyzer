package team.splunk.csc480.researcher;

import team.splunk.csc480.data.DataItem;
import team.splunk.csc480.handler.ThreatHandler.*;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class KnowledgeBase {
   ArrayList<String> knowledge;

   public KnowledgeBase() {
     knowledge = new ArrayList<String>();
   }

   /**
    *  Add a new piece of knowledge to the knowledge base.
    */
    public synchronized void learn(String newKnowledge) {
       if (!knowledge.contains(newKnowledge)) {
          knowledge.add(newKnowledge);
       }
    }

   /**
    *  Determine if an existing piece of a knowledge matches the rule specified.
    *
    *  @param regex the rule to match.
    */
    public boolean remember(String regex) {
       Pattern attack = Pattern.compile(regex);
       Matcher itemMatch;

       for (String currentItem : knowledge) {
          itemMatch = attack.matcher(currentItem);
          String match = itemMatch.find() ? itemMatch.group(0) : "";
          if (!match.equals(""))
             return true;
       }
       return false;
    }
}
