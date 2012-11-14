package team.splunk.csc480.data;

import java.util.Date;
import java.util.HashMap;

/**
 * Created with IntelliJ IDEA.
 * User: tcirwin
 * Date: 11/13/12
 * Time: 3:53 PM
 * To change this template use File | Settings | File Templates.
 */
public class HelloDataSource extends DataSource {

   /**
    * Start up a DataSource that just returns a "hello" DataItem every 5 secs.
    */
   public HelloDataSource() { }

   @Override
   public void run() {
      DataItem item = new DataItem("hello", new Date(), new HashMap<String, String>());

      try {
         while (true) {
            if (stopNow)
               break;

            Thread.sleep(2000);

            cast.broadcastEvent(item);
         }
      }
      catch (InterruptedException e) {
         System.err.println("Thread interrupted.");
      }
   }
}
