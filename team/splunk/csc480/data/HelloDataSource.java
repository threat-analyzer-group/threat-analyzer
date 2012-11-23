package team.splunk.csc480.data;

/**
 * Test data source. Sends out a "hello" data item every 5 seconds.
 *
 * @author Team Splunk
 * @version 3.14
 * @date Nov. 13, 2012
 */
public class HelloDataSource extends DataSource {

   /**
    * Initialize a HelloDataSource. When a new thread is started, it just
    * returns a "hello" DataItem every 5 secs.
    */
   public HelloDataSource() { }

   @Override
   public void run() {
      DataItem item = new DataItem("test", "hello");

      try {
         while (!stopNow) {
            Thread.sleep(2000);

            cast.broadcastEvent(item);
         }
      }
      catch (InterruptedException e) {
         System.err.println("Thread interrupted.");
      }
   }
}
