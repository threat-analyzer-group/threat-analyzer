package team.splunk.csc480.data;

import team.splunk.csc480.handler.Broadcaster;

/**
 * DataSource abstract class. Represents a Thread that notifies each of its
 * Researchers when a new DataItem is available. For an example, see the
 * HelloDataSource class.
 *
 * @see HelloDataSource
 * @author Team Splunk
 * @version 3.14
 * @date Nov. 13, 2012
 */
public abstract class DataSource implements Runnable {
   protected Broadcaster cast;
   protected boolean stopNow;

   /**
    * Starts a new DataSource that broadcasts any new DataItems to the handler.
    */
   public DataSource() { }

   /**
    * Sets the Broadcaster for this DataSource.
    *
    * @param cast the Broadcaster for this DataSource
    */
   public void setBroadcaster(Broadcaster cast) { this.cast = cast; }

   /**
    * Starts a new Thread using this. run() is then called and the stopNow
    * flag is reset. <b>DO NOT</b> call this more than once.
    *
    * @return a Thread that was just started for this DataSource
    */
   public Thread startThread() {
      Thread t = new Thread(this);
      stopNow = false;
      t.start();
      return t;
   }

   /**
    * Sets a flag that tells this DataSource to stop executing.
    */
   public synchronized void stopNow() { stopNow = true; }

   /**
    * This method will be run in its own Thread when startThread() is called.
    * If this method will run indefinitely (checking a file, for example..) it
    * <b>must</b> check <b>stopNow</b> periodically to determine if this
    * DataSource has been stopped.
    */
   public abstract void run();
}
