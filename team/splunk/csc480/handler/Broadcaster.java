package team.splunk.csc480.handler;

import team.splunk.csc480.data.DataItem;

/**
 * Broadcasts DataItems to Researchers for processing. For an example, see
 * Commander.
 *
 * @see Commander
 * @author Team Splunk
 * @version 3.14
 * @date Nov. 13, 2012
 */
public interface Broadcaster {

   /**
    * Receives events from DataSources and broadcasts them to all Researchers.
    *
    * @param item the DataItem to broadcast
    */
   public void broadcastEvent(DataItem item);
}
