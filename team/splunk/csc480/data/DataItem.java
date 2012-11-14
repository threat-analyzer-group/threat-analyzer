package team.splunk.csc480.data;

import java.util.Date;
import java.util.HashMap;

/**
 * A piece of data representing one log entry of a file.
 *
 * @author Team Splunk
 * @version 3.14
 * @date Nov. 13, 2012
 */
public class DataItem {
   public final String fromFile;
   public final Date date;
   public final HashMap<String, String> data;

   public static class IPAddress {
      private static final int byteMask = 0x000000FF;

      public final int addr;

      public IPAddress(String ip) {
         addr = toInteger(ip);
      }

      private static int toInteger(String ip) {
         String[] strs = ip.split("\\.");

         try {
            if (strs.length > 4 || strs.length < 4)
               return -1;

            return (
              ((Integer.parseInt(strs[0]) & byteMask) << 24) |
                ((Integer.parseInt(strs[1]) & byteMask) << 16) |
                ((Integer.parseInt(strs[2]) & byteMask) << 8) |
                (Integer.parseInt(strs[3]) & byteMask)
            );
         }
         catch (NumberFormatException e) {
            System.err.println(e);
            return -1;
         }
      }

      public String toString() {
         return ((addr >> 24) & byteMask) + "." +
           ((addr >> 16) & byteMask) + "." +
           ((addr >> 8) & byteMask) + "." +
           (addr & byteMask);
      }
   }
   
   public DataItem(String ff, Date d, HashMap<String, String> dt) {
      data = dt; fromFile = ff; date = d;
   }
}
