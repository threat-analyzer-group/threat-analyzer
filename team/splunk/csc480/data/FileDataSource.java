package team.splunk.csc480.data;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Date;
import java.util.HashMap;
import java.util.Scanner;

/**
 * Opens a file and formats a DataItem from every line of the file.
 *
 * @author Team Splunk
 * @version 3.14
 * @date Nov. 13, 2012
 */
public class FileDataSource extends DataSource {
   Scanner scan;
   
   /**
    * Open a file with name fileName for reading.
    */
   public FileDataSource(String fileName) throws FileNotFoundException {
      scan = new Scanner(new File(fileName));
   }

   @Override
   public void run() {
      DataItem item = new DataItem("hello", new Date(), new HashMap<String, String>());
      cast.broadcastEvent(item);
   }
}
