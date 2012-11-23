package team.splunk.csc480.data;

import java.io.*;
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
   InputStream stream;
   public final String filename;

   /**
    * Open a file with name filename for reading.
    */
   public FileDataSource(String filename) throws FileNotFoundException {
      this.filename = filename;

      File inputFile = new File(filename);
      InputStream is = new FileInputStream(inputFile);
      stream = new BufferedInputStream(is);
      scan = new Scanner(stream);
   }

   @Override
   public void run() {
      String line;

      try {
         while (!stopNow) {
            while (scan.hasNextLine()) {
               line = scan.nextLine();
               cast.broadcastEvent(new DataItem(filename, line));
            }

            Thread.sleep(1000);

            if (stream.available() > 0)
               scan = new Scanner(stream);
         }
      }
      catch (InterruptedException e) {
         e.printStackTrace();
      }
      catch (IOException e) {
         e.printStackTrace();
      }
   }
}
