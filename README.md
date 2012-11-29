threat-analyzer
===============

Analyzes log files in real time looking for strange user behavior.

Approaches
----------
1. Regex matching of Apache error codes (403, 404, 500, etc), as well as 
   error\_log messages (warn, error, alert, etc).
2. Request correlation (eg. large amount of 'good' requests in a small amount of
   time.)

Future Work
-----------
3. Future: SQL/HTML injection attempts
4. Add support for other log file types
  + SSH files
  + Dovecot
  + IPTables
5. Add support for clusters of server
6. Abstract away log parsing from researcher into its own class
7. GUI with Graphs
