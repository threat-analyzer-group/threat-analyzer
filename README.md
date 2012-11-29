threat-analyzer
===============

Analyzes log files in real time looking for strange user behavior.

Approaches
==========
1. Regex matching of Apache error codes (403, 404, 500, etc), as well as error_log messages (warn, error, alert, etc).
2. Request correlation (eg. large amount of 'good' requests in a small amount of time.)
3. SQL/HTML injection attempts