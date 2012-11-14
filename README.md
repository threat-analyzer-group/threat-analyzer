threat-analyzer
===============

Analyzes log files in real time looking for strange user behavior.

Approaches
==========
1. Regex matching of Apache Error codes (possibly ERROR or WARN messages as well).
2. Request correlation (eg. large amount of 'good' requests in a small amount of time.)