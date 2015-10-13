ABOUT
Identify what aspects of the work have been correctly implemented and what have not:
    > I attempted to implement all aspects of the work correctly, including the bonus. If I missed something, I am not currently aware of it.
    > If one packet has more than one incident, it is only shown once, for the first incident identified.
    > I don't convert to base 64 before printing the payload
    
Identify anyone with whom you have collaborated or discussed the assignment:
    > I worked alone on this assignment.

Say approximately how many hours you have spent completing the assignment:
    > 11 hours

QUESTIONS
1.) Are the heuristics used in this assignment to determine incidents "even that good"?
I don't think they are "even that good." Here are some possible concerns:
- I don't know that my regex are airtight. For example, if a log for some reason used single quotes (') instead of double quotes ("), or if the payload contained a double quote within it, they would fail to parse the log line correctly.
- For detecting some of these scans (nikto, masscan, shellshock-scan), I'm simply looking for the names of these in the user agent. I'm not sure if any of these have stealth modes that could bypass detection.
- I'm not sure if there are other communications that have the same TCP flag settings as the FIN, Xmas, and NULL Nmap scans, which would cause false positives in detecting these scans.
- My shell code strings probably don't cover all possible shell code strings that you might find in an apache log.
- The credit card leak check strips out whitespace and dashes, but there could very well be other separators. There may also be other types of credit cards that might not be covered by the regex, and there may be numbers that are identified as credit card numbers that are, in fact, something else (false positives). 
-As discussed in class, Nmap scan packets don't always have a payload, so searching for "nmap" in the payload fails to detect the scan in this case

2.) If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?
- I would try to close some of the "holes" mentioned above by using existing, effective gems (such as Apache Log Regex, http://simonecarletti.com/blog/2009/02/apache-log-regex-a-lightweight-ruby-apache-log-parser/ as well as looking for credit card verification gems) or by exploring more attacks/incidents that have occurred.
- I might try to check for Nmap scans that use fragmentation.
- I would add some error handling
- I would do the bonus
- I would check for credit cards in binary/hex
