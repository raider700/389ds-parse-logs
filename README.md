# 389ds-parse-logs

Script for parsing and combining 389-ds log lines.

It is also working with RedHat Directory Server 11 (389-ds-base-1.4.3.22).

## Installation

There is no installation needed, you only have to start the script.
Only python3 (>= 3.6) with its standard library is needed (no redis or other external modules).

The state of the open connections is kept in the memory of the process:
* Closed connections are removed after 5 minutes, inactive connections after 24 hours.
* `--max_connections` limits the number of connections kept in memory (oldest inactive are removed first).
* With `--state_file` the state and the read position are saved on stop (and every 5 minutes).
  On the next start the script continues at the saved position, so no lines get lost on a restart.
  If the logfile was rotated in the meantime, the script starts at the end of the new file.

Last successful binds can be stored in a SQLite db with `--lastbind_db` (table `lastbind`
with the columns `stage`, `servername`, `user`, `bindtime`, `updated`). The db uses WAL mode,
so it can be read by other tools while the script is running, e.g.:
```bash
sqlite3 /var/lib/parse-logs/lastbind.db "SELECT user, bindtime FROM lastbind ORDER BY updated DESC"
```

## Usage

Execute: ./parse-logs.py <params>
```bash
Possible params:
-i | --log_input       ... Input log file from 389-ds (needed)
-o | --log_output      ... Output log file for combined log (default: False)
-l | --log_lastbind    ... Logfile for last successful binds (default: False)
-b | --lastbind_db     ... SQLite db for last successful binds (default: False)
     --lastbind_ttl    ... Seconds to keep binds in the SQLite db, 0 = forever (default: 93600)
-f | --state_file      ... File to save the state on stop and continue on start (default: False)
     --max_connections ... Max number of connections kept in memory, 0 = unlimited (default: 100000)
-s | --servername      ... Name of the server for the log lines (default: <hostname>)
-e | --stage           ... Define the server environment p, v or d (default: p ... production)
-d | --syslog_host     ... Destination server for the syslog message (default: 127.0.0.1)
-p | --syslog_port     ... Destination port for the syslog message (default: 514)
-v | --syslog_value    ... Facility and level for the syslog message (default: 165)
-t | --stdout          ... Display combined log on stdout (default: True)
-h | --help            ... This message :)

To disable a output function use:
--log_output=False    ... Write no combined logfile
--log_lastbind=False  ... Write no lastbind logfile
--syslog_host=False   ... Do not send a syslog message
--stdout=False        ... Do not write to stdout

Send SIGHUP to reopen the output files after a logrotate.
```
  
## Example

Original 389-ds log lines:
```python
[28/Sep/2021:13:30:39.061117647 +0200] conn=123 fd=4096 slot=4096 SSL connection from 10.10.10.20 to 10.10.10.10
[28/Sep/2021:13:30:39.312732156 +0200] conn=123 op=0 BIND dn="cn=Directory Manager" method=128 version=3
[28/Sep/2021:13:30:39.313621178 +0200] conn=123 op=0 RESULT err=0 tag=97 nentries=0 wtime=0.050183451 optime=0.000902082 etime=0.051082291 dn="cn=directory manager"
[28/Sep/2021:13:30:39.321295649 +0200] conn=123 op=1 SRCH base="cn=monitor" scope=0 filter="(objectClass=*)" attrs="* aci"
[28/Sep/2021:13:30:39.322509856 +0200] conn=123 op=1 RESULT err=0 tag=101 nentries=1 wtime=0.001051741 optime=0.174392170 etime=0.175441291
[28/Sep/2021:13:30:40.617683492 +0200] conn=123 op=-1 fd=4096 closed error - B1
```

Execution command:
```bash
./parse-logs.py --log_input=/var/log/dirsrv/sldapd-userroot/access --servername=ldapserver01
```

Output of parse-logs.py:
```python
ldapserver01 [28/Sep/2021:13:30:39.061117647 +0200] conn=123 op=-1 OPEN type=open RESULT err=0 errname=success CONNECTION connectioninfo=true fd=4096 slot=4096 tls=true starttls=false port=636 from=10.10.10.20 to=10.10.10.10 autobind=false binddn=none
ldapserver01 [28/Sep/2021:13:30:39.312732156 +0200] conn=123 op=0 BIND type="bind" dn="cn=Directory Manager" method=128 version=3 RESULT err=0 errname=success tag=97 nentries=0 wtime=0.050183451 optime=0.000902082 etime=0.051082291 dn="cn=directory manager" CONNECTION connectioninfo=true fd=4096 slot=4096 tls=true starttls=false port=636 from=10.10.10.20 to=10.10.10.10 autobind=false binddn="cn=Directory Manager" method=128 version=3
ldapserver01 [28/Sep/2021:13:30:39.321295649 +0200] conn=123 op=1 SRCH type="srch" base="cn=monitor" scope=0 filter="(objectClass=*)" attrs="* aci" RESULT err=0 errname=success tag=101 nentries=1 wtime=0.001051741 optime=0.174392170 etime=0.175441291 CONNECTION connectioninfo=true fd=4096 slot=4096 tls=true starttls=false port=636 from=10.10.10.20 to=10.10.10.10 autobind=false binddn="cn=Directory Manager" method=128 version=3
ldapserver01 [28/Sep/2021:13:30:40.617683492 +0200] conn=123 op=-1 CLOSE type="close" note="close without unbind" RESULT err=0 errname=success closed_error=B1 CONNECTION connectioninfo=true fd=4096 slot=4096 tls=true starttls=false port=636 from=10.10.10.20 to=10.10.10.10 autobind=false binddn="cn=Directory Manager" method=128 version=3
```

## Contributing

Pull requests are always welcome.
 
Known possible improvments:
* Input hardening for some params
* Error handling to fine grade exceptions
* Code improvement for function params
* Add debugging options
  
## License
GNU General Public License v2.0
