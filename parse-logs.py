#!/usr/bin/python3

#################################################################################
#
# Licence: GPL v2
# 2021 - Raider700
#
# This script is used to parse and combine the 389-ds logs.
# The connection state is kept in the memory of the process (no redis needed).
# Optional the state can be saved on stop and restored on start.
#
# Output can be:
#   * stdout
#   * local file
#   * syslog server
#
# Additional the last success binds can be also recorded to file and sqlite db
#
# To see all params: <scipt> -h
#
#################################################################################

# import needed libs
import sys
import os
import re
import json
import getopt
import sqlite3
import time
import datetime
import signal
import socket
from collections import OrderedDict

#################################################################################

# servername for logging
__servername = "localhost"
__stage = "p"

# needed logging targets for syslog
__syslogsocket = None
__sysloghost = "127.0.0.1"
__syslogport = 514

# FACILITY
# 'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
# 'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
# 'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
# 'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
# 'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
# LEVEL
# 'emerg': 0, 'alert':1, 'crit': 2, 'err': 3,
# 'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
__syslogvalue = 165  # (local4=20) * 8 + (notice=5) = 165

# input logfile
__inlogfile = False

# output logfile (disabled on default)
__outlogfile = False
__outlastbindfile = False

# output on stdout
__stdout = True

# state file for restarts and sqlite db for last binds (disabled on default)
__statefile = False
__lastbinddb = False
__lastbindttl = 93600  # 26h, 0 ... never expire
__maxconnections = 100000

# runtime objects
__connections = None
__lastbindstore = None
__outlogwriter = None
__outlastbindwriter = None

# max age of connections in seconds
# 1h ... 3600, 6h ... 21600, 12h ... 43200, 24h ... 86400
CONNECTION_MAX_AGE = 86400
CLOSED_CONNECTION_MAX_AGE = 300

# intervals for the periodic tasks in seconds
FLUSH_INTERVAL = 1
SWEEP_INTERVAL = 60
SNAPSHOT_INTERVAL = 300

# read size for the input logfile
READ_CHUNK_SIZE = 1024 * 1024

# connection info without any data
EMPTY_CONNECTION_INFO = "connectioninfo=false fd=0 slot=0 tls=false starttls=false port=0 from=0.0.0.0 to=0.0.0.0 autobind=none binddn=none"

# split a prepared connection line into the parts around the tls fields
CONNECTION_PATTERN = re.compile(r"^(.*?) tls=(true|false) starttls=false (.*)$")

#################################################################################

# class to close script on "strg+c" and reopen output files on "kill -HUP"
class GracefulKiller:
    kill_now = False
    reopen = False

    def __init__(self):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)
        signal.signal(signal.SIGHUP, self.reopen_files)

    def exit_gracefully(self, signum, frame):
        self.kill_now = True

    def reopen_files(self, signum, frame):
        self.reopen = True


# information about a single connection and its open operations
class Connection:
    __slots__ = ("info", "prefix", "tls", "starttls", "suffix", "autobind", "binddn", "ops", "lastseen", "closed")

    def __init__(self):
        self.info = False
        self.prefix = "fd=0 slot=0"
        self.tls = "false"
        self.starttls = "false"
        self.suffix = "port=0 from=0.0.0.0 to=0.0.0.0"
        self.autobind = "autobind=none"
        self.binddn = "binddn=none"
        self.ops = {}
        self.lastseen = 0
        self.closed = 0

    # build the connection string for the logline
    def render(self):
        if self.tls is None:
            middle = self.prefix
        else:
            middle = "%s tls=%s starttls=%s %s" % (self.prefix, self.tls, self.starttls, self.suffix)
        return "CONNECTION connectioninfo=%s %s %s %s" % \
               ("true" if self.info else "false", middle, self.autobind, self.binddn)

    def dump(self):
        return {name: getattr(self, name) for name in self.__slots__}

    @classmethod
    def load(cls, data):
        entry = cls()
        for name in cls.__slots__:
            if name in data:
                setattr(entry, name, data[name])
        return entry


# store for all known connections (oldest used connection first)
class ConnectionStore:

    def __init__(self, maxsize):
        self.items = OrderedDict()
        self.maxsize = maxsize

    def get(self, con):
        return self.items.get(con)

    # mark the connection as used
    def touch(self, con, now):
        entry = self.items.get(con)
        if entry is not None:
            entry.lastseen = now
            self.items.move_to_end(con)
        return entry

    # add a new connection (replaces an old one with the same number)
    def create(self, con, now):
        entry = Connection()
        entry.lastseen = now
        self.items[con] = entry
        self.items.move_to_end(con)
        if self.maxsize and len(self.items) > self.maxsize:
            self.items.popitem(last=False)
        return entry

    def get_or_create(self, con, now):
        entry = self.touch(con, now)
        if entry is None:
            entry = self.create(con, now)
        return entry

    # remove closed and inactive connections
    def sweep(self, now):
        closed = [con for con, entry in self.items.items()
                  if entry.closed and entry.closed + CLOSED_CONNECTION_MAX_AGE < now]
        for con in closed:
            del self.items[con]
        while self.items:
            con, entry = next(iter(self.items.items()))
            if entry.lastseen + CONNECTION_MAX_AGE >= now:
                break
            self.items.popitem(last=False)

    def dump(self):
        return [[con, entry.dump()] for con, entry in self.items.items()]

    def load(self, data):
        for con, entry in data:
            self.items[con] = Connection.load(entry)


# store the last successful binds in a sqlite db
class LastBindStore:

    def __init__(self, path, stage, servername, ttl):
        self.stage = stage
        self.servername = servername
        self.ttl = ttl
        self.pending = {}
        self.db = sqlite3.connect(path, timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS lastbind ("
                        "stage TEXT NOT NULL, servername TEXT NOT NULL, user TEXT NOT NULL, "
                        "bindtime TEXT NOT NULL, updated INTEGER NOT NULL, "
                        "PRIMARY KEY (stage, servername, user))")
        self.db.execute("CREATE INDEX IF NOT EXISTS lastbind_updated ON lastbind (updated)")
        self.db.commit()

    # remember the bind, it is written on the next commit
    def record(self, user, bindtime, now):
        self.pending[user] = (bindtime, int(now))

    def commit(self):
        if not self.pending:
            return
        try:
            self.db.executemany("INSERT OR REPLACE INTO lastbind (stage, servername, user, bindtime, updated) "
                                "VALUES (?, ?, ?, ?, ?)",
                                [(self.stage, self.servername, user, bindtime, updated)
                                 for user, (bindtime, updated) in self.pending.items()])
            self.db.commit()
            self.pending = {}
        except sqlite3.Error as e:
            print("ERROR writing last binds to the sqlite db!")
            print(e)

    # remove binds older than the ttl
    def expire(self, now):
        if not self.ttl:
            return
        try:
            self.db.execute("DELETE FROM lastbind WHERE updated < ?", (int(now) - self.ttl,))
            self.db.commit()
        except sqlite3.Error as e:
            print("ERROR expiring last binds in the sqlite db!")
            print(e)

    def close(self):
        self.commit()
        self.db.close()


# output file which is reopened after a logrotate
class OutputFile:

    def __init__(self, path):
        self.path = path
        self.handle = None
        self.inode = None
        self.open()

    def open(self):
        self.handle = open(self.path, "a", encoding="utf-8")
        self.inode = os.fstat(self.handle.fileno()).st_ino

    def write(self, string):
        self.handle.write(string)

    def flush(self):
        self.handle.flush()

    def close(self):
        self.handle.close()

    # reopen the file if it was moved or removed
    def check(self, force=False):
        try:
            changed = os.stat(self.path).st_ino != self.inode
        except OSError:
            changed = True
        if changed or force:
            self.close()
            self.open()


# read new lines from the logfile (tail -f)
class LogTailer:

    def __init__(self, path):
        self.path = path
        self.handle = None
        self.inode = None
        self.offset = 0
        self.buffer = b""

    # open the logfile and continue at the given position or start at the end
    def open(self, position=None, inode=None, fromstart=False):
        self.handle = open(self.path, "rb")
        stats = os.fstat(self.handle.fileno())
        resumed = position is not None and inode == stats.st_ino and position <= stats.st_size
        if resumed:
            self.offset = position
        elif fromstart:
            self.offset = 0
        else:
            self.offset = stats.st_size
        self.handle.seek(self.offset)
        self.inode = stats.st_ino
        self.buffer = b""
        return resumed

    def close(self):
        self.handle.close()

    # position of the first not parsed byte
    def position(self):
        return self.offset - len(self.buffer)

    # read the next block and return the complete lines (None if there is no new data)
    def read_lines(self):
        block = self.handle.read(READ_CHUNK_SIZE)
        if not block:
            return None
        self.offset += len(block)
        lines = (self.buffer + block).split(b"\n")
        # keep the last line (maybe incomplete -> next round)
        self.buffer = lines.pop()
        return lines

    # check for logrotate: returns "rotated", "truncated" or None
    def check_rotation(self):
        try:
            stats = os.stat(self.path)
        except OSError:
            # new logfile does not exist (yet)
            return None
        if stats.st_ino != self.inode:
            return "rotated"
        if stats.st_size < self.offset:
            self.handle.seek(0)
            self.offset = 0
            self.buffer = b""
            return "truncated"
        return None

    # return the last line of a rotated file and open the new file
    def reopen(self):
        rest = self.buffer
        self.close()
        self.open(fromstart=True)
        return rest


# function to get current time in ldap format
def get_current_time_ldap():
    return time.strftime("[%d/%b/%Y:%H:%M:%S.000000000 %z]", time.gmtime())


# cache for the syslog time (only changes every second)
__syslogtime = [None, ""]


# function the get current time in syslog format
def get_current_time_syslog():
    # get the current local time
    timenow = time.localtime()
    if __syslogtime[0] == timenow:
        return __syslogtime[1]

    # get the time offset to send correct syslog time
    daylightsaving = time.daylight and timenow.tm_isdst > 0
    tzoffset = time.altzone if daylightsaving else time.timezone

    # convert the current time and return it
    date = datetime.datetime.fromtimestamp(time.mktime(timenow))
    __syslogtime[0] = timenow
    __syslogtime[1] = date.strftime("%Y-%m-%dT%H:%M:%S") + "%+03d:00" % (tzoffset / 60 / 60 * - 1)
    return __syslogtime[1]


# translate error code to name
ERROR_NAMES = {
    "err=0": "errname=success",
    "err=1": "errname=operation_error",
    "err=2": "errname=protocol_error",
    "err=3": "errname=time_limit_exceeded",
    "err=4": "errname=size_limit_exceeded",
    "err=5": "errname=compare_false",
    "err=6": "errname=compare_true",
    "err=7": "errname=auth_method_not_supported",
    "err=8": "errname=strong_auth_required",
    "err=9": "errname=ldap_partial_results",
    "err=10": "errname=referral",
    "err=11": "errname=admin_limit_exceeded",
    "err=12": "errname=unavailable_critical_extension",
    "err=13": "errname=confidentiality_required",
    "err=14": "errname=sasl_bind_in_progress",
    "err=16": "errname=no_such_attribute",
    "err=17": "errname=undefined_attribute_type",
    "err=18": "errname=inappropriate_matching",
    "err=19": "errname=constraint_violation",
    "err=20": "errname=attribute_or_value_exists",
    "err=21": "errname=invalid_attribute_syntax",
    "err=32": "errname=no_such_object",
    "err=33": "errname=alias_problem",
    "err=34": "errname=invalid_dn_syntax",
    "err=35": "errname=is_leaf",
    "err=36": "errname=alias_dereferencing_problem",
    "err=48": "errname=inappropriate_authentication",
    "err=49": "errname=invalid_credentials",
    "err=50": "errname=insufficient_access_rights",
    "err=51": "errname=busy",
    "err=52": "errname=unavailable",
    "err=53": "errname=unwilling_to_perform",
    "err=54": "errname=loop_defect",
    "err=64": "errname=naming_violation",
    "err=65": "errname=object_class_violation",
    "err=66": "errname=not_allowed_on_nonleaf",
    "err=67": "errname=not_allowed_on_rdn",
    "err=68": "errname=entry_already_exists",
    "err=69": "errname=object_class_mods_prohibited",
    "err=71": "errname=affects_multiple_dsas",
    "err=80": "errname=other",
    "err=81": "errname=server_down",
    "err=85": "errname=ldap_timeout",
    "err=89": "errname=param_error",
    "err=91": "errname=connect_error",
    "err=92": "errname=ldap_not_supported",
    "err=93": "errname=control_not_found",
    "err=94": "errname=no_results_returned",
    "err=95": "errname=more_results_to_return",
    "err=96": "errname=client_loop",
    "err=97": "errname=referral_limit_exceeded"
}


def get_error_code_by_name(reserr):
    return ERROR_NAMES.get(reserr, "errname=unknown")


# store the last successful bind into the sqlite db and the lastbind logfile
def record_last_success_bind(servername, user, bindtime):
    # try to parse tle line
    try:
        # insert new bind into the sqlite db
        if __lastbindstore is not None:
            __lastbindstore.record(user, bindtime, now())

        # create line to record
        logline = "%s INFO: %s - RECORD - Success Bind from \"%s\" at \"%s\" on server \"%s\"" % \
                  (get_current_time_syslog(), servername, user, bindtime, servername)

        # append info to the lastbind logfile
        try:
            if __outlastbindwriter is not None:
                __outlastbindwriter.write("%s %s\n" % (get_current_time_syslog(), logline))
        except Exception as e:
            print("ERROR writing local lastbind line! (%s)" % logline)
            print(e)

    except Exception as e:
        print("ERROR on record_last_success_bind function! (%s %s %s)" % (servername, user, bindtime))
        print(e)


# send the logline to syslog
def send_syslog_message(string, servername):
    # check if the line should be send
    global __sysloghost
    if not __sysloghost:
        return

    # generate the send line
    global __syslogvalue
    line = "<%s>1 %s gdcc01 rhds-log-combi - - -  %s\n" % (str(__syslogvalue), get_current_time_syslog(), string)

    # define the send socket for syslog lines
    global __syslogsocket
    try:
        try:
            # send the logline
            __syslogsocket.send(line.encode())
        except:
            # open socket on error and try to send againv
            global __syslogport
            __syslogsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            __syslogsocket.connect((__sysloghost, __syslogport))
            __syslogsocket.send(line.encode())
    except Exception as e:
        print("ERROR sending syslog message! (%s - %s)" % (servername, line))
        print(e)


# write the logline to a local file
def write_local_logfile(string):
    try:
        # direct write to logfile to avoid journald
        if __outlogwriter is not None:
            __outlogwriter.write("%s %s\n" % (get_current_time_syslog(), string))

    except Exception as e:
        print("ERROR writing local syslog line to file! (%s - %s)" % (__outlogfile, string))
        print(e)


# log a connection
def log_line(servername, line):
    try:
        # build the string with all possible options
        string = ("%s %s" % (servername, line))

        # write log to syslog and local file
        send_syslog_message(string, servername)
        write_local_logfile(string)

        # write to stdout if defined
        if __stdout:
            print(string)

    except Exception as e:
        print("ERROR on log_line function!")
        print(e)


# log a error
def log_error(source, servername, line, error):
    try:
        # show the original line as error string
        string = str("%s %s conn=-1 %s %s" % (servername, get_current_time_ldap(), error, line.rstrip()))

        # write log to syslog and local file
        send_syslog_message(string, servername)
        write_local_logfile(string)

        # on error always write to stdout
        print("%s: %s" % (source, string))

    except Exception as e:
        print("ERROR on log_error function!")
        print(e)


# current time for the connection ages
def now():
    return time.time()


# create entry for new connection
def new_connection(servername, con, line):
    # time for later los usage
    linetime = "%s]" % line.split('] ')[0]

    # prepare the connection info
    line = line.replace(('%s ' % con), '', 1)
    line = line.replace('SSL connection', 'tls=true starttls=false port=636')
    line = line.replace('connection', 'tls=false starttls=false port=389')
    line = line.replace('from ', 'from=')
    line = line.replace('to ', 'to=')
    line = line.split('] ')[-1]

    # store the connection info (replaces an old connection with the same number)
    entry = __connections.create(con, now())
    entry.info = True
    entry.autobind = "autobind=false"
    match = CONNECTION_PATTERN.match(line)
    if match:
        entry.prefix, entry.tls, entry.suffix = match.group(1, 2, 3)
    else:
        # unknown format, keep the line as it is
        entry.prefix = line
        entry.tls = None

    # generate the logline
    logline = str("%s %s op=-1 OPEN type=open RESULT err=0 errname=success %s" % (linetime, con, entry.render()))

    # send the logline
    log_line(servername, logline)


# update connection information for starttls
def update_connection_tls(servername, con, line):
    # prepare the tls info
    tlsinfo = line.replace(('%s ' % con), '', 1)
    tlsinfo = tlsinfo.split('] ')[-1]
    tlsinfo = tlsinfo.replace(' ', ',')

    # an ssl connection (port 636) is already encrypted, only plain connections use starttls
    entry = __connections.get_or_create(con, now())
    if entry.tls == "false":
        entry.tls = "true"
        entry.starttls = "\"%s\"" % tlsinfo


# update connection information for autobind user
def update_connection_autobind(servername, con, line):
    # prepare the autobind info
    line = line.replace(('%s ' % con), '', 1)
    line = line.replace('AUTOBIND dn=', 'autobind=')
    line = line.split('] ')[-1]

    # only the first autobind is stored
    entry = __connections.get_or_create(con, now())
    if entry.autobind in ("autobind=false", "autobind=none"):
        entry.autobind = line


# update connection information for bind user
def update_connection_bind(servername, con, opnumber, line):
    # prepare the bind info
    line = line.replace(('%s ' % con), '', 1)
    line = line.replace('BIND dn=', 'binddn=', 1)
    line = line.replace(('%s ' % opnumber), '', 1)
    line = line.split('] ')[-1]

    # only the first bind is stored
    entry = __connections.get_or_create(con, now())
    if entry.binddn == "binddn=none":
        entry.binddn = line


# store the current operation
def new_operation(servername, con, opnumber, operation, line):
    # prepare the line
    line = line.replace(('%s %s' % (opnumber, operation)),
                        ('%s %s type=\"%s\"' % (opnumber, operation, operation.lower())), 1)

    # add the line to the connection
    __connections.get_or_create(con, now()).ops[opnumber] = line


# log result with operation and connection data
def log_operation(servername, con, opnumber, errorcode, line):
    # prepare the result info
    line = line.replace(('%s ' % con), '', 1)
    line = line.replace(('%s ' % opnumber), '', 1)
    line = line.replace(('%s ' % errorcode), ('%s %s ' % (errorcode, get_error_code_by_name(errorcode))), 1)
    line = line.split('] ')[-1]

    # get the connection and operation information (operation is removed)
    entry = __connections.get(con)
    operation = None
    if entry is None:
        connection = "CONNECTION %s" % EMPTY_CONNECTION_INFO
    else:
        connection = entry.render()
        operation = entry.ops.pop(opnumber, None)
    if operation is None:
        operation = "%s %s %s UNKNOWN(Operation not found in redis!) operationmissing=true" % \
                    (get_current_time_ldap(), con, opnumber)

    # check if it was the result of a successfull bind
    try:
        if errorcode == "err=0" and " dn=" in line:
            # extract the needed values from the strings
            user = line.split(' dn=')[-1]
            user = user.replace('"', '')
            bindtime = "%s]" % operation.split('] ')[0]
            # record the bind
            record_last_success_bind(servername, user, bindtime)
    except Exception as a:
        log_error("log_operation_lastbind", servername, line, ("ERROR(%s)" % str(a)))

    # generate the logline
    logline = str("%s %s %s" % (operation, line, connection))

    # send the logline
    log_line(servername, logline)


# log the closing connection
def close_connection(servername, con, opnumber, fdnumber, line):
    # prepare the additional info
    closeinfo = line.split("%s " % fdnumber)[-1]
    closeinfo = closeinfo.replace(' - ', '=')
    closeinfo = closeinfo.replace(' ', '_')

    # get the connection and operation information
    entry = __connections.get(con)
    operation = None
    if entry is None:
        connection = "CONNECTION %s %s" % (fdnumber, EMPTY_CONNECTION_INFO)
    else:
        connection = entry.render()
        if opnumber != "op=-1":
            operation = entry.ops.pop(opnumber, None)
        # mark entry for deletion in 5min
        entry.closed = now()
    if operation is None:
        operation = "%s CLOSE type=\"close\" note=\"close without unbind\"" % (line.split(" %s" % fdnumber)[0])

    # generate the logline
    logline = str("%s RESULT err=0 errname=success %s %s" % (operation, closeinfo, connection))

    # send the logline
    log_line(servername, logline)


# parse the given logline
def parse_current_log_line(servername, line):
    try:
        # skip empty lines
        if not line.strip():
            return
        # remove all null values from string
        line = line.replace('\x00', '')
        # add starting [ if needed
        if line[0].isdigit() and line[36] == ']':
            line = "[%s" % line
        # check if line seams to be correct with initial time
        if not (line[0] == "[" and line[37] == "]" and line[43] == "="):
            print("IGNORING BAD LINE (%s): %s" % (servername, line.encode()))
            return
    except:
        print("IGNORING BROKEN LINE (%s): %s" % (servername, line.encode()))
        return

    # try to parse tle line
    try:
        # split the line to usable args (only the first fields are needed)
        # [time, timezone], conn, op/fd/TLS/AUTOBIND, operation, errorcode
        args = line.split(None, 6)

        # get infos about the current line
        con = args[2]
        opnumber = args[3]

        # mark the connection as active
        __connections.touch(con, now())

        # check the next step for the logline
        if opnumber.startswith("op="):
            # get the operation from the line
            operation = args[4]
            if operation == "RESULT":
                # get the error code from the line
                errorcode = args[5]
                # result should send a logine
                log_operation(servername, con, opnumber, errorcode, line)
            elif operation == "BIND":
                # bind user should be stored as soon as possible
                update_connection_bind(servername, con, opnumber, line)
                # also store the operation
                new_operation(servername, con, opnumber, operation, line)
            elif operation.startswith("fd="):
                # send log line on connection close
                close_connection(servername, con, opnumber, operation, line)
            else:
                # normal operation should be stored
                new_operation(servername, con, opnumber, operation, line)
        elif opnumber.startswith("fd="):
            # log new connection
            new_connection(servername, con, line)
        elif opnumber.startswith("TLS"):
            # update connection status to starttls
            update_connection_tls(servername, con, line)
        elif opnumber.startswith("AUTOBIND"):
            # update connection to show autobind usage
            update_connection_autobind(servername, con, line)
        else:
            # unknown line should be logged with information about that
            log_error("parse_current_log_line", servername, line, "UNKNOWN(TYPE OF LOG LINE!)")

    except Exception as e:
        # log the wrong line
        log_error("parse_current_log_line", servername, line, ("ERROR(%s)" % str(e)))


# load the state of the last run (None if there is no usable state)
def load_state(logfile):
    if not __statefile or not os.path.exists(__statefile):
        return None
    try:
        with open(__statefile, "r", encoding="utf-8") as statefile:
            state = json.load(statefile)
        if state.get("version") != 1 or state.get("logfile") != os.path.abspath(logfile):
            print("IGNORING STATE FILE (%s): other version or logfile" % __statefile)
            return None
        return state
    except Exception as e:
        print("ERROR reading the state file (%s)! ... Starting without state" % __statefile)
        print(e)
        return None


# save the current state (atomic replace of the state file)
def save_state(logfile, tailer):
    if not __statefile:
        return
    try:
        state = {
            "version": 1,
            "logfile": os.path.abspath(logfile),
            "inode": tailer.inode,
            "position": tailer.position(),
            "saved": now(),
            "connections": __connections.dump()
        }
        tmpfile = "%s.tmp" % __statefile
        with open(tmpfile, "w", encoding="utf-8") as statefile:
            json.dump(state, statefile, separators=(",", ":"))
            statefile.flush()
            os.fsync(statefile.fileno())
        os.replace(tmpfile, __statefile)
    except Exception as e:
        print("ERROR writing the state file (%s)!" % __statefile)
        print(e)


# open the output files and the sqlite db
def open_outputs():
    global __outlogwriter
    global __outlastbindwriter
    global __lastbindstore
    if __outlogfile:
        __outlogwriter = OutputFile(__outlogfile)
    if __outlastbindfile:
        __outlastbindwriter = OutputFile(__outlastbindfile)
    if __lastbinddb:
        __lastbindstore = LastBindStore(__lastbinddb, __stage, __servername, __lastbindttl)


# flush all outputs and reopen moved output files
def flush_outputs(reopen=False):
    for writer in (__outlogwriter, __outlastbindwriter):
        if writer is None:
            continue
        try:
            writer.flush()
            writer.check(force=reopen)
        except Exception as e:
            print("ERROR writing or reopening the output file (%s)!" % writer.path)
            print(e)
    if __lastbindstore is not None:
        __lastbindstore.commit()
    sys.stdout.flush()


# close all outputs
def close_outputs():
    flush_outputs()
    for writer in (__outlogwriter, __outlastbindwriter):
        if writer is not None:
            writer.close()
    if __lastbindstore is not None:
        __lastbindstore.close()


# parse all given lines
def parse_lines(servername, lines):
    for logline in lines:
        parse_current_log_line(servername, logline.decode("utf-8", "replace"))


# funktion for tailing the logfile
def file_seeker_loop(servername, logfile, killer):
    global __connections
    __connections = ConnectionStore(__maxconnections)

    # restore the state of the last run
    state = load_state(logfile)
    if state is not None:
        __connections.load(state.get("connections", []))
        __connections.sweep(now())

    # open the input logfile and the outputs
    tailer = LogTailer(logfile)
    try:
        if state is None:
            tailer.open()
        elif tailer.open(state.get("position"), state.get("inode")):
            print("CONTINUE READING (%s) at position %s" % (logfile, tailer.position()))
        open_outputs()
    except Exception as ae:
        print("ERROR reading or writing the logs files (IN=%s, OUT=%s)! ... Exiting" % (logfile, str(__outlogfile)))
        print(ae)
        sys.exit(1)

    # times for the periodic tasks
    nextflush = now() + FLUSH_INTERVAL
    nextsweep = now() + SWEEP_INTERVAL
    nextsnapshot = now() + SNAPSHOT_INTERVAL

    while not killer.kill_now:
        # read and parse the next lines
        lines = None
        try:
            lines = tailer.read_lines()
            if lines is not None:
                parse_lines(servername, lines)
            else:
                # no new data, check for logrotate
                rotation = tailer.check_rotation()
                if rotation == "rotated":
                    # read the rest of the old file before switching to the new one
                    lines = tailer.read_lines()
                    while lines is not None:
                        parse_lines(servername, lines)
                        lines = tailer.read_lines()
                    parse_lines(servername, [tailer.reopen()])
                elif rotation == "truncated":
                    print("LOGFILE TRUNCATED (%s) ... starting from beginning" % logfile)
        except Exception as ae:
            print("ERROR reading new data from the logfile (%s)!" % logfile)
            print(ae)

        # periodic tasks
        currenttime = now()
        if lines is None or currenttime >= nextflush or killer.reopen:
            flush_outputs(reopen=killer.reopen)
            killer.reopen = False
            nextflush = currenttime + FLUSH_INTERVAL
        if currenttime >= nextsweep:
            __connections.sweep(currenttime)
            if __lastbindstore is not None:
                __lastbindstore.expire(currenttime)
            nextsweep = currenttime + SWEEP_INTERVAL
        if currenttime >= nextsnapshot:
            save_state(logfile, tailer)
            nextsnapshot = currenttime + SNAPSHOT_INTERVAL

        # sleep some time before next read
        if lines is None and not killer.kill_now:
            time.sleep(0.1)

    # save the state and close everything
    save_state(logfile, tailer)
    close_outputs()
    tailer.close()


# help function for script execution
def show_help():
    global __servername
    print("There are needed params missing!\n"
          "Use: <script> <params>\n"
          "\n"
          "Possible params:\n"
          "-i | --log_input       ... Input log file from 389-ds (needed)\n"
          "-o | --log_output      ... Output log file for combined log (default: False)\n"
          "-l | --log_lastbind    ... Logfile for last successful binds (default: False)\n"
          "-b | --lastbind_db     ... SQLite db for last successful binds (default: False)\n"
          "     --lastbind_ttl    ... Seconds to keep binds in the SQLite db, 0 = forever (default: 93600)\n"
          "-f | --state_file      ... File to save the state on stop and continue on start (default: False)\n"
          "     --max_connections ... Max number of connections kept in memory, 0 = unlimited (default: 100000)\n"
          "-s | --servername      ... Name of the server for the log lines (default: %s)\n"
          "-e | --stage           ... Define the server environment p, v or d (default: p ... production)\n"
          "-d | --syslog_host     ... Destination server for the syslog message (default: 127.0.0.1)\n"
          "-p | --syslog_port     ... Destination port for the syslog message (default: 514)\n"
          "-v | --syslog_value    ... Facility and level for the syslog message (default: 165)\n"
          "-t | --stdout          ... Display combined log on stdout (default: True)\n"
          "-h | --help            ... This message :)\n"
          "\n"
          "To disable a output function use:\n"
          "--log_output=False    ... Write no combined logfile\n"
          "--log_lastbind=False  ... Write no lastbind logfile\n"
          "--syslog_host=False   ... Do not send a syslog message\n"
          "--stdout=False        ... Do not write to stdout\n"
          "\n"
          "Send SIGHUP to reopen the output files after a logrotate.\n" % __servername)
    sys.exit(1)


# convert the param to a file name or False
def file_param(arg):
    if arg == "False" or arg == "None":
        return False
    return arg


# convert the param to a number or show the help
def int_param(arg):
    try:
        return int(arg)
    except ValueError:
        show_help()


# define the main funktion
def main(argv):
    # initialize a signal handler
    killer = GracefulKiller()

    # read the servername
    global __servername
    try:
        __servername = socket.gethostname().split('.')[0]
    except:
        pass

    # read the given option
    try:
        opts, args = getopt.getopt(argv, "i:o:l:b:f:s:e:d:p:v:t:h", ["log_input=", "log_output=", "log_lastbind=",
                                                                     "lastbind_db=", "lastbind_ttl=", "state_file=",
                                                                     "max_connections=", "servername=", "stage=",
                                                                     "syslog_host=", "syslog_port=", "syslog_value=",
                                                                     "stdout=", "help"])
    except:
        show_help()
        sys.exit(1)

    # store the given params
    for opt, arg in opts:
        if opt in ("-i", "--log_input"):
            global __inlogfile
            __inlogfile = arg
        if opt in ("-o", "--log_output"):
            global __outlogfile
            __outlogfile = file_param(arg)
        if opt in ("-l", "--log_lastbind"):
            global __outlastbindfile
            __outlastbindfile = file_param(arg)
        if opt in ("-b", "--lastbind_db"):
            global __lastbinddb
            __lastbinddb = file_param(arg)
        if opt == "--lastbind_ttl":
            global __lastbindttl
            __lastbindttl = int_param(arg)
        if opt in ("-f", "--state_file"):
            global __statefile
            __statefile = file_param(arg)
        if opt == "--max_connections":
            global __maxconnections
            __maxconnections = int_param(arg)
        if opt in ("-s", "--servername"):
            __servername = arg
        if opt in ("-e", "--stage"):
            if arg == "p" or arg == "v" or arg == "d":
                global __stage
                __stage = arg
            else:
                show_help()
        if opt in ("-d", "--syslog_host"):
            global __sysloghost
            __sysloghost = file_param(arg)
        if opt in ("-p", "--syslog_port"):
            global __syslogport
            __syslogport = int_param(arg)
        if opt in ("-v", "--syslog_value"):
            global __syslogvalue
            __syslogvalue = int_param(arg)
        if opt in ("-t", "--stdout"):
            global __stdout
            if arg in ("False", "false"):
                __stdout = False
            elif arg in ("True", "true"):
                __stdout = True
            else:
                show_help()
        if opt in ("-h", "--help"):
            show_help()

    # check if needed logfile was defined
    if not __inlogfile:
        show_help()

    # enter the seeker loop
    file_seeker_loop(__servername, __inlogfile, killer)


# open main after start
if __name__ == "__main__":
    main(sys.argv[1:])
