# my-little-snitch

Little Snitch's rules and traffic from the command line, as root: list the
rules, add or remove one, clean out the outdated ones, and see what one
program connected to.

Little Snitch's own `littlesnitch` can export and restore the WHOLE rule
model and print the traffic log, but has no command for one rule.
my-little-snitch edits the exported model and restores it -- carefully, see
"How a change is made".

## Needs

- root (littlesnitch refuses anyone else)
- Little Snitch > Settings > Security > "Allow access via Terminal" on
- once per machine: `my-little-snitch diag roundtrip go` -- export, restore
  unchanged, compare. Until it has passed, every change is refused.

## Commands

    my-little-snitch list [<FILTER>]
    my-little-snitch allow [go] <PROCESS> <REMOTE> [--port <N>|any] [--host] [--owner <USER>|anyone|system] [--via <PROGRAM>]
    my-little-snitch deny  [go] <PROCESS> <REMOTE> ...
    my-little-snitch remove [go] [<ID>..]
    my-little-snitch cleanup [go]
    my-little-snitch log [<PROCESS>|<FILTER>] [--since 1h] [--denied]
    my-little-snitch diag roundtrip [go] | diag events [--since 10m]

Every command that changes rules shows what it would do; with `go` it does it.

**list** -- one line per rule: an ID (6 hex), a TAB (so `cut -f 1` takes
it), then process (and `via` the program it runs through -- curl, for a
script that calls it), action, remote, protocol/port, owner, and -- where
there is something to do -- one token saying what:

| token | means |
|---|---|
| `cleanup?[never-matches]` | a `*` where Little Snitch has none: it matches nothing (see below) |
| `cleanup?[program-gone]` | the program it names, or its via program, no longer exists |
| `cleanup?[user-gone]` | its owner uid is no user on this machine |
| `cleanup?[expired]` | an expired temporary rule (Little Snitch's "suggestion") |
| `allow?[version-path]` | works, but names one Homebrew version: breaks on the next upgrade -- `allow go` its program again, then `remove go` this one |

The ID is a hash of the rule without Little Snitch's counters, so it stays
the same from one `list` to the next; a changed rule gets a new one.

**allow / deny** -- an outgoing rule. PROCESS is `any`, a path, or a name
found on `$PATH` and `PROGRAM_PATH` (`aria2c`). A Homebrew program gets `*`
for its version folder, as Little Snitch's own alert writes it -- and a
Python is its `Python.app`, which is what connects -- so the rule survives
upgrades:

    my-little-snitch allow /opt/homebrew/bin/python3 api.example.org
     >>> process: path.opt/homebrew/Cellar/python@3.15/*/Frameworks/Python.framework/Versions/3.15/Resources/Python.app/Contents/MacOS/Python
        > (from /opt/homebrew/bin/python3 = ...: a Python connects as its Python.app; its version folder made '*', ...)
     >>> would add: ...  allow  api.example.org  tcp/443  alice

Little Snitch has no wildcards in process paths but this one: a `*` for the
folder of Homebrew's version, right after `Cellar/<formula>/` (its
developers, 2026-10). A `*` anywhere else -- `python@*`, `Versions/*` -- is
stored by `restore-model` and never matches, so my-little-snitch refuses it.
A new minor version (`python@3.16`) is another program: allow it again.

REMOTE is a domain (and its hosts), a host with `--host`, or `any`. `--port`
defaults to 443 (tcp), `--owner` to `OWNER_DEFAULT`. A rule that is already
there is said, never doubled.

`--via <PROGRAM>` is the program PROCESS connects through -- curl, run by a
script or by brew -- found the same way as PROCESS and written as Little Snitch stores one (an
Apple program by its code identity, `com.apple.curl`). A script PROCESS is then
`script.<path>`, as Little Snitch names the scripts it shows "via" something.
The rule's proof is the via program's log (`log curl`): it is what connects.

    my-little-snitch allow go /usr/local/bin/fetch.sh example.org --via curl

**remove** -- by ID, as arguments or one per line on stdin:

    my-little-snitch list python@3.10 | cut -f 1 | my-little-snitch remove go

**cleanup** -- the OUTDATED rules, useless because what they name no longer
exists: exactly the `cleanup?` lines of `list`.

**log** -- the connections Little Snitch counted (`littlesnitch log-traffic`):
local time, in/out, program, remote, protocol/port, bytes in and out, new
connects (when there were any), `DENIED n`. Each line is a sample of a
connection: bytes with no connects is traffic on an open connection, 0 bytes
is nothing moved. A PROCESS (`aria2c`, a path) matches every Homebrew version
of it, as the connecting program or the app around it; anything else is a
part of the line. `--denied`: only lines with a denial. `-V` adds the full
path.

    my-little-snitch log aria2c --since 1d --denied

**diag events** -- Little Snitch's own messages (`littlesnitch log`).

## How a change is made

`littlesnitch restore-model` replaces the whole model, so each change:

1. exports the model -- the backup, `BACKUP_DIR/<local time>.json` (0600)
2. changes a copy
3. exports again; if any rule differs from step 1 (counters aside), it
   refuses: Little Snitch changed a rule meanwhile, and restoring would lose it
4. restores the copy (`-t`: Terminal access stays on)
5. exports once more; the rules must be exactly what was asked -- otherwise
   an ERROR names the backup and the command to restore it

Step 5 proves the rule was STORED, not that it MATCHES: only a connection
it lets through proves that (`log <PROCESS>` after the next run), and the
`added:` line says so.

It is NOT atomic. Steps 1-5 run under a lock against other
my-little-snitch runs (a dead run's lock is broken, and said), but Little
Snitch itself cannot be locked: a rule it makes during the restore call --
an alert answered, by you or by its 45 s auto-confirm -- is lost, and step 5
cannot see it. The backup is the remedy. The counters (`useCount`,
`lastUsed`) return to their step-1 values.

## The model, as littlesnitch exports it

`rules` is a list of flat dicts:

- `process`: `path.<path without the leading />` (with `*`),
  `identifier.<TEAM>/<bundle id>`, `script.<path>`, an older plain
  `/path`, or absent = any process; `via`, the program it runs through:
  `identifier.APPLE/com.apple.ping` for an Apple program, else its plain path
  (`requiresTrustedSignatureForAnyProcess`: "Require: Trusted Code Signature")
- owner: `uid` = that user's "Me", `owner: "system"`, neither = anyone
- remote: `remote-domains` / `remote-hosts` / `remote-addresses`, or
  `remote: "any"` / `"local-net"`
- `action`: allow / deny / suggestion; `direction` absent = outgoing
- `ports`, `protocol`; `origin`, `creationDate`, `modificationDate`;
  `useCount`, `lastUsed` are Little Snitch's own counters

The traffic log is CSV: date (UTC), direction, uid, ipAddress,
remoteHostname, protocol (6 tcp, 17 udp), port, connectCount, denyCount,
byteCountIn, byteCountOut, connectingExecutable, parentAppExecutable.

## Config

`my-little-snitch --create-config` prints it: `LITTLESNITCH`, `BACKUP_DIR`
(default `/var/db/my-little-snitch`), `OWNER_DEFAULT`,
`PROGRAM_PATH`, `QUIET`/`VRB`/`DBG`. Searched as `--help` lists, first found
wins.

## Tests

`my-little-snitch --run-tests [<FILTER>]` -- TAP, against a stub
littlesnitch that keeps its model in a file; runs as any user, changes
nothing real.
