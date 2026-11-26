import json
import sqlite3
from contextlib import contextmanager

def connect(filename):
    db=sqlite3.connect(filename, isolation_level=None)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=3000')
    db.execute('CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY, subsystem TEXT NOT NULL, object_id TEXT NOT NULL, event TEXT NOT NULL, version INTEGER NOT NULL, detail TEXT NOT NULL)')
    db.executescript("CREATE TABLE IF NOT EXISTS pools(id TEXT PRIMARY KEY, capacity INTEGER, version INTEGER, racks TEXT, rack_regions TEXT, status TEXT);\n    CREATE TABLE IF NOT EXISTS reservations(id TEXT PRIMARY KEY, pool_id TEXT, amount INTEGER, rack TEXT, expires INTEGER, state TEXT, version INTEGER, plan_id TEXT);\n    CREATE TABLE IF NOT EXISTS placement_plans(id TEXT PRIMARY KEY, pool_id TEXT, replica_size INTEGER, state TEXT);\n    CREATE TABLE IF NOT EXISTS placement_members(plan_id TEXT, rack TEXT, state TEXT, PRIMARY KEY(plan_id,rack));\nCREATE TABLE IF NOT EXISTS claims(id TEXT PRIMARY KEY, size INTEGER, mode TEXT, region TEXT, generation INTEGER);\n    CREATE TABLE IF NOT EXISTS bindings(id TEXT PRIMARY KEY, claim_id TEXT, reservation_id TEXT, workload TEXT, node_region TEXT, state TEXT, token INTEGER);\n    CREATE TABLE IF NOT EXISTS writer_grants(id TEXT PRIMARY KEY, claim_id TEXT, binding_id TEXT, workload TEXT, state TEXT, generation INTEGER);\n    CREATE TABLE IF NOT EXISTS attachments(id TEXT PRIMARY KEY, binding_id TEXT, node_region TEXT, token INTEGER, state TEXT);\nCREATE TABLE IF NOT EXISTS replicas(id TEXT PRIMARY KEY, claim_id TEXT, rack TEXT, generation INTEGER, state TEXT);\n    CREATE TABLE IF NOT EXISTS snapshots(id TEXT PRIMARY KEY, claim_id TEXT, parent TEXT, generation INTEGER, valid INTEGER);\n    CREATE TABLE IF NOT EXISTS recovery_attempts(id TEXT PRIMARY KEY, claim_id TEXT, candidate TEXT, state TEXT, generation INTEGER);\n    CREATE TABLE IF NOT EXISTS fences(id TEXT PRIMARY KEY, claim_id TEXT, primary_id TEXT, generation INTEGER, state TEXT);\n    CREATE TABLE IF NOT EXISTS restore_plans(id TEXT PRIMARY KEY, claim_id TEXT, candidate TEXT, snapshot_id TEXT, state TEXT);")
    db.executescript("CREATE TABLE IF NOT EXISTS rack_evidence(seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT, evidence_version TEXT, pool_id TEXT, rack TEXT, controller TEXT, cabinet TEXT, serial TEXT, backplane TEXT, capacity INTEGER, verified INTEGER, observed_at INTEGER, received_at INTEGER, state TEXT, note TEXT, payload TEXT);\n    CREATE TABLE IF NOT EXISTS capacity_credentials(kind TEXT, object_id TEXT, rack TEXT, pool_id TEXT, physical_key TEXT, domain_key TEXT, evidence_version TEXT, verified INTEGER, capacity INTEGER, cabinet TEXT, serial TEXT, backplane TEXT, controller TEXT, detail TEXT, state TEXT, PRIMARY KEY(kind,object_id,rack));\n    CREATE TABLE IF NOT EXISTS pending_remediation(id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_version TEXT, reason TEXT, kind TEXT, object_id TEXT, pool_id TEXT, physical_key TEXT, amount INTEGER, protected INTEGER, detail TEXT, state TEXT);")
    return db

@contextmanager
def transaction(db):
    nested=db.in_transaction
    db.execute('SAVEPOINT nested_action' if nested else 'BEGIN IMMEDIATE')
    try:
        yield
        db.execute('RELEASE SAVEPOINT nested_action' if nested else 'COMMIT')
    except:
        if nested:
            db.execute('ROLLBACK TO SAVEPOINT nested_action')
            db.execute('RELEASE SAVEPOINT nested_action')
        else: db.execute('ROLLBACK')
        raise

def record(db, subsystem, object_id, event, version, detail):
    db.execute('INSERT INTO evidence(subsystem,object_id,event,version,detail) VALUES(?,?,?,?,?)',
               (subsystem,object_id,event,version,json.dumps(detail,ensure_ascii=False,sort_keys=True)))

def report(db):
    return [dict(row) for row in db.execute('SELECT * FROM evidence ORDER BY id')]

def audit_run(subsystem):
    def decorate(fn):
        def wrapped(db, payload):
            with transaction(db):
                result=fn(db,payload)
                object_id=str(payload.get('id') or payload.get('pool') or payload.get('service') or 'unknown')
                record(db,subsystem,object_id,'decision',int(payload.get('generation',0)),
                       {'input':payload,'result':result})
            return result
        return wrapped
    return decorate

def replay(filename, modules):
    source=connect(filename)
    decisions=[dict(row) for row in source.execute("SELECT subsystem,detail FROM evidence WHERE event='decision' ORDER BY id")]
    target=connect(':memory:')
    divergences=[]
    for index,entry in enumerate(decisions,1):
        fact=json.loads(entry['detail'])
        actual=modules[entry['subsystem']].run(target,fact['input'])
        if actual!=fact['result']:
            divergences.append({'step':index,'subsystem':entry['subsystem'],'expected':fact['result'],'actual':actual})
    tables=[r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('evidence','sqlite_sequence') ORDER BY name")]
    for table in tables:
        if not target.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
            divergences.append({'table':table,'reason':'missing_in_replay'});continue
        before=[tuple(r) for r in source.execute('SELECT * FROM '+table+' ORDER BY rowid')]
        after=[tuple(r) for r in target.execute('SELECT * FROM '+table+' ORDER BY rowid')]
        if before!=after:divergences.append({'table':table,'reason':'state_mismatch','before':before,'after':after})
    source.close();target.close()
    return {'decision_count':len(decisions),'verified':not divergences,'divergences':divergences}
