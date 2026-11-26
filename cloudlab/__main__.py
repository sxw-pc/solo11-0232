import argparse
import json
from pathlib import Path
from .store import connect,report,replay
from . import pool
from . import claim
from . import recovery
from . import legal_production

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('command',choices=["pool","claim","recovery","legal","demo","report","replay"])
    parser.add_argument('--db',default='demo.sqlite')
    parser.add_argument('--fixture')
    args=parser.parse_args()
    db=connect(args.db)
    def invoke(module,payload):
        return [module.run(db,step) for step in payload] if isinstance(payload,list) else module.run(db,payload)
    if args.command=='report':
        result=report(db)
    elif args.command=='replay':
        db.close()
        result=replay(args.db,{"pool":pool,"claim":claim,"recovery":recovery,"legal":legal_production})
    elif args.command=='demo':
        result=[]
        for name in ["pool","claim","recovery","legal_production"]:
            for file in sorted(Path('fixtures').glob(name+'_*.json')):
                payload=json.loads(file.read_text(encoding='utf-8'))
                result.append({'fixture':str(file),'result':invoke(globals()[name],payload)})
    else:
        if not args.fixture: parser.error('--fixture is required')
        payload=json.loads(Path(args.fixture).read_text(encoding='utf-8'))
        module=legal_production if args.command=='legal' else globals()[args.command]
        result=invoke(module,payload)
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))
    if args.command=='replay' and not result['verified']: raise SystemExit(2)

if __name__=='__main__': main()
