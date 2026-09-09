"""Validate real pilot outputs, controlled regression outputs and matched settings."""
from pathlib import Path
import math,json
root=Path(__file__).resolve().parents[1]

def metrics(path):
    result={}
    for line in path.read_text().splitlines():
        if ': ' in line:
            key,value=line.split(':',1)
            try: result[key.strip()]=float(value.strip())
            except ValueError: pass
    return result

common='oppo_cache_hit oppo_cache_miss drop_list drop_pit drop_nonce query_count duplicated_query static_cache_hit static_cache_miss response_count false_content_generated false_content_cached false_content_received legitimate_content_received false_content_reception_ratio legitimate_content_satisfaction_ratio total_cache_evictions legitimate_content_evicted_by_false max_cache_occupancy max_false_content_in_cache max_false_cache_ratio average_interval'.split()
zeros='false_content_generated false_content_cached false_content_received false_content_reception_ratio legitimate_content_evicted_by_false max_false_content_in_cache max_false_cache_ratio'.split()
transport='created started relayed dropped removed delivered delivery_prob overhead_ratio latency_avg latency_med hopcount_avg buffertime_avg'.split()
results=[]
for mode in ['Normal','Attack']:
    for buf in ['5k','80k']:
        route='FC' if mode=='Normal' else 'Epi'
        prefix=f'Pilot6h_{mode}_{route}_Int600_TTL180_Buf{buf}_Seed1_'
        ccn=metrics(next((root/'validation/reports').glob(prefix+'*CCN_application_reporter.txt')))
        dtn=metrics(root/'validation/reports'/f'{prefix}MessageStatsReport.txt')
        assert all(k in ccn and math.isfinite(ccn[k]) for k in common)
        assert all(k in dtn and math.isfinite(dtn[k]) for k in transport)
        assert ccn['response_count']==ccn['false_content_received']+ccn['legitimate_content_received']
        assert 0 < ccn['response_count'] <= ccn['query_count']
        for key in ['false_content_reception_ratio','legitimate_content_satisfaction_ratio','max_false_cache_ratio']:
            assert 0<=ccn[key]<=1
        assert math.isclose(ccn['false_content_reception_ratio'],ccn['false_content_received']/ccn['response_count'])
        assert math.isclose(ccn['legitimate_content_satisfaction_ratio'],ccn['legitimate_content_received']/ccn['query_count'])
        assert ccn['max_cache_occupancy']<=10 and ccn['max_false_content_in_cache']<=10
        assert ccn['legitimate_content_evicted_by_false']<=ccn['total_cache_evictions']
        if mode=='Normal':
            assert all(ccn[k]==0 for k in zeros)
            assert ccn['legitimate_content_received']>0
        else:
            assert ccn['false_content_generated']>0 and ccn['false_content_cached']>0 and ccn['false_content_received']>0
        results.append(dict(scenario=mode,buffer=buf,ccn=ccn,dtn=dtn))
for i,mode in enumerate(['Normal','Attack']):
    small,large=results[2*i:2*i+2]
    changes=[k for k in transport if small['dtn'][k]!=large['dtn'][k]]
    print(mode+' 5k vs 80k changed: '+(', '.join(changes) if changes else 'none; plateau'))
for a,b in [(results[0],results[2]),(results[1],results[3])]:
    equal=all(a['dtn'][k]==b['dtn'][k] for k in transport)
    print('Observed paired transport metrics identical at '+a['buffer']+': '+str(equal))
assert any(results[2]['dtn'][k]!=results[3]['dtn'][k] for k in transport), 'No observed attack buffer sensitivity'
# Exact reporter schemas and fractional timing in the controlled cache-path test.
functional=[metrics(next((root/'validation/functional_reports').glob('Functional_'+mode+'_*CCN_application_reporter.txt'))) for mode in ['Normal','Attack']]
assert list(functional[0])==list(functional[1])
assert all(m['average_interval']==0.375 for m in functional)
assert math.isclose(functional[0]['legitimate_content_satisfaction_ratio'],2/3)
for path in (root/'validation/zero_reports').glob('*.txt'):
    m=metrics(path)
    assert all(m[k]==0 for k in common),path
assert len(list((root/'validation/zero_reports').glob('*.txt')))==2
# Raw final settings differ only in the authorized Group 5 treatment, prefixes and report/scenario names.
def settings(path):
    return {line.split('=',1)[0].strip():line.split('=',1)[1].strip() for line in path.read_text().splitlines() if '=' in line and not line.lstrip().startswith('#')}
n=settings(root/'CCN_Normal_configuration.txt'); a=settings(root/'Malicious_injection.txt')
a={k.replace('MaliciousCCN.','ControlSourceCCN.'):v.replace('MaliciousCCN_application','CCN_application').replace('MaliciousCCN','ControlSourceCCN') for k,v in a.items()}
assert 'Group5.router' not in n and n['Group.router']=='FirstContactRouter'
assert a.pop('Group5.router')=='EpidemicRouter'
assert n['Group5.groupID']=='nS' and a['Group5.groupID']=='mS'
a['Group5.groupID']=n['Group5.groupID']
a['Scenario.name']=n['Scenario.name']
assert n==a, {k:(n.get(k),a.get(k)) for k in n.keys()|a.keys() if n.get(k)!=a.get(k)}
normal=[x.split()[1] for x in (root/'validation/logs/audit_normal.log').read_text().splitlines() if x[:1].isdigit()]
attack=[x.split()[1] for x in (root/'validation/logs/audit_attack.log').read_text().splitlines() if x[:1].isdigit()]
assert normal==attack and len(set(normal))==150
serializable=[dict(scenario=r['scenario'],buffer=r['buffer'],ccn=r['ccn'],dtn={k:(v if math.isfinite(v) else None) for k,v in r['dtn'].items()}) for r in results]
(root/'validation/pilot_results.json').write_text(json.dumps(serializable,indent=2,allow_nan=False)+'\n')
print('PASS: schemas, all CCN/DTN required fields, ratios, conservation, clean Normal, active Attack, bounded cache metrics, buffer sensitivity, fractional averages, zero denominators and 150 paired settings.')
