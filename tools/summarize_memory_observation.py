"""Read-only analysis of VM memory samples. No leak-free certification."""
import json,statistics,sys
from collections import defaultdict
from pathlib import Path

def summarize(r):
    series=defaultdict(list)
    for s in r.get('samples',[]):
        for p in s.get('processes',[]):
            if 'privateBytes' in p:
                series[(p['pid'],p['started'],p['role'])].append((s['elapsedSeconds'],p))
    processes=[]
    for (pid,generation,role),rows in series.items():
        values=[p['privateBytes']/1048576 for _,p in rows]
        times=[t for t,_ in rows]
        mean_t=statistics.mean(times);mean_v=statistics.mean(values)
        denom=sum((t-mean_t)**2 for t in times)
        slope=sum((t-mean_t)*(v-mean_v) for t,v in zip(times,values))/denom*3600 if denom else None
        blocks=[]
        for i in range(4):
            block=[v for t,v in zip(times,values) if i*900<=t<(i+1)*900]
            blocks.append(round(statistics.median(block),2) if block else None)
        processes.append(dict(pid=pid,generation=generation,role=role,samples=len(rows),
            private_start_mib=round(values[0],2),private_end_mib=round(values[-1],2),
            private_peak_mib=round(max(values),2),private_growth_mib=round(values[-1]-values[0],2),
            private_slope_mib_per_hour=round(slope,2) if slope is not None else None,
            quarter_medians_mib=blocks,handles_start=rows[0][1]['handles'],handles_end=rows[-1][1]['handles'],
            handles_peak=max(p['handles'] for _,p in rows),threads_start=rows[0][1]['threads'],threads_end=rows[-1][1]['threads'],
            working_set_start_mib=round(rows[0][1]['workingSetBytes']/1048576,2),
            working_set_end_mib=round(rows[-1][1]['workingSetBytes']/1048576,2)))
    samples=r.get('samples',[]);last=samples[-1] if samples else {}
    before=r.get('before',{}).get('counter_totals',{});after=last.get('counters',{})
    return dict(status=r['status'],elapsed_seconds=round(r['elapsedSeconds'],1),samples=len(samples),
        policy_unchanged=r.get('policyBefore')==r.get('policyAfter'),errors=r.get('errors',[]),
        deltas={k:after[k]-before[k] for k in ('events_generated','events_delivered','events_dropped','events_flushed') if k in before and k in after},
        final_pending=last.get('pending'),final_kernel_queue=last.get('kernelQueue'),
        max_pending=max((s.get('pending',0) for s in samples),default=0),
        sample_errors=[p for s in samples for p in s.get('processes',[]) if 'sampleError' in p],processes=processes)

if __name__=='__main__':
    result=summarize(json.loads(Path(sys.argv[1]).read_text(encoding='utf-8-sig')))
    print(json.dumps(result,ensure_ascii=False,indent=2))
