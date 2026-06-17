import { writeFileSync, existsSync, mkdirSync } from 'fs';
import { getFindings, addFinding } from './findings.js';

export async function exportAssetGraph(origin, outputDir = './scans') {
  if (!existsSync(outputDir)) mkdirSync(outputDir, { recursive: true });
  const findings = getFindings();

  const nodes = [];
  const edges = [];
  const seen = new Set();

  const addNode = (id, label, group) => {
    if (seen.has(id)) return;
    seen.add(id);
    nodes.push({ id, label, group });
  };

  addNode('target', origin.replace(/https?:\/\//, '').replace(/\/$/, ''), 'target');
  addNode('findings', 'Findings', 'meta');
  addNode('validation', 'Validation Engine', 'meta');
  addNode('chains', 'Attack Chains', 'meta');

  for (const f of findings) {
    const modId = f.module.replace(/\s+/g, '-').toLowerCase();
    addNode(modId, f.module, 'module');
    edges.push({ from: 'findings', to: modId });

    if (f.validated) {
      edges.push({ from: modId, to: 'validation', label: f.exploitability || '?' });
    }

    for (const mod of ['xss', 'sqli', 'ssrf', 'jwt', 'cors', 'idor', 'lfi', 'xssi', 'oauth', 'saml']) {
      if (f.module.toLowerCase().includes(mod) || f.title.toLowerCase().includes(mod)) {
        const vulnId = `vuln-${mod}`;
        addNode(vulnId, mod.toUpperCase(), f.severity.toLowerCase());
        edges.push({ from: modId, to: vulnId, label: f.severity });
      }
    }
  }

  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><script src="https://d3js.org/d3.v7.min.js"></script><style>
body{margin:0;background:#0d1117;overflow:hidden}#graph{width:100vw;height:100vh}.node{cursor:pointer}.node text{fill:#c9d1d9;font:10px monospace}.link{stroke:#30363d;stroke-opacity:0.6}.critical{fill:#f44336}.high{fill:#ff5722}.medium{fill:#ff9800}.low{fill:#2196f3}.meta{fill:#58a6ff}.module{fill:#8b949e}.target{fill:#3fb950}
</style></head><body><div id="graph"></div><script>
const data={nodes:${JSON.stringify(nodes)},edges:${JSON.stringify(edges)}};
const svg=d3.select("#graph").append("svg").attr("width","100%").attr("height","100%");
const sim=d3.forceSimulation(data.nodes).force("link",d3.forceLink(data.edges).id(d=>d.id).distance(100)).force("charge",d3.forceManyBody().strength(-300)).force("center",d3.forceCenter(window.innerWidth/2,window.innerHeight/2));
const link=svg.append("g").selectAll("line").data(data.edges).join("line").attr("class","link");
const node=svg.append("g").selectAll("g").data(data.nodes).join("g").call(d3.drag().on("start",(e,d)=>{if(!e.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y}).on("drag",(e,d)=>{d.fx=e.x;d.fy=e.y}).on("end",(e,d)=>{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null}));
node.append("circle").attr("r",d=>d.group==='target'?12:d.group==='meta'?8:6).attr("class",d=>d.group);
node.append("text").text(d=>d.label.substring(0,25)).attr("dx",10).attr("dy",4);
sim.on("tick",()=>{link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y).attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);node.attr("transform",d=>\`translate(\${d.x},\${d.y})\`)})</script></body></html>`;

  const path = `${outputDir}/asset-graph.html`;
  writeFileSync(path, html);
  return path;
}

export async function startMonitor(origin, intervalMinutes = 60, spinner) {
  let baseline = null;
  const findings = getFindings();

  const check = async () => {
    spinner.text = `[Monitor] Scanning ${new Date().toLocaleTimeString()}...`;
    const { runRemoteScan } = await import('../../scan.js');

    findings.length = 0;
    await runRemoteScan(origin, spinner, ['headers', 'files', 'tech', 'ssl']);

    if (!baseline) {
      baseline = { score: 100, findings: findings.length, time: Date.now() };
      addFinding('INFO', 'Monitor', `Baseline set (${baseline.score}/100)`,
        `${baseline.findings} findings at baseline`, 'Continuous monitoring active');
    } else {
      if (findings.length > baseline.findings) {
        addFinding('CRITICAL', 'Monitor', `New findings detected! +${findings.length - baseline.findings}`,
          `${findings.length} now vs ${baseline.findings} baseline`, 'Investigate new findings immediately');
      } else if (findings.length < baseline.findings) {
        addFinding('INFO', 'Monitor', `${baseline.findings - findings.length} findings fixed since baseline`,
          `${findings.length} now vs ${baseline.findings} baseline`, 'Good — security posture improving');
      }
    }
  };

  check();
  const interval = setInterval(check, intervalMinutes * 60 * 1000);
  return interval;
}

export function stopMonitor(interval) {
  clearInterval(interval);
}
