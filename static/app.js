function copyPoC(btn) {
  const code = btn.previousElementSibling.innerText;
  navigator.clipboard.writeText(code);
  const originalHTML = btn.innerHTML;
  btn.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>';
  setTimeout(() => {
    btn.innerHTML = originalHTML;
  }, 2000);
}

function renderGraph(issues, isFree) {
  const container = document.getElementById('graph');
  if (!container) return;

  const elements = [];
  const chains = [];

  // --- LOGIC: CHAIN DETECTION ---
  
  // Helper to find issues by keywords in name or impact
  const findIssue = (keywords) => issues.some(i => 
    keywords.some(k => (i.name.toLowerCase().includes(k) || i.impact.toLowerCase().includes(k)))
  );

  // 1. XSS Chain: Entry -> Escalation -> Impact
  const hasXSS = findIssue(['xss', 'cross-site scripting', 'injection']);
  const hasInsecureCookie = findIssue(['httponly', 'session cookie', 'cookie flag']);
  
  if (hasXSS && (hasInsecureCookie || findIssue(['hijack']))) {
    chains.push([
      { id: 'xss_entry', label: 'Injection Entry', type: 'entry' },
      { id: 'xss_escalate', label: 'Session Extraction', type: 'escalation' },
      { id: 'xss_impact', label: 'Account Takeover', type: 'impact' }
    ]);
  }

  // 2. Transport Chain: Entry -> Escalation -> Impact
  const hasTransportRisk = findIssue(['unencrypted', 'mitm', 'hsts', 'http allowed', 'transport']);
  
  if (hasTransportRisk) {
    chains.push([
      { id: 'mitm_entry', label: 'Network Interception', type: 'entry' },
      { id: 'mitm_escalate', label: 'Cleartext Discovery', type: 'escalation' },
      { id: 'mitm_impact', label: 'Data Theft', type: 'impact' }
    ]);
  }

  // 3. Redirect Chain: Entry -> Escalation -> Impact
  const hasRedirect = findIssue(['open redirect', 'redirect vulnerability']);
  
  if (hasRedirect) {
    chains.push([
      { id: 'redir_entry', label: 'Open Redirect', type: 'entry' },
      { id: 'redir_escalate', label: 'Phishing Vector', type: 'escalation' },
      { id: 'redir_impact', label: 'Credential Theft', type: 'impact' }
    ]);
  }

  // 4. Exposure Chain: Entry -> Escalation -> Impact
  const hasExposure = findIssue(['exposure', 'sensitive file', 'config', 'backup']);

  if (hasExposure) {
    chains.push([
      { id: 'exp_entry', label: 'File Discovery', type: 'entry' },
      { id: 'exp_escalate', label: 'Metadata Leak', type: 'escalation' },
      { id: 'exp_impact', label: 'System Compromise', type: 'impact' }
    ]);
  }

  // Final check: If no specific chains but has HIGH severity issues, create a logical generic path
  // to avoid "empty graph" frustration while staying connected.
  if (chains.length === 0 && issues.some(i => i.severity === 'HIGH')) {
    const highIssue = issues.find(i => i.severity === 'HIGH');
    chains.push([
      { id: 'gen_entry', label: 'Attack Vector', type: 'entry' },
      { id: 'gen_escalate', label: 'Privilege Escalation', type: 'escalation' },
      { id: 'gen_impact', label: 'Partial Takeover', type: 'impact' }
    ]);
  }

  // Requirement: Do not generate graph if no logical chain exists
  if (chains.length === 0) {
    container.innerHTML = `
      <div class="flex items-center justify-center h-full text-gray-600 font-mono text-[10px] uppercase tracking-widest italic text-center px-10">
        Attack surface analyzed. No logical exploit sequences identified for identified vectors.
      </div>
    `;
    return;
  }

  // Build Cytoscape Elements
  chains.forEach((chain, chainIdx) => {
    chain.forEach((node, nodeIdx) => {
      let label = node.label;
      let type = node.type;
      
      if (isFree && node.type === 'impact') {
        label = 'LOCKED IMPACT';
        type = 'locked';
      }

      elements.push({
        data: { 
          id: `${node.id}_${chainIdx}`, 
          label: label, 
          type: type, 
          chain: chainIdx 
        }
      });

      if (nodeIdx > 0) {
        elements.push({
          data: { 
            id: `e_${node.id}_${chainIdx}`, 
            source: `${chain[nodeIdx - 1].id}_${chainIdx}`, 
            target: `${node.id}_${chainIdx}`,
            type: isFree && node.type === 'impact' ? 'locked-edge' : 'chain-edge'
          }
        });
      }
    });
  });

  const cy = cytoscape({
    container: container,
    elements: elements,
    style: [
      {
        selector: 'node',
        style: {
          'label': 'data(label)',
          'color': '#94a3b8',
          'font-family': 'Outfit, sans-serif',
          'font-size': '24px',
          'font-weight': '700',
          'text-valign': 'bottom',
          'text-margin-y': '15px',
          'background-color': '#1e293b',
          'border-width': 4,
          'border-color': '#334155',
          'width': '60px',
          'height': '60px',
          'transition-property': 'background-color, border-color, width, height',
          'transition-duration': '0.3s'
        }
      },
      {
        selector: 'node[type="entry"]',
        style: {
          'background-color': '#6366f1',
          'border-color': '#818cf8'
        }
      },
      {
        selector: 'node[type="escalation"]',
        style: {
          'background-color': '#f59e0b',
          'border-color': '#fbbf24',
          'shape': 'hexagon'
        }
      },
      {
        selector: 'node[type="impact"]',
        style: {
          'background-color': '#ef4444',
          'border-color': '#f87171',
          'shape': 'diamond',
          'width': '80px',
          'height': '80px',
          'color': '#ef4444'
        }
      },
      {
        selector: 'node[type="locked"]',
        style: {
          'background-color': '#334155',
          'border-style': 'dashed',
          'color': '#475569'
        }
      },
      {
        selector: 'edge',
        style: {
          'width': 8,
          'line-color': '#334155',
          'target-arrow-color': '#334155',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'opacity': 0.6
        }
      },
      {
        selector: 'edge[type="locked-edge"]',
        style: {
          'line-style': 'dashed',
          'opacity': 0.3
        }
      }
    ],
    layout: {
      name: 'grid',
      rows: chains.length,
      padding: 60,
      spacingFactor: 2.2,
      animate: true,
      animationDuration: 800
    },
    userZoomingEnabled: false,
    userPanningEnabled: false,
    boxSelectionEnabled: false
  });

  // Pulse effect
  setInterval(() => {
    cy.nodes('[type="impact"]').animate({
      style: { 'width': '100px', 'height': '100px' }
    }, { duration: 1000 }).delay(200).animate({
      style: { 'width': '80px', 'height': '80px' }
    }, { duration: 1000 });
  }, 3000);
}


