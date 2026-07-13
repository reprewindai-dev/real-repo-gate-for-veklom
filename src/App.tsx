import { useState, useEffect } from 'react';
import { TerminalEvent, VerifiedFinding, RiskLevel, RiskGateScan, PolicyResult, PolicyRule } from './types';
import { 
  DEFAULT_RULES, 
  calculateCanonicalHash, 
  generateFilesForRepo, 
  scanFilesForFindings, 
  determineOverallRisk,
  VeklomAudioEngine,
  announceSpeech
} from './utils';
import { RiskIndicators } from './components/RiskIndicators';
import { EvidenceLedger } from './components/EvidenceLedger';
import { ManualReviewModal } from './components/ManualReviewModal';
import { 
  Shield, 
  Play, 
  CheckCircle, 
  AlertTriangle, 
  Search, 
  Database, 
  Cpu, 
  Compass, 
  RefreshCw,
  Clock,
  Volume2,
  VolumeX,
  MessageSquare,
  HelpCircle,
  Laptop,
  Smartphone,
  Tablet
} from 'lucide-react';

// Preset options for quick operator testing
const REPO_PRESETS = [
  { url: 'https://github.com/veklom-ai/core-kernel', name: 'veklom-ai/core-kernel', label: 'Core kernel', desc: 'Critical Risk: Native Platform Core Security' },
  { url: 'https://github.com/expressjs/express-stripe-node', name: 'expressjs/express-stripe-node', label: 'Express / Stripe Node', desc: 'Enterprise Risk: Combined Router Framework & Stripe Node Integrations' },
  { url: 'https://github.com/kubernetes/kubernetes', name: 'kubernetes/kubernetes', label: 'Kubernetes', desc: 'Complex Infrastructure Audit: Truncated Cluster Matrix' }
];

export default function App() {
  // Input URL
  const [repoUrl, setRepoUrl] = useState('https://github.com/veklom-ai/core-kernel');
  const [errorText, setErrorText] = useState('');

  // Custom Target Scenario Scopes
  const [customScenariosList, setCustomScenariosList] = useState<string[]>([
    'src/auth/private_keys.key',
    'db/migrations/009_drop_tenant.sql',
    'deploy/k8s/v1_cluster.yaml'
  ]);
  const [newScenarioInput, setNewScenarioInput] = useState('');
  const [isScenariosOpen, setIsScenariosOpen] = useState(false);

  // Scanning State
  const [scanState, setScanState] = useState<RiskGateScan>({
    run_id: 'run_8fa29d',
    agent_id: 'agent_041',
    status: 'idle',
    repo_url: 'https://github.com/veklom-ai/core-kernel',
    repo_owner: 'veklom-ai',
    repo_name: 'core-kernel',
    default_branch: 'main',
    risk_level: 'CRITICAL',
    tree_truncated: false,
    files_seen: 16
  });

  // Distracted user/Aura state variables
  const [audioEnabled, setAudioEnabled] = useState(true);
  const [speechEnabled, setSpeechEnabled] = useState(false);
  const [m2mEnabled, setM2mEnabled] = useState(false);
  const [audioEngine] = useState(() => new VeklomAudioEngine());

  // Enriched GPC Historical Sweep Telemetry state (SOC2 Value tracking)
  const [history, setHistory] = useState<any[]>(() => {
    try {
      const saved = localStorage.getItem('veklom_sweep_history_v2');
      if (saved) {
        return JSON.parse(saved);
      }
    } catch (e) {
      console.error('Error loading history:', e);
    }
    return [
      { 
        name: '18FA', 
        remediated: 3, 
        blocked: 1, 
        critical: 3, 
        warning: 5,
        valueMessage: 'Credential Leak Defused: Auto-remediation virtualized raw private keys, averting credentials harvesting and SOC2 compliance failures.' 
      },
      { 
        name: '191B', 
        remediated: 1, 
        blocked: 0, 
        critical: 0, 
        warning: 1,
        valueMessage: 'Clean Integration Build: Micro-agent verified all deployment paths. Zero policy deviations detected on primary branch.' 
      },
      { 
        name: '204A', 
        remediated: 2, 
        blocked: 2, 
        critical: 2, 
        warning: 3,
        valueMessage: 'Multi-Tenant Shield Active: Stopped an RBAC bypass attempt and raw SQL injection. Preserved strict database partition boundaries.' 
      },
      { 
        name: '211C', 
        remediated: 3, 
        blocked: 1, 
        critical: 1, 
        warning: 4,
        valueMessage: 'Stripe Webhook Enforce: Mitigated unverified billing calls. Secured payment hooks with strict signature checks, preventing financial leakages.' 
      },
      { 
        name: '225M', 
        remediated: 4, 
        blocked: 2, 
        critical: 4, 
        warning: 6,
        valueMessage: 'Infrastructure Lock: Intercepted a privilege escalation attempt in Kubernetes cluster configurations, securing container host runtime.' 
      },
      { 
        name: '2711', 
        remediated: 5, 
        blocked: 3, 
        critical: 5, 
        warning: 7,
        valueMessage: 'Critical Database Save: Prevented tenant-drop SQL migration execution. Preserved active DB schema integrity & isolated developer errors.' 
      }
    ];
  });

  const handleResetHistory = () => {
    const defaultHist = [
      { 
        name: '18FA', 
        remediated: 3, 
        blocked: 1, 
        critical: 3, 
        warning: 5,
        valueMessage: 'Credential Leak Defused: Auto-remediation virtualized raw private keys, averting credentials harvesting and SOC2 compliance failures.' 
      },
      { 
        name: '191B', 
        remediated: 1, 
        blocked: 0, 
        critical: 0, 
        warning: 1,
        valueMessage: 'Clean Integration Build: Micro-agent verified all deployment paths. Zero policy deviations detected on primary branch.' 
      },
      { 
        name: '204A', 
        remediated: 2, 
        blocked: 2, 
        critical: 2, 
        warning: 3,
        valueMessage: 'Multi-Tenant Shield Active: Stopped an RBAC bypass attempt and raw SQL injection. Preserved strict database partition boundaries.' 
      },
      { 
        name: '211C', 
        remediated: 3, 
        blocked: 1, 
        critical: 1, 
        warning: 4,
        valueMessage: 'Stripe Webhook Enforce: Mitigated unverified billing calls. Secured payment hooks with strict signature checks, preventing financial leakages.' 
      },
      { 
        name: '225M', 
        remediated: 4, 
        blocked: 2, 
        critical: 4, 
        warning: 6,
        valueMessage: 'Infrastructure Lock: Intercepted a privilege escalation attempt in Kubernetes cluster configurations, securing container host runtime.' 
      },
      { 
        name: '2711', 
        remediated: 5, 
        blocked: 3, 
        critical: 5, 
        warning: 7,
        valueMessage: 'Critical Database Save: Prevented tenant-drop SQL migration execution. Preserved active DB schema integrity & isolated developer errors.' 
      }
    ];
    setHistory(defaultHist);
    try {
      localStorage.setItem('veklom_sweep_history_v2', JSON.stringify(defaultHist));
    } catch (e) {
      console.error(e);
    }
  };

  // Viewport mode and mobile active tab configurations
  const [viewportMode, setViewportMode] = useState<'responsive' | 'pc' | 'mobile_sim'>(() => {
    try {
      const saved = localStorage.getItem('veklom_viewport_mode');
      if (saved) return saved as any;
    } catch {}
    return 'responsive';
  });
  const [mobileActiveTab, setMobileActiveTab] = useState<'scan' | 'logs' | 'risks' | 'ledger' | 'policies'>('scan');
  const [windowWidth, setWindowWidth] = useState(typeof window !== 'undefined' ? window.innerWidth : 1024);

  useEffect(() => {
    const handleResize = () => setWindowWidth(window.innerWidth);
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  useEffect(() => {
    localStorage.setItem('veklom_viewport_mode', viewportMode);
  }, [viewportMode]);

  // Mobile/Tablet views segment toggler (only visible on mobile layouts)
  const [activeTab, setActiveTab] = useState<'terminal' | 'analytics'>('terminal');

  // Real-time ticking UTC clock state
  const [currentUtcTime, setCurrentUtcTime] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const year = now.getUTCFullYear();
      const month = String(now.getUTCMonth() + 1).padStart(2, '0');
      const day = String(now.getUTCDate()).padStart(2, '0');
      const hours = String(now.getUTCHours()).padStart(2, '0');
      const minutes = String(now.getUTCMinutes()).padStart(2, '0');
      const seconds = String(now.getUTCSeconds()).padStart(2, '0');
      setCurrentUtcTime(`${year}-${month}-${day} ${hours}:${minutes}:${seconds} UTC`);
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  // Events & Findings lists
  const [events, setEvents] = useState<TerminalEvent[]>([]);
  const [findings, setFindings] = useState<VerifiedFinding[]>([]);
  const [scannedFilesList, setScannedFilesList] = useState<string[]>(() => {
    const { paths } = generateFilesForRepo('https://github.com/veklom-ai/core-kernel');
    return paths;
  });
  const [currentStepIndex, setCurrentStepIndex] = useState(-1);
  const [dbPoolCount, setDbPoolCount] = useState(12);

  // Dynamic calculation of active M2M background agents
  const getActiveM2mAgents = () => {
    if (!m2mEnabled) return 0;
    
    const remediatingPaths = new Set<string>();
    const verifiedPaths = new Set<string>();
    
    events.forEach(evt => {
      if (evt.event_type === 'm2m.remediating' && evt.target) {
        remediatingPaths.add(evt.target);
      }
      if (evt.event_type === 'm2m.verified' && evt.target) {
        verifiedPaths.add(evt.target);
      }
    });
    
    let activeSwarmCount = 0;
    remediatingPaths.forEach(path => {
      if (!verifiedPaths.has(path)) {
        activeSwarmCount += 2; // [Refactor-Agent-Alpha] and [Security-Shield-Guard]
      }
    });
    
    return 1 + activeSwarmCount; // 1 standby listener agent + active activeSwarmCount
  };
  const activeAgents = getActiveM2mAgents();

  // Operator Decision Intercept Modal States
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [activeInterceptedFinding, setActiveInterceptedFinding] = useState<VerifiedFinding | null>(null);

  // Stable audit hash representation
  const [auditHash, setAuditHash] = useState('6f8e9a2b5c1d7e4f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f');

  // Backend source-of-truth buffers
  const [backendEvents, setBackendEvents] = useState<any[]>([]);
  const [backendFindings, setBackendFindings] = useState<any[]>([]);

  // Multi-Channel Notification triggers (when waiting for human authorization)
  useEffect(() => {
    let intervalId: any;
    if (scanState.status === 'awaiting_decision') {
      let toggle = false;
      intervalId = setInterval(() => {
        document.title = toggle ? '⚠️ INTERCEPT OVERRIDE REQUIRED' : 'Veklom Risk Gate v1.0.0';
        toggle = !toggle;
      }, 1000);
    } else if (scanState.status === 'scanning' || scanState.status === 'fetching') {
      document.title = '🔄 Sweeping Repository Tree...';
    } else {
      document.title = 'Veklom Risk Gate v1.0.0';
    }
    return () => {
      clearInterval(intervalId);
      document.title = 'Veklom Risk Gate v1.0.0';
    };
  }, [scanState.status]);

  // Keyboard Shortcuts hook (for advanced desktop PC operations)
  useEffect(() => {
    const handleGateHotkeys = (e: KeyboardEvent) => {
      if (isModalOpen && activeInterceptedFinding) {
        const key = e.key.toLowerCase();
        if (key === 'a') {
          handleOperatorDecision('APPROVED', 'Self-certified: Hot-key approved verification sign-off.');
        } else if (e.key === 'e' || key === 'e') {
          handleOperatorDecision('ESCALATED', 'Hot-key elevated state: Transferred to senior security officer review.');
        } else if (e.key === 'b' || key === 'b') {
          handleOperatorDecision('BLOCKED', 'Keyboard directive: Manual isolation block logged.');
        }
      }
    };
    window.addEventListener('keydown', handleGateHotkeys);
    return () => window.removeEventListener('keydown', handleGateHotkeys);
  }, [isModalOpen, activeInterceptedFinding]);

  // Trigger state evaluation and stable hashing
  useEffect(() => {
    const updateHash = async () => {
      const generated = await calculateCanonicalHash(events);
      setAuditHash(generated);
    };
    updateHash();
  }, [events]);

  // Handle preset repository selection
  const handleSelectPreset = (url: string) => {
    setRepoUrl(url);
    setErrorText('');
    
    // Animate audio signal for feedback
    if (audioEnabled) {
      audioEngine.playChime('start');
    }
  };

  // Helper: Append a new event sequentially with sequence control
  const emitEvent = (
    type: string,
    message: string,
    target: string = '',
    policy: PolicyResult | 'none' = 'none',
    logLevel?: 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL'
  ): TerminalEvent => {
    let determinedLevel: 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL' = 'INFO';
    if (type === 'file.access.blocked' || policy === 'blocked_env_boundary') {
      determinedLevel = 'CRITICAL';
    } else if (type === 'policy.gate.triggered' || policy === 'escalate_to_security' || policy === 'human_approval_required') {
      determinedLevel = 'ERROR';
    } else if (type === 'git.tree.warning' || type === 'finding.alert') {
      determinedLevel = 'WARN';
    }

    const timestamp = new Date().toISOString();
    const newEvent: TerminalEvent = {
      id: `evt_${Date.now()}_${Math.random().toString(36).substr(2, 4)}`,
      run_id: scanState.run_id,
      agent_id: scanState.agent_id,
      event_type: type,
      target: target,
      policy_result: policy,
      message: message,
      timestamp: timestamp,
      hash: '', // secure cryptographic placeholder
      sequence_no: events.length + 1,
      log_level: logLevel || determinedLevel
    };

    setEvents(prev => {
      const updated = [...prev, newEvent];
      // Sync DB Pool mock movements for added realism
      setDbPoolCount(Math.min(15, Math.max(1, 12 + (updated.length % 3) - (updated.length % 2))));
      return updated;
    });

    return newEvent;
  };

  // Validates user input URL format
  const validateUrl = (url: string): { owner: string; repo: string } | null => {
    let normalized = url.replace(/^(https?:\/\/)?(www\.)?/, '').trim();
    if (!normalized.startsWith('github.com/')) {
      return null;
    }
    const pathParts = normalized.replace('github.com/', '').split('/');
    if (pathParts.length < 2 || !pathParts[0].trim() || !pathParts[1].trim()) {
      return null;
    }
    return {
      owner: pathParts[0].trim(),
      repo: pathParts[1].replace('.git', '').trim()
    };
  };

  // Resets logs and generates file assets, then kicks off scan
  const startGovernedReview = async () => {
    const parsed = validateUrl(repoUrl);
    if (!parsed) {
      setErrorText('Please enter a valid GitHub URL, e.g., github.com/owner/repo');
      return;
    }
    setErrorText('');

    // Play visual & sound chimes
    if (audioEnabled) {
      audioEngine.playChime('start');
    }
    if (speechEnabled) {
      announceSpeech(`Launching custom risk sweep on repository default tree path.`);
    }

    setScanState(prev => ({
      ...prev,
      status: 'fetching',
      repo_url: repoUrl,
      repo_owner: parsed.owner,
      repo_name: parsed.repo,
      risk_level: 'unknown',
      files_seen: 0,
    }));

    // Make sure smaller devices prioritize the Terminal console panel on sweep launch
    setActiveTab('terminal');
    setMobileActiveTab('logs');

    setEvents([]);
    setFindings([]);
    setCurrentStepIndex(0);

    const { paths } = generateFilesForRepo(repoUrl);
    // Combine standard files with user's custom scenarios list
    const combinedPaths = [...paths];
    customScenariosList.forEach(customP => {
      if (customP && !combinedPaths.includes(customP)) {
        combinedPaths.push(customP);
      }
    });
    setScannedFilesList(combinedPaths);

    try {
      const res = await fetch('/api/v1/repo-risk-gate/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          repo_url: repoUrl, 
          m2m: m2mEnabled,
          custom_paths: customScenariosList
        })
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }
      const runData = await res.json();

      const eventsRes = await fetch(`/api/v1/repo-risk-gate/runs/${runData.run_id}/events`);
      const findingsRes = await fetch(`/api/v1/repo-risk-gate/runs/${runData.run_id}/findings`);

      const eventsData = await eventsRes.json();
      const findingsData = await findingsRes.json();

      setBackendEvents(eventsData);
      setBackendFindings(findingsData);

      setScanState(prev => ({
        ...prev,
        run_id: runData.run_id,
        agent_id: runData.agent_id,
        default_branch: runData.default_branch || 'main',
        tree_truncated: runData.tree_truncated,
        files_seen: runData.files_seen,
        risk_level: runData.risk_level,
        status: 'scanning'
      }));

      setCurrentStepIndex(0);
    } catch (err: any) {
      setErrorText(err.message || 'Scan failed to communicate with backend gateway');
      setScanState(prev => ({ ...prev, status: 'failed' }));
    }
  };

  // Scan execution step controller
  useEffect(() => {
    if (scanState.status !== 'scanning') return;
    if (backendEvents.length === 0) return;

    const timeout = setTimeout(() => {
      if (currentStepIndex < backendEvents.length) {
        const nextEvt = backendEvents[currentStepIndex];

        const mappedEvent: TerminalEvent = {
          id: nextEvt.event_id,
          run_id: nextEvt.run_id,
          agent_id: nextEvt.agent_id,
          event_type: nextEvt.event_type,
          target: nextEvt.target || '',
          policy_result: nextEvt.policy_result || 'none',
          message: nextEvt.message,
          timestamp: nextEvt.created_at || new Date().toISOString(),
          hash: nextEvt.event_hash || '',
          sequence_no: nextEvt.sequence_no
        };

        setEvents(prev => [...prev, mappedEvent]);

        // Push finding if it matches the warning/alert
        if (nextEvt.event_type === 'finding.alert' && nextEvt.target) {
          const findingForPath = backendFindings.find(f => f.path === nextEvt.target);
          if (findingForPath) {
            setFindings(prev => {
              if (prev.some(f => f.id === findingForPath.finding_id)) return prev;
              return [...prev, {
                id: findingForPath.finding_id,
                run_id: findingForPath.run_id,
                path: findingForPath.path,
                matched_rule: findingForPath.matched_rule,
                policy_result: findingForPath.policy_result,
                risk_level: findingForPath.risk_level,
                reason: findingForPath.reason,
                created_at: findingForPath.created_at
              }];
            });
          }
        }

        if (nextEvt.event_type === 'finding.alert' && audioEnabled) {
          audioEngine.playChime('alert');
        }
        if (nextEvt.event_type === 'm2m.intercept' && speechEnabled) {
          announceSpeech(`M2M daemon active. Intercepting violation on path: ${nextEvt.target}`);
        }
        if (nextEvt.event_type === 'm2m.patch' && speechEnabled) {
          announceSpeech(`M2M swarm successfully patched vulnerability.`);
        }
        if (nextEvt.event_type === 'file.access.blocked' && speechEnabled) {
          announceSpeech(`Direct infrastructure mutation blocked for path: ${nextEvt.target}`);
        }

        const matchingFinding = backendFindings.find(f => f.path === nextEvt.target);
        if (
          nextEvt.event_type === 'policy.gate.triggered' &&
          matchingFinding &&
          (matchingFinding.policy_result === 'human_approval_required' || matchingFinding.policy_result === 'escalate_to_security')
        ) {
          setScanState(prev => ({ ...prev, status: 'awaiting_decision' }));
          setActiveInterceptedFinding({
            id: matchingFinding.finding_id,
            run_id: matchingFinding.run_id,
            path: matchingFinding.path,
            matched_rule: matchingFinding.matched_rule,
            policy_result: matchingFinding.policy_result,
            risk_level: matchingFinding.risk_level,
            reason: matchingFinding.reason,
            created_at: matchingFinding.created_at
          });
          setIsModalOpen(true);

          if (audioEnabled) {
            audioEngine.playChime('alert');
          }
          if (speechEnabled) {
            announceSpeech(`Global policy violation warning on path: ${matchingFinding.path}. operator signature required.`);
          }
          return;
        }

        setCurrentStepIndex(prev => prev + 1);
      } else {
        setScanState(prev => ({ ...prev, status: 'completed' }));
        if (audioEnabled) {
          audioEngine.playChime('complete');
        }
        if (speechEnabled) {
          announceSpeech("Governance tree check finished. Sovereign ledger hash safely verified and sealed.");
        }

        // Record historical scan telemetry v2
        setHistory(prev => {
          const shortLabel = scanState.run_id.replace(/^run_/i, '').trim().toUpperCase();
          const alreadyLogged = prev.some(item => item.name === shortLabel);
          if (alreadyLogged) return prev;

          const activeCritical = findings.filter(f => f.risk_level === 'CRITICAL' && !f.remediated).length;
          const activeHigh = findings.filter(f => f.risk_level === 'HIGH' && !f.remediated).length;
          const activeMedium = findings.filter(f => f.risk_level === 'MEDIUM' && !f.remediated).length;
          const activeLow = findings.filter(f => f.risk_level === 'LOW' && !f.remediated).length;

          const currentCritical = activeCritical + activeHigh;
          const currentWarning = activeMedium + activeLow;

          // Value-Added Remediation (Remediated findings are active shields where M2M saved the day!)
          const remediatedCount = findings.filter(f => f.remediated).length;
          // Policy Blocked (Non-remediated findings or hard blocks requiring operator override)
          const blockedCount = findings.filter(f => !f.remediated).length;

          let valueMessage = '';
          if (remediatedCount > 0 && blockedCount > 0) {
            valueMessage = `Dual Protection Engaged: M2M Daemon deployed ${remediatedCount} active auto-remediations (securing vulnerabilities), while blocking ${blockedCount} unauthorized operations pending audit approval.`;
          } else if (remediatedCount > 0) {
            valueMessage = `Autonomous Shielding Active: Successfully applied ${remediatedCount} live container patches. Eliminated critical risks with zero developer friction or downtime.`;
          } else if (blockedCount > 0) {
            valueMessage = `Policy Gate Intervention: Intercepted ${blockedCount} unauthorized development practices. Quarantined file changes to ensure SOC2 and relational compliance.`;
          } else {
            valueMessage = `Nominal Sweep: Standard compliance audit validated. Zero policy violations detected on live files.`;
          }

          const newRecord = {
            name: shortLabel,
            remediated: remediatedCount,
            blocked: blockedCount,
            critical: currentCritical,
            warning: currentWarning,
            valueMessage: valueMessage
          };

          const updatedHistory = [...prev, newRecord];
          if (updatedHistory.length > 7) {
            updatedHistory.shift();
          }

          try {
            localStorage.setItem('veklom_sweep_history_v2', JSON.stringify(updatedHistory));
          } catch (e) {
            console.error(e);
          }
          return updatedHistory;
        });
      }
    }, 400);

    return () => clearTimeout(timeout);
  }, [scanState.status, currentStepIndex, backendEvents, backendFindings]);

  // Handle user decision submitted from intercept modal
  const handleOperatorDecision = async (decision: 'APPROVED' | 'ESCALATED' | 'BLOCKED', note: string) => {
    setIsModalOpen(false);

    if (speechEnabled) {
      announceSpeech(`Operator signature: action ${decision} validated. Resuming sweep.`);
    }

    try {
      const res = await fetch(`/api/v1/repo-risk-gate/runs/${scanState.run_id}/decision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision, note })
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }

      const eventsRes = await fetch(`/api/v1/repo-risk-gate/runs/${scanState.run_id}/events`);
      const updatedEvents = await eventsRes.json();
      setBackendEvents(updatedEvents);

      setScanState(prev => ({
        ...prev,
        status: 'scanning',
        decision: decision,
        decision_note: note,
        decision_at: new Date().toISOString()
      }));

      setCurrentStepIndex(prev => prev + 1);
      setActiveInterceptedFinding(null);
    } catch (err: any) {
      setErrorText('Failed to submit decision: ' + err.message);
    }
  };

  // Calculate scan progress metrics
  const totalSteps = scannedFilesList.length + 3;
  let progressPercent = 0;
  if (scanState.status === 'idle') {
    progressPercent = 0;
  } else if (scanState.status === 'completed') {
    progressPercent = 100;
  } else {
    const activeStep = currentStepIndex === -1 ? totalSteps : currentStepIndex;
    progressPercent = Math.min(100, Math.round((activeStep / totalSteps) * 100));
  }

  return (
    <div className="min-h-screen bg-[#0F0F0F] text-[#E0E0E0] font-sans flex flex-col p-2 sm:p-4 md:p-8 m-0 select-none">
      
      {/* High-Contrast Priority flashing ticker active when waiting for decision */}
      {scanState.status === 'awaiting_decision' && (
        <div className="w-full bg-[#FF6B00] text-black py-2 px-4 sm:px-8 font-mono text-xs font-black uppercase tracking-[0.2em] animate-pulse flex items-center justify-between z-40 select-none shrink-0 border-b border-white/20 select-text">
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-black animate-ping"></span>
            <span>🚨 [GPC MUTATION INTERCEPT ACTIVE] Global Policy safety gate triggered</span>
          </div>
          <span className="hidden md:inline-block text-[10px] text-neutral-900 border border-black/30 px-2 font-bold select-none text-right">
            Action required. Press "A" to Approve, "B" to Block, "E" to Escalate
          </span>
        </div>
      )}

      <div className="w-full max-w-7xl mx-auto bg-[#0F0F0F] border-2 sm:border-4 md:border-8 border-[#1A1A1A] flex flex-col overflow-y-auto shadow-2xl relative flex-1">        {/* Sleek, Ultra-Minimalist Veklom Brand Header */}
        <header className="flex flex-col lg:flex-row items-start lg:items-center justify-between px-4 sm:px-6 md:px-10 py-2 border-b border-[#222] bg-[#0A0A0A] gap-4">
          {/* Left panel: Compact Logo & Navigation context */}
          <div className="flex flex-row items-center gap-2.5 sm:gap-3.5">
            {/* Real Veklom Logo SVG + Brand Text */}
            <div className="flex items-center space-x-2 select-text">
              <svg viewBox="0 0 100 100" className="w-5 h-5 select-none shrink-0" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M 22 25 L 50 80 L 78 25" stroke="#FF6B00" strokeWidth="15" strokeLinecap="round" strokeLinejoin="round" />
                <circle cx="50" cy="45" r="9.5" fill="#FF6B00" />
              </svg>
              <span className="text-sm font-bold tracking-tight text-white font-sans lowercase">veklom</span>
            </div>

            {/* Context line separation */}
            <div className="h-4 w-px bg-neutral-800" />

            <div className="flex items-center gap-1.5 font-mono">
              <span className="text-[10px] sm:text-xs tracking-wider text-[#FF6B00] uppercase font-bold">
                Repo Risk Gate
              </span>
              <span className="hidden sm:inline-block text-[8px] sm:text-[9px] text-gray-500 uppercase tracking-wider bg-neutral-900 border border-neutral-800/60 px-1.5 py-0.5 rounded">
                Dev Scope
              </span>
            </div>
          </div>

          {/* Right panel: Controls & Sweep Input */}
          <div className="w-full lg:w-[55%] flex flex-col sm:flex-row items-stretch sm:items-center gap-3 md:justify-end">
            {/* Extremely compact Operator settings directly inline to save space! */}
            <div className="flex items-center space-x-2 shrink-0 bg-neutral-950 p-1 border border-neutral-800/60 rounded">
              {/* Sound alert switch */}
              <button
                onClick={() => setAudioEnabled(!audioEnabled)}
                title="Toggle Multi-Channel Web Audio Alerts Synthesizer"
                className={`flex items-center space-x-1 py-1 px-2 border transition-all cursor-pointer rounded ${
                  audioEnabled 
                    ? 'border-[#00FF41]/30 text-[#00FF41] bg-[#00FF41]/5' 
                    : 'border-transparent text-gray-500 hover:text-gray-400'
                }`}
              >
                {audioEnabled ? <Volume2 className="w-3.5 h-3.5 text-[#00FF41]" /> : <VolumeX className="w-3.5 h-3.5 text-gray-500" />}
                <span className="uppercase text-[9px] font-mono font-bold tracking-tight">Audio {audioEnabled ? 'ON' : 'OFF'}</span>
              </button>

              {/* Speech alert switch */}
              <button
                onClick={() => setSpeechEnabled(!speechEnabled)}
                title="Announce scan intercepts, errors, policy triggers, and completions dynamically out loud"
                className={`flex items-center space-x-1 py-1 px-2 border transition-all cursor-pointer rounded ${
                  speechEnabled 
                    ? 'border-[#FF6B00]/30 text-[#FF6B00] bg-[#FF6B00]/5' 
                    : 'border-transparent text-gray-500 hover:text-gray-400'
                }`}
              >
                <MessageSquare className={`w-3.5 h-3.5 ${speechEnabled ? 'text-[#FF6B00]' : 'text-gray-500'}`} />
                <span className="uppercase text-[9px] font-mono font-bold tracking-tight lowercase">Voice {speechEnabled ? 'on' : 'off'}</span>
              </button>

              {/* M2M Autonomous daemon switch & Health Pulse Indicator */}
              <div className="flex items-center space-x-1.5">
                <button
                  onClick={() => {
                    const val = !m2mEnabled;
                    setM2mEnabled(val);
                    if (speechEnabled) {
                      announceSpeech(val ? "M2M background remediation daemon active. Machine to Machine blocking bypassed." : "M2M daemon deactivated.");
                    }
                  }}
                  title="Enable M2M Autonomous Auto-Remediation Daemon. Intercepts vulnerabilities and patches code in-memory on the fly, yielding seamless A+ compliance scores without human operator blockage."
                  className={`flex items-center space-x-1 py-1 px-2 border transition-all cursor-pointer rounded ${
                    m2mEnabled 
                      ? 'border-cyan-500/30 text-cyan-400 bg-cyan-500/5 shadow-[0_0_8px_rgba(6,182,212,0.15)]' 
                      : 'border-transparent text-gray-500 hover:text-gray-400'
                  }`}
                >
                  <Cpu className={`w-3.5 h-3.5 ${m2mEnabled ? 'text-cyan-400' : 'text-gray-500'}`} />
                  <span className="uppercase text-[9px] font-mono font-bold tracking-tight">M2M Fixer {m2mEnabled ? 'ACTIVE' : 'OFF'}</span>
                </button>

                {/* Subtle Health pulse indicator */}
                <div 
                  className={`flex items-center space-x-1.5 px-1.5 py-1 border rounded text-[8px] font-mono font-bold uppercase tracking-wider transition-all duration-300 ${
                    !m2mEnabled 
                      ? 'border-neutral-800/40 text-neutral-600 bg-neutral-900/10' 
                      : activeAgents === 1 
                        ? 'border-emerald-500/20 text-emerald-400 bg-emerald-500/5' 
                        : 'border-amber-500/30 text-amber-400 bg-amber-500/5 shadow-[0_0_10px_rgba(245,158,11,0.15)]'
                  }`}
                  title={
                    !m2mEnabled 
                      ? 'M2M Daemon Offline. No background agents active.' 
                      : activeAgents === 1 
                        ? 'M2M Daemon Online. 1 standby listener agent active.' 
                        : `M2M Remediation Swarm Active! ${activeAgents} background agents patching and verifying threats.`
                  }
                >
                  <span className="relative flex h-1.5 w-1.5">
                    <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${
                      !m2mEnabled 
                        ? 'bg-neutral-600' 
                        : activeAgents === 1 
                          ? 'bg-emerald-400 animate-ping' 
                          : 'bg-amber-400 animate-[ping_1s_infinite]'
                    }`}></span>
                    <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${
                      !m2mEnabled 
                        ? 'bg-neutral-600' 
                        : activeAgents === 1 
                          ? 'bg-emerald-500' 
                          : 'bg-amber-500'
                    }`}></span>
                  </span>
                  <span className="text-[8.5px] font-bold tracking-tight">
                    {m2mEnabled 
                      ? `Health: ${activeAgents} Agent${activeAgents > 1 ? 's' : ''}` 
                      : 'Health: OFF'
                    }
                  </span>
                </div>
              </div>
            </div>

            {/* Input & Run buttons */}
            <div className="flex-1 flex items-center bg-[#050505] border border-[#222] hover:border-neutral-700 transition-colors px-2.5 py-1.5 text-white h-9">
              <Search className="w-3.5 h-3.5 text-[#555] mr-1.5 shrink-0" />
              <input
                type="text"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="github.com/veklom-ai/core-kernel"
                onKeyDown={(e) => { if(e.key === 'Enter') startGovernedReview(); }}
                className="bg-transparent border-0 outline-none text-xs w-full font-mono text-gray-100 placeholder-neutral-700 focus:ring-0 focus:outline-none"
                title="Press enter to launch scan workflow"
              />
            </div>

            <button
              onClick={startGovernedReview}
              disabled={scanState.status === 'fetching' || scanState.status === 'scanning' || scanState.status === 'awaiting_decision'}
              className="py-1.5 px-3 bg-[#FF6B00] hover:bg-opacity-80 text-black font-extrabold text-[11px] uppercase tracking-wider h-9 flex items-center justify-center space-x-1.5 transition-all disabled:opacity-40 disabled:cursor-not-allowed select-none cursor-pointer border border-[#FF6B00] touch-manipulation font-mono shrink-0"
            >
              {scanState.status === 'fetching' || scanState.status === 'scanning' ? (
                <>
                  <RefreshCw className="w-3 h-3 animate-spin" />
                  <span>Sweeping...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-black stroke-[2]" />
                  <span>Run Scan</span>
                </>
              )}
            </button>
          </div>
        </header>

        {/* Dynamic High-Visibility Progress Bar */}
        <div id="scan-progress-bar" className="w-full bg-[#050505] border-b border-[#222] select-none">
          <div className="relative h-1 w-full bg-[#111] overflow-hidden">
            <div 
              className="absolute top-0 left-0 h-full bg-gradient-to-r from-orange-600 via-[#FF6B00] to-amber-500 transition-all duration-300 ease-out shadow-[0_0_8px_rgba(255,107,0,0.6)]"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
          <div className="flex items-center justify-between px-4 sm:px-6 md:px-10 py-1.5 text-[9px] sm:text-[10px] font-mono text-gray-500">
            <div className="flex items-center space-x-2 truncate">
              <span className="font-bold uppercase tracking-wider text-neutral-400">Scan Progress:</span>
              <span className="text-[#FF6B00] font-black">{progressPercent}%</span>
              <span className="text-neutral-700">|</span>
              <span className="uppercase text-neutral-400 truncate tracking-tight">
                {scanState.status === 'idle' && 'Ready to Initiate'}
                {scanState.status === 'fetching' && 'Initializing Governance Framework'}
                {scanState.status === 'scanning' && `Verifying Artifact ${Math.max(1, currentStepIndex - 2)} of ${scannedFilesList.length}`}
                {scanState.status === 'awaiting_decision' && 'Interceptors Paused (Action Signature Required)'}
                {scanState.status === 'completed' && 'Sovereign Integrity Audit Signed & Sealed'}
              </span>
            </div>
            <div className="flex items-center space-x-2 shrink-0">
              <span className="text-neutral-500">
                {scanState.status !== 'idle' && scanState.status !== 'completed' && `STEP ${currentStepIndex === -1 ? totalSteps : currentStepIndex}/${totalSteps}`}
                {scanState.status === 'completed' && 'AUDIT END'}
                {scanState.status === 'idle' && '0/0 STEPS'}
              </span>
            </div>
          </div>
        </div>

        {/* Preset selections list bar - responsive wraps for phone viewport */}
        <div className="px-4 sm:px-6 md:px-10 py-3 sm:py-4 bg-[#080808] border-b border-[#222] flex flex-col sm:flex-row items-start sm:items-center gap-3 select-none">
          <span className="font-mono text-[9px] text-gray-500 uppercase tracking-widest shrink-0 flex items-center space-x-1 font-bold">
            <Compass className="w-3 h-3 text-[#555]" />
            <span>Target Scenarios:</span>
          </span>
          <div className="flex flex-wrap items-center justify-between gap-2 w-full">
            <div className="flex flex-wrap items-center gap-2">
              {REPO_PRESETS.map((p) => {
                const isActive = repoUrl === p.url;
                return (
                  <button
                    key={p.url}
                    onClick={() => handleSelectPreset(p.url)}
                    title={p.desc}
                    disabled={scanState.status === 'fetching' || scanState.status === 'scanning' || scanState.status === 'awaiting_decision'}
                    className={`text-[10px] font-mono px-3 py-2 border transition-all cursor-pointer touch-manipulation flex-1 sm:flex-none text-center ${
                      isActive 
                        ? 'border-[#FF6B00] text-[#FF6B00] bg-[#FF6B00]/5 font-black' 
                        : 'border-[#222] text-[#666] hover:text-gray-300 hover:border-[#444]'
                    }`}
                  >
                    {p.label}
                  </button>
                );
              })}

              <button
                onClick={() => setIsScenariosOpen(!isScenariosOpen)}
                disabled={scanState.status === 'fetching' || scanState.status === 'scanning'}
                className={`text-[10px] font-mono px-3 py-2 border transition-all cursor-pointer flex items-center space-x-1.5 ${
                  isScenariosOpen 
                    ? 'border-[#FF6B00] text-[#FF6B00] bg-[#FF6B00]/10 font-bold' 
                    : 'border-[#222]/80 text-[#888] bg-neutral-900/40 hover:text-white hover:border-neutral-700'
                }`}
              >
                <span>{isScenariosOpen ? '▼ Hide Custom Targets' : '▲ Add Custom Targets'}</span>
                {customScenariosList.length > 0 && (
                  <span className="ml-1.5 bg-[#FF6B00] text-black text-[8px] font-black px-1.5 py-0.5 rounded font-mono">
                    {customScenariosList.length}
                  </span>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Custom Scenarios Expandable Config Panel */}
        {isScenariosOpen && (
          <div className="px-4 sm:px-6 md:px-10 py-4 bg-[#0a0a0a] border-b border-[#222] animate-[fadeIn_0.2s_ease-out] font-mono text-[11px] select-none">
            <div className="max-w-4xl space-y-4">
              <div className="flex flex-col space-y-1">
                <span className="text-[#FF6B00] font-bold uppercase text-[10px] tracking-wider">Configure Custom Target Scenarios</span>
                <span className="text-[#666] text-[10px] leading-relaxed">
                  Inject specific, custom target filepaths into the governance review pipeline. These custom paths will be appended to any active repo check, allowing the system to run policy checks on your specific developer and security test scenarios.
                </span>
              </div>

              {/* Input Area */}
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                <div className="flex-1 flex items-center bg-[#050505] border border-[#222] hover:border-neutral-700 transition-colors px-2.5 py-1.5 text-white h-9">
                  <input
                    type="text"
                    value={newScenarioInput}
                    onChange={(e) => setNewScenarioInput(e.target.value)}
                    placeholder="e.g., config/private_keys.key"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        if (newScenarioInput.trim()) {
                          const path = newScenarioInput.trim();
                          if (!customScenariosList.includes(path)) {
                            setCustomScenariosList([...customScenariosList, path]);
                          }
                          setNewScenarioInput('');
                        }
                      }
                    }}
                    className="bg-transparent border-0 outline-none text-xs w-full text-gray-100 placeholder-neutral-700 focus:ring-0 focus:outline-none font-mono"
                  />
                </div>
                <button
                  type="button"
                  onClick={() => {
                    if (newScenarioInput.trim()) {
                      const path = newScenarioInput.trim();
                      if (!customScenariosList.includes(path)) {
                        setCustomScenariosList([...customScenariosList, path]);
                      }
                      setNewScenarioInput('');
                    }
                  }}
                  className="py-1.5 px-4 bg-neutral-900 hover:bg-neutral-800 border border-neutral-700 text-gray-300 font-bold uppercase text-[10px] tracking-wider transition-colors h-9"
                >
                  Add Path
                </button>
              </div>

              {/* Recommended Quick Injects */}
              <div className="space-y-1.5">
                <span className="text-[#555] text-[9px] uppercase tracking-wider block font-bold">Suggested Vulnerability Archetypes (Click to Inject)</span>
                <div className="flex flex-wrap gap-1.5">
                  {[
                    { path: 'src/keys/prod_secret.pem', label: 'Secrets Key (.pem)', color: 'border-red-950/40 text-red-400 bg-red-950/10 hover:border-red-500' },
                    { path: 'db/migrations/003_drop_rbac.sql', label: 'SQL DB Migration (.sql)', color: 'border-amber-950/40 text-amber-500 bg-amber-950/10 hover:border-amber-500' },
                    { path: 'deploy/k8s/admin-bypass.yaml', label: 'K8s Cluster Manifest (.yaml)', color: 'border-purple-950/40 text-purple-400 bg-purple-950/10 hover:border-purple-500' },
                    { path: 'src/auth/jwt_signing.rs', label: 'Auth Router Claim (.rs)', color: 'border-blue-950/40 text-blue-400 bg-blue-950/10 hover:border-blue-500' },
                    { path: 'billing/stripe_bypass.py', label: 'Billing Stripe Hook (.py)', color: 'border-[#FF6B00]/20 text-[#FF6B00] bg-[#FF6B00]/5 hover:border-[#FF6B00]' }
                  ].map((rec) => {
                    const isAdded = customScenariosList.includes(rec.path);
                    return (
                      <button
                        key={rec.path}
                        onClick={() => {
                          if (isAdded) {
                            setCustomScenariosList(customScenariosList.filter(p => p !== rec.path));
                          } else {
                            setCustomScenariosList([...customScenariosList, rec.path]);
                          }
                        }}
                        className={`text-[9px] px-2.5 py-1.5 border rounded-xs transition-all flex items-center space-x-1 ${
                          isAdded 
                            ? 'border-[#00FF41] text-[#00FF41] bg-[#00FF41]/5 font-bold shadow-[0_0_8px_rgba(0,255,65,0.1)]' 
                            : `${rec.color} opacity-70 hover:opacity-100`
                        }`}
                      >
                        <span>{isAdded ? '✓' : '+'}</span>
                        <span>{rec.label}</span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Configured Paths List */}
              <div className="space-y-2">
                <span className="text-[#555] text-[9px] uppercase tracking-wider block font-bold">Active Custom Targets ({customScenariosList.length})</span>
                {customScenariosList.length === 0 ? (
                  <p className="text-gray-600 text-[10px] italic">// No custom target pathways active.</p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {customScenariosList.map((path) => (
                      <div 
                        key={path} 
                        className="flex items-center space-x-1.5 bg-neutral-900 border border-neutral-800 px-2 py-1 text-[10px] text-gray-300 font-mono"
                      >
                        <span className="truncate max-w-[250px]">{path}</span>
                        <button
                          onClick={() => setCustomScenariosList(customScenariosList.filter(p => p !== path))}
                          className="text-red-500 hover:text-red-400 font-extrabold px-1 cursor-pointer text-xs"
                          title="Remove custom path"
                        >
                          ×
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Compact Widescreen Matrix Monitor Strip */}
        {scannedFilesList && scannedFilesList.length > 0 && (
          <div className="bg-[#080808] border-b border-[#222] px-4 sm:px-6 md:px-10 py-2.5 font-mono select-none">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 mb-1.5">
              <span className="text-[9px] font-bold tracking-widest text-[#888] uppercase flex items-center gap-1.5">
                <span className={`w-1.5 h-1.5 rounded-full ${scanState.status === 'scanning' ? 'bg-[#FF6B00] animate-ping' : events.length > 0 ? 'bg-[#00FF41]' : 'bg-gray-700'}`}></span>
                <span>File Tree Sweep Index (Matrix Monitor)</span>
              </span>
              <span className="text-[8px] text-neutral-600 uppercase tracking-widest">
                State: <span className="font-bold text-[#FF6B00]">{scanState.status === 'scanning' ? 'SWEEPING' : events.length > 0 ? 'SEALED' : 'READY'}</span>
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-1">
              {scannedFilesList.map((path, idx) => {
                const fileIndex = currentStepIndex - 3;
                const isCurrent = scanState.status === 'scanning' && idx === fileIndex;
                const isPast = (currentStepIndex === -1 && events.length > 0) || (currentStepIndex - 3 > idx);
                const pathFinding = findings.find(f => f.path === path);
                const hasFailure = !!pathFinding;

                let colorClass = "bg-neutral-900/60 border-neutral-800/60 text-neutral-500";
                let titleText = `QUEUED`;

                if (isCurrent) {
                  colorClass = "bg-[#FF6B00]/15 border-[#FF6B00] text-[#FF6B00] animate-pulse font-bold";
                  titleText = "SCANNING";
                } else if (isPast) {
                  if (hasFailure) {
                    colorClass = "bg-red-950/20 border-red-500/50 text-red-400 font-bold";
                    titleText = "TRIGGERED";
                  } else {
                    colorClass = "bg-[#00FF41]/5 border-[#00FF41]/30 text-[#00FF41]/80";
                    titleText = "PASSED";
                  }
                }

                const filename = path.split('/').pop() || path;
                const ext = filename.split('.').pop() || '';

                return (
                  <div 
                    key={path}
                    className={`px-2 py-0.5 text-[9px] border rounded-xs font-mono transition-all duration-300 max-w-[150px] truncate flex items-center gap-1 cursor-help ${colorClass}`}
                    title={`Path: ${path}\nStatus: ${titleText}`}
                  >
                    <span>{filename}</span>
                    <span className="text-[7.5px] opacity-40 lowercase">({ext})</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Responsive Cross-grid arrangement */}
        {windowWidth < 768 ? (
          /* Mobile-Optimized Main Workspace: Clean, high-readability screen */
          <main className="flex-1 flex flex-col bg-[#050505] p-4 gap-4 overflow-y-auto select-none">
            {/* Render inline Manual Action Intercept if awaiting decision on mobile */}
            {scanState.status === 'awaiting_decision' && activeInterceptedFinding && (
              <div className="p-3 bg-red-950/20 border border-red-500/40 rounded flex flex-col gap-3 animate-pulse">
                <div className="flex items-center space-x-1.5 text-red-500 font-bold uppercase text-[10px] tracking-wider">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-[#FF6B00]" />
                  <span>MUTATION INTERCEPT ACTION REQUIRED</span>
                </div>
                <p className="text-[10px] text-neutral-400 font-mono leading-relaxed">
                  A file violating safety policies was detected: <span className="text-white font-bold">{activeInterceptedFinding.path}</span>. Matched security rule: <span className="text-red-400 font-black">"{activeInterceptedFinding.matched_rule}"</span>.
                </p>
                <div className="flex flex-col gap-1.5">
                  <button
                    onClick={() => handleOperatorDecision('APPROVED', 'Self-certified mobile sign-off.')}
                    className="py-2.5 bg-emerald-500 hover:bg-emerald-600 text-black font-black text-[11px] tracking-wider uppercase rounded font-mono cursor-pointer"
                  >
                    ✓ Approve Override (Sign Ledger)
                  </button>
                  <button
                    onClick={() => handleOperatorDecision('BLOCKED', 'Manual containment isolation block requested.')}
                    className="py-2.5 bg-red-600 hover:bg-red-700 text-white font-black text-[11px] tracking-wider uppercase rounded font-mono cursor-pointer"
                  >
                    🗙 Block Commit (Enforce Gate)
                  </button>
                  <button
                    onClick={() => handleOperatorDecision('ESCALATED', 'Transferred to senior security review.')}
                    className="py-2.5 bg-yellow-500 hover:bg-yellow-600 text-black font-black text-[11px] tracking-wider uppercase rounded font-mono cursor-pointer"
                  >
                    ⚠ Escalate Incident (Forward Case)
                  </button>
                </div>
              </div>
            )}

            <RiskIndicators 
              findings={findings}
              riskLevel={scanState.risk_level}
              isScanning={scanState.status === 'fetching' || scanState.status === 'scanning'}
              filesScanned={scanState.files_seen}
              runId={scanState.run_id}
              scannedFilesList={scannedFilesList}
              history={history}
              onResetHistory={handleResetHistory}
            />

            <EvidenceLedger 
              runId={scanState.run_id}
              agentId={scanState.agent_id}
              repoUrl={scanState.repo_url}
              filesScannedCount={scanState.files_seen}
              overallRisk={scanState.risk_level}
              userDecision={scanState.decision || null}
              events={events}
              findings={findings}
              auditHash={auditHash}
              treeTruncated={scanState.tree_truncated}
              history={history}
              onResetHistory={handleResetHistory}
            />
          </main>
        ) : (
          /* Desktop/Tablet Responsive Main Workspace: Complex, dual-pane grid views */
          <main className="flex-1 flex flex-col md:flex-row min-h-0 select-none">
            {/* Column 1 - Indicators (Scored risk & sealed ledger proof) */}
            <section className="w-full md:w-[58%] border-b md:border-b-0 md:border-r border-[#333] flex flex-col bg-[#0F0F0F] overflow-y-auto min-h-0">
              <RiskIndicators 
                findings={findings}
                riskLevel={scanState.risk_level}
                isScanning={scanState.status === 'fetching' || scanState.status === 'scanning'}
                filesScanned={scanState.files_seen}
                runId={scanState.run_id}
                scannedFilesList={scannedFilesList}
                history={history}
                onResetHistory={handleResetHistory}
              />
            </section>

            {/* Column 2 - Secured Evidence Ledger */}
            <section className="w-full md:w-[42%] flex flex-col bg-[#0A0A0A] overflow-y-auto min-h-0">
              <EvidenceLedger 
                runId={scanState.run_id}
                agentId={scanState.agent_id}
                repoUrl={scanState.repo_url}
                filesScannedCount={scanState.files_seen}
                overallRisk={scanState.risk_level}
                userDecision={scanState.decision || null}
                events={events}
                findings={findings}
                auditHash={auditHash}
                treeTruncated={scanState.tree_truncated}
                history={history}
                onResetHistory={handleResetHistory}
              />
            </section>
          </main>
        )}

        {/* Modal operator signature block popup */}
        <ManualReviewModal 
          isOpen={isModalOpen}
          finding={activeInterceptedFinding}
          onDecision={handleOperatorDecision}
        />

        {/* Global Hub Footer */}
        <footer className="h-auto md:h-12 border-t border-[#333] flex flex-col md:flex-row items-center justify-between px-4 sm:px-6 md:px-10 py-3 md:py-0 font-mono text-[9px] md:text-[10px] text-[#666] uppercase tracking-[0.2em] bg-[#0A0A0A] gap-2 select-text">
          <span className="flex items-center">
            <Clock className="w-3.5 h-3.5 text-[#333] mr-1.5 shrink-0" />
            Server Time: <span className="text-gray-400 font-bold ml-1">{currentUtcTime || '2026-07-12 11:45:25 UTC'}</span>
          </span>

          <span>Gate ID: VEKLOM-STABLE-01</span>
        </footer>
      </div>
    </div>
  );
}
