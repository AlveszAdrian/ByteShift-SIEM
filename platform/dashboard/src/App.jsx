import { useState, useEffect } from 'react';
import './index.css';
import { Overview, Alerts, Agents, Rules, Search } from './components/Views.jsx';

// ── SVG Icons ─────────────────────────────────────────────────────────────────
const IconGrid      = () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>;
const IconBell      = () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>;
const IconMonitor   = () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>;
const IconShield    = () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
const IconSearch    = () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>;
const IconRefresh   = () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>;

const TABS = [
  { id: 'overview', label: 'Overview',         Icon: IconGrid },
  { id: 'alerts',   label: 'Alerts',           Icon: IconBell },
  { id: 'agents',   label: 'Agents',           Icon: IconMonitor },
  { id: 'rules',    label: 'Detection Rules',  Icon: IconShield },
  { id: 'search',   label: 'Log Search',       Icon: IconSearch },
];

const tabMeta = {
  overview: { title: 'Overview',         sub: 'Real-time security monitoring' },
  alerts:   { title: 'Alerts',           sub: 'Incident management' },
  agents:   { title: 'Agents',           sub: 'Monitored endpoints' },
  rules:    { title: 'Detection Rules',  sub: 'Dynamic threat engine' },
  search:   { title: 'Log Search',       sub: 'Forensic analysis on historical data' },
};

export default function App() {
  const [tab, setTab] = useState('overview');
  const [time, setTime] = useState('');
  const [apiOk, setApiOk] = useState(null);

  useEffect(() => {
    const tick = () => setTime(new Date().toLocaleTimeString('pt-BR'));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const check = () => fetch('/api/stats/overview').then(r => setApiOk(r.ok)).catch(() => setApiOk(false));
    check();
    const id = setInterval(check, 15000);
    return () => clearInterval(id);
  }, []);

  const { title, sub } = tabMeta[tab];

  return (
    <div className="app">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-top">
          <div className="brand">
            <div className="brand-icon"><IconShield /></div>
            <div>
              <div className="brand-name">SIEM Platform</div>
              <div className="brand-sub">Enterprise Security</div>
            </div>
          </div>
          <div className="health-bar">
            <span className={`health-dot ${apiOk === true ? 'online' : apiOk === false ? 'error' : ''}`}/>
            <span>{apiOk === true ? 'Indexer connected' : apiOk === false ? 'No connection' : 'Checking...'}</span>
          </div>
        </div>

        <nav className="nav">
          {TABS.map(({ id, label, Icon }) => (
            <button key={id} className={`nav-btn ${tab === id ? 'active' : ''}`} onClick={() => setTab(id)}>
              <span className="nav-icon"><Icon /></span>
              {label}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="time-display">{time}</div>
        </div>
      </aside>

      {/* Content */}
      <div className="content-wrap">
        <header className="topbar">
          <div>
            <h1>{title}</h1>
            <div className="topbar-sub">{sub}</div>
          </div>
          <button className="btn-refresh" onClick={() => setTab(t => t)}>
            <IconRefresh /> Refresh
          </button>
        </header>

        <main className="main">
          {tab === 'overview' && <Overview />}
          {tab === 'alerts'   && <Alerts />}
          {tab === 'agents'   && <Agents />}
          {tab === 'rules'    && <Rules />}
          {tab === 'search'   && <Search />}
        </main>
      </div>
    </div>
  );
}
