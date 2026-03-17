import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { LogOut, Video, AlertCircle, X, Loader2, RefreshCw } from 'lucide-react';
import { getChannels, getChannelStatus, setChannelStatus, getAppInfo } from '../api';

interface ChannelStatus {
  name: string;
  channel: string;
  status: boolean;
  poe_power?: string;
  poe_current?: string;
  poe_voltage?: string;
  poe_class?: string;
  switch_name?: string;
  port_idx?: number;
  error?: string;
}

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [channels, setChannels] = useState<ChannelStatus[]>([]);
  const [isInitialLoading, setIsInitialLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  
  const [modalVisible, setModalVisible] = useState(false);
  const [selectedError, setSelectedError] = useState('');
  const [selectedChannelId, setSelectedChannelId] = useState('');
  const [appVersion, setAppVersion] = useState('');
  const [windowWidth, setWindowWidth] = useState(window.innerWidth);

  useEffect(() => {
    const handleResize = () => setWindowWidth(window.innerWidth);
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const token = localStorage.getItem('auth_token') || '';

  const handleLogout = () => {
    localStorage.removeItem('auth_token');
    navigate('/login');
  };

  const loadData = async (silent = false) => {
    if (!token) {
      navigate('/login');
      return;
    }

    try {
      if (!silent) {
        if (channels.length === 0) setIsInitialLoading(true);
        else setIsRefreshing(true);
      } else {
        setIsRefreshing(true);
      }

      const channelIds = await getChannels(token);
      
      const promises = channelIds.map((id: string) => 
        getChannelStatus(token, id)
          .then(data => ({
            channel: id,
            name: data.name || `Channel ${id}`,
            status: data.status,
            poe_power: data.poe_power,
            poe_current: data.poe_current,
            poe_voltage: data.poe_voltage,
            poe_class: data.poe_class,
            switch_name: data.switch_name,
            port_idx: data.port_idx,
            error: data.error && data.error !== "" ? data.error : undefined
          }))
          .catch(err => ({ 
            channel: id, 
            name: `Channel ${id}`, 
            status: false, 
            error: err.response?.data?.error || err.message || 'Error fetching status' 
          }))
      );
      
      const results = await Promise.all(promises);
      setChannels(results);
    } catch (err: any) {
      console.error(err);
      if (err.response?.status === 401) {
        handleLogout();
      }
    } finally {
      setIsInitialLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
    
    // Auto-refresh every minute
    const interval = setInterval(() => {
      loadData(silentAutoRefresh);
    }, 60000);

    return () => clearInterval(interval);
  }, [token]);

  useEffect(() => {
    getAppInfo().then(data => setAppVersion(data.version)).catch(console.error);
  }, []);

  // Small helper to avoid shadowed variable issues in closure
  const silentAutoRefresh = true;

  const toggleChannel = async (id: string, currentStatus: boolean) => {
    // Optimistic UI update
    setChannels(prev => prev.map(ch => 
      ch.channel === id ? { ...ch, status: !currentStatus, error: undefined } : ch
    ));

    try {
      await setChannelStatus(token, id, !currentStatus);
      // Refetch data after toggle to get updated PoE metrics (Power, Current, etc.)
      await loadData(true);
    } catch (error: any) {
      // Revert on failure
      setChannels(prev => prev.map(ch => 
        ch.channel === id ? { 
          ...ch, 
          status: currentStatus, 
          error: error.response?.data?.error || error.message || 'Failed to update configuration.' 
        } : ch
      ));
    }
  };

  const showErrorDetails = (channelId: string, errorMsg: string) => {
    setSelectedChannelId(channelId);
    setSelectedError(errorMsg);
    setModalVisible(true);
  };

  if (isInitialLoading) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
         <Loader2 size={48} color="var(--primary)" className="animate-spin" />
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', padding: '24px', maxWidth: '1000px', margin: '0 auto', width: '100%' }}>
      
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '24px', borderBottom: '1px solid var(--glass-border)', marginBottom: '32px' }} className="animate-fade-in">
        <div>
          <h1 style={{ fontSize: '28px', fontWeight: 800, color: '#fff', letterSpacing: '0.5px' }}>Unifi PoE</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '14px', marginTop: '4px' }}>Unifi Control System</p>
        </div>
        
        <button 
          onClick={handleLogout}
          style={{ 
            display: 'flex', alignItems: 'center', gap: '8px', 
            background: 'var(--danger-bg)', color: 'var(--danger)', 
            border: '1px solid rgba(255, 107, 107, 0.3)', 
            padding: '10px 16px', borderRadius: '10px', fontWeight: 700, 
            cursor: 'pointer', transition: 'all 0.2s' 
          }}
          onMouseOver={(e) => e.currentTarget.style.background = 'rgba(255, 107, 107, 0.25)'}
          onMouseOut={(e) => e.currentTarget.style.background = 'var(--danger-bg)'}
        >
          <LogOut size={18} />
          Logout
        </button>
      </header>

      <main style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {channels.length === 0 ? (
          <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '18px', marginTop: '40px' }}>
            No recording channels found.
          </div>
        ) : (
          channels.map((ch, idx) => (
            <div 
              key={ch.channel} 
              className="glass-card animate-fade-in" 
              style={{ padding: '24px', animationDelay: `${idx * 0.1}s`, display: 'flex', flexDirection: 'column', gap: '16px' }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                
                {/* Left Side: Avatar + Names */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                  <div style={{ 
                    width: '56px', height: '56px', borderRadius: '16px', 
                    background: 'rgba(0, 210, 255, 0.15)', display: 'flex', 
                    alignItems: 'center', justifyContent: 'center', color: 'var(--primary)'
                  }}>
                    <Video size={28} />
                  </div>
                  <div>
                    <h2 style={{ fontSize: '20px', fontWeight: 700, margin: 0 }}>{ch.name}</h2>
                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '6px' }}>
                      {ch.switch_name && (
                        <span style={{ 
                          fontSize: '11px', color: 'var(--text-muted)', 
                          background: 'rgba(255,255,255,0.05)', 
                          padding: '2px 8px', borderRadius: '4px',
                          border: '1px solid rgba(255,255,255,0.1)'
                        }}>
                          Switch: {ch.switch_name}
                        </span>
                      )}
                      {ch.port_idx !== undefined && (
                        <span style={{ 
                          fontSize: '11px', color: 'var(--primary)', 
                          background: 'rgba(0, 210, 255, 0.05)', 
                          padding: '2px 8px', borderRadius: '4px',
                          border: '1px solid rgba(0, 210, 255, 0.1)'
                        }}>
                          Port: {ch.port_idx}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Right Side: Toggle */}
                <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                  <div style={{ position: 'relative' }}>
                    <input 
                      type="checkbox" 
                      style={{ opacity: 0, width: 0, height: 0 }} 
                      checked={ch.status} 
                      onChange={() => toggleChannel(ch.channel, ch.status)}
                    />
                    <div style={{ 
                      width: '60px', height: '32px', borderRadius: '16px',
                      background: ch.status ? 'var(--primary)' : 'rgba(255, 255, 255, 0.1)',
                      transition: 'background 0.3s',
                      position: 'relative'
                    }}>
                      <div style={{ 
                        width: '24px', height: '24px', borderRadius: '50%', background: '#fff', 
                        position: 'absolute', top: '4px', left: ch.status ? '32px' : '4px', 
                        transition: 'left 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275)'
                      }} />
                    </div>
                  </div>
                </label>
              </div>

              {/* Stats Section */}
              {ch.status && ch.poe_power && (
                <div style={{ 
                  display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', 
                  gap: '12px', background: 'rgba(255, 255, 255, 0.03)', 
                  padding: '16px', borderRadius: '16px', border: '1px solid rgba(255, 255, 255, 0.05)',
                  marginTop: '4px'
                }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Power</span>
                    <span style={{ fontSize: '16px', fontWeight: 700, color: 'var(--primary)' }}>{ch.poe_power} W</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Voltage</span>
                    <span style={{ fontSize: '16px', fontWeight: 600 }}>{ch.poe_voltage} V</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Current</span>
                    <span style={{ fontSize: '16px', fontWeight: 600 }}>{ch.poe_current} mA</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Class</span>
                    <span style={{ fontSize: '16px', fontWeight: 600 }}>{ch.poe_class || 'N/A'}</span>
                  </div>
                </div>
              )}

              {/* Error Ribbon */}
              {ch.error && (
                <div 
                  onClick={() => showErrorDetails(ch.channel, ch.error as string)}
                  style={{ 
                    marginTop: '8px', padding: '12px 16px', background: 'var(--danger-bg)', 
                    border: '1px solid rgba(255, 107, 107, 0.3)', borderRadius: '12px',
                    display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer',
                    color: 'var(--danger)', fontWeight: 600, fontSize: '14px'
                  }}
                >
                  <AlertCircle size={20} />
                  <span>Issue Detected: Action failed. Click for details.</span>
                </div>
              )}
            </div>
          ))
        )}
      </main>

      <footer style={{ marginTop: 'auto', paddingTop: '40px', paddingBottom: '16px', textAlign: 'center' }}>
        <p style={{ color: 'var(--text-muted)', fontSize: '11px', opacity: 0.6, letterSpacing: '0.5px' }}>
          {appVersion ? `Unifi Control Service ${appVersion}` : 'Unifi Control Service'}
        </p>
      </footer>

      {/* Error Details Modal */}
      {modalVisible && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          padding: '24px', zIndex: 1000
        }}>
          <div className="animate-fade-in" style={{
            background: '#1a2933', border: '1px solid var(--glass-border)',
            width: '100%', maxWidth: '500px', borderRadius: '24px', overflow: 'hidden',
            boxShadow: '0 20px 40px rgba(0,0,0,0.5)'
          }}>
            <header style={{ 
              display: 'flex', justifyContent: 'space-between', alignItems: 'center', 
              padding: '24px', borderBottom: '1px solid var(--glass-border)' 
            }}>
              <h2 style={{ color: 'var(--danger)', margin: 0, fontSize: '20px', display: 'flex', gap: '10px', alignItems: 'center' }}>
                <AlertCircle /> Channel {selectedChannelId} Error
              </h2>
              <button 
                onClick={() => setModalVisible(false)} 
                style={{ background: 'transparent', border: 'none', color: '#fff', cursor: 'pointer' }}
              >
                <X size={24} />
              </button>
            </header>
            <div style={{ padding: '24px' }}>
              <div style={{ 
                background: 'rgba(0,0,0,0.3)', padding: '16px', borderRadius: '12px', 
                color: '#fff', fontSize: '14px', whiteSpace: 'pre-wrap', fontFamily: 'monospace',
                wordBreak: 'break-all', overflowWrap: 'break-word',
                maxHeight: '350px', overflowY: 'auto'
              }}>
                {selectedError}
              </div>
            </div>
            <div style={{ padding: '24px', paddingTop: 0 }}>
              <button onClick={() => setModalVisible(false)} className="btn-primary">
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Floating Refresh Button */}
      <button 
        onClick={() => loadData(false)}
        className="glass-card"
        style={{
          position: 'fixed',
          bottom: windowWidth < 640 ? '16px' : '32px',
          right: windowWidth < 640 ? '16px' : '32px',
          width: windowWidth < 640 ? '48px' : '64px',
          height: windowWidth < 640 ? '48px' : '64px',
          borderRadius: '50%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--primary)',
          cursor: 'pointer',
          zIndex: 900,
          boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
          border: '1px solid var(--glass-border)',
          transition: 'all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275)',
          padding: 0
        }}
        onMouseOver={(e) => {
          e.currentTarget.style.transform = 'scale(1.1) rotate(90deg)';
          e.currentTarget.style.background = 'rgba(255, 255, 255, 0.15)';
          e.currentTarget.style.boxShadow = '0 12px 40px rgba(0, 210, 255, 0.3)';
        }}
        onMouseOut={(e) => {
          e.currentTarget.style.transform = 'scale(1) rotate(0deg)';
          e.currentTarget.style.background = 'var(--glass-bg)';
          e.currentTarget.style.boxShadow = '0 8px 32px rgba(0,0,0,0.4)';
        }}
        title="Refresh Status"
      >
        <RefreshCw size={windowWidth < 640 ? 20 : 28} className={isRefreshing ? "animate-spin" : ""} />
      </button>

    </div>
  );
};
