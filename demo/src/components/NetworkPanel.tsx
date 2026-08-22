import type { NetworkInfo } from '../hooks/useDemoSimulation'

function Row({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div className="flex gap-2 py-1 border-b border-[#1a3a5c]/40 last:border-0">
      <span className="text-[10px] text-[#6b8fa3] w-24 shrink-0 uppercase tracking-wide">{label}</span>
      <span
        className={`font-mono text-[11px] break-all ${highlight ? 'text-[#00ff9d]' : 'text-[#e0f7ff]'}`}
      >
        {value}
      </span>
    </div>
  )
}

export function NetworkPanel({ network, loading }: { network: NetworkInfo | null; loading: boolean }) {
  if (!network && !loading) {
    return (
      <p className="text-xs text-[#6b8fa3] italic text-center py-6">
        Press START to scan network, VPN, and DNS in real time.
      </p>
    )
  }

  if (loading && !network) {
    return <p className="text-xs text-[#00e5ff] animate-pulse text-center py-6">Scanning network channels...</p>
  }

  if (!network) return null

  return (
    <div className="space-y-0">
      <Row label="Hostname" value={network.hostname} />
      <Row label="Local IP" value={network.localIp} />
      <Row label="Public IP" value={network.publicIp} />
      <Row
        label="VPN"
        value={network.vpnActive ? `ACTIVE — ${network.vpnName}` : 'Not detected'}
        highlight={network.vpnActive}
      />
      {network.vpnActive && (
        <>
          <Row label="VPN IP" value={network.vpnIp || '—'} highlight />
          <Row label="Gateway" value={network.gateway} />
        </>
      )}
      <Row label="DNS" value={network.dnsServers.join(' · ') || '—'} />
      <p className="text-[9px] text-[#6b8fa3] mt-3 italic">
        Refreshes every 15s · Full agent uses real Windows adapter detection
      </p>
    </div>
  )
}
