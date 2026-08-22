import type { FeedEvent } from '../hooks/useDemoSimulation'

const levelColor = {
  info: 'text-[#00e5ff]',
  warn: 'text-[#ffb020]',
  critical: 'text-[#ff3366]',
}

const levelPrefix = {
  info: '›',
  warn: '⚠',
  critical: '◆',
}

export function IntelligenceFeed({ events }: { events: FeedEvent[] }) {
  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="feed-scroll flex-1 overflow-y-auto font-mono text-xs leading-relaxed space-y-1 pr-1">
        {events.map((ev) => (
          <div key={ev.id} className="feed-line border-l-2 border-[#1a3a5c] pl-2 py-0.5 hover:border-[#00e5ff] transition-colors">
            <span className="text-[#6b8fa3]">[{ev.time}]</span>{' '}
            <span className={levelColor[ev.level]}>{levelPrefix[ev.level]}</span>{' '}
            <span className="text-[#0099b3]">[{ev.module}]</span>{' '}
            <span className="text-[#e0f7ff]/90">{ev.message}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
