export type Alert = {
  id: number;
  timestamp: number;
  severity: string;
  type: string;
  message: string;
  src?: string;
  dst?: string;
};

export type PacketSummary = {
  id: number;
  timestamp: number;
  src: string;
  dst: string;
  src_port?: number | null;
  dst_port?: number | null;
  protocol: string;
  transport?: string | null;
  length: number;
  info: string;
  flow_key?: string | null;
  details?: Record<string, unknown>;
};

export type FlowRecord = {
  key: string;
  src: string;
  dst: string;
  src_port?: number | null;
  dst_port?: number | null;
  protocol: string;
  packets: number;
  bytes_total: number;
  duration: number;
  last_seen: number;
};

export type Overview = {
  packets_total: number;
  bytes_total: number;
  packet_rate: number;
  bandwidth_bps: number;
  active_flows: number;
  unique_hosts: number;
  alerts_last_hour: number;
  dropped_packets: number;
};
