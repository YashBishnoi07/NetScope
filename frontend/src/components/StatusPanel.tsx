type StatusPanelProps = {
  label: string;
  value: string;
};

export default function StatusPanel({ label, value }: StatusPanelProps) {
  return (
    <div className="card small-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
