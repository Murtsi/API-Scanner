export default function Header() {
  return (
    <header className="header">
      <div className="brand">
        <div className="logo" aria-hidden="true"></div>
        <div>
          <h1>API-Scanner</h1>
          <div className="subtitle">Secret & API Key Detector for public websites</div>
        </div>
      </div>
      <span className="pill">Client-side scan · Fast preview</span>
    </header>
  );
}
