import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
import "./styles/app.css";

// Ensure global session fallback
if (typeof window !== 'undefined' && typeof window.session === 'undefined') {
  window.session = null;
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
