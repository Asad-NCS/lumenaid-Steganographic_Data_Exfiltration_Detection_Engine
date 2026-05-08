//React app entry point — mounts the Dashboard component into the DOM
import React from "react";
import ReactDOM from "react-dom/client";
import Dashboard from "./Dashboard";

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <React.StrictMode>
    <Dashboard />
  </React.StrictMode>
);
