import React from "react";
import ReactDOM from "react-dom";
import ScopedCssBaseline from "@mui/material/ScopedCssBaseline";

import { DockerMuiThemeProvider } from "@docker/docker-mui-theme";

//import { App } from "./App";

ReactDOM.render(
  <React.StrictMode>
    {/*
      If you eject from MUI (which we don't recommend!), you should add
      the `dockerDesktopTheme` class to your root <html> element to get
      some minimal Docker theming.
    */}
    <DockerMuiThemeProvider>
      <ScopedCssBaseline
        style={{
          backgroundColor: "#27272a",
        }}
      >
      </ScopedCssBaseline>
    </DockerMuiThemeProvider>
  </React.StrictMode>,
  document.getElementById("root"),
);
