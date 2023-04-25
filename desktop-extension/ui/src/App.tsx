import React, { useEffect, useState } from "react";
//import LoadingButton from "@mui/lab/LoadingButton";

import { v1 } from "@docker/extension-api-client-types";
//import { Stack, Typography, Container } from "@mui/material";
//import { load, dump } from "js-yaml";

const getDockerDesktopClient = (): v1.DockerDesktopClient => {
  return window.ddClient as v1.DockerDesktopClient;
};

const App: React.FC = () => {
  const ddClient: v1.DockerDesktopClient = getDockerDesktopClient();
};

export { App };
