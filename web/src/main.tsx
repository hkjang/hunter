import React from "react";
import ReactDOM from "react-dom/client";
import { MantineProvider, createTheme } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { BrowserRouter } from "react-router-dom";
import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";
import "@fontsource-variable/noto-sans-kr";
import "./styles.css";
import App from "./App";
import { RenderBoundary } from "./render-boundary";
const theme = createTheme({
  primaryColor: "teal",
  primaryShade: 8,
  fontFamily: '"Noto Sans KR Variable", sans-serif',
  fontSizes: {
    xs: "0.8125rem",
    sm: "0.9375rem",
    md: "1rem",
    lg: "1.125rem",
    xl: "1.375rem",
  },
  defaultRadius: "md",
  headings: {
    fontFamily: '"Noto Sans KR Variable", sans-serif',
    fontWeight: "700",
  },
  components: {
    Button: { defaultProps: { size: "md" } },
    TextInput: { defaultProps: { size: "md" } },
    PasswordInput: { defaultProps: { size: "md" } },
    Select: { defaultProps: { size: "md" } },
    Textarea: { defaultProps: { size: "md" } },
    NumberInput: { defaultProps: { size: "md" } },
    MultiSelect: { defaultProps: { size: "md" } },
    Modal: {
      defaultProps: {
        centered: true,
        radius: "lg",
        overlayProps: { backgroundOpacity: 0.35, blur: 3 },
      },
    },
  },
});
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <MantineProvider theme={theme}>
      <Notifications position="top-right" />
      <BrowserRouter>
        <RenderBoundary>
          <App />
        </RenderBoundary>
      </BrowserRouter>
    </MantineProvider>
  </React.StrictMode>,
);
